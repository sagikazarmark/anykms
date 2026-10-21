//! Token-endpoint plumbing shared by the credential sources: zeroizing form bodies, response
//! parsing, and the error mapping for token endpoints.

use std::time::Duration;

use anykms_core::{BackendDetail, Error, ErrorKind, Result};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::{Fetched, MAX_TOKEN_RESPONSE, auth_err};
use anykms_http::credentials::Expiring;

/// Appends `s` form-urlencoded (`application/x-www-form-urlencoded`) to `out`.
fn form_encode(out: &mut Zeroizing<Vec<u8>>, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in s {
        let mut enc = [0u8; 3];
        let piece: &[u8] = match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                enc[0] = b;
                &enc[..1]
            }
            b' ' => b"+",
            _ => {
                enc = [b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]];
                &enc[..]
            }
        };
        anykms_http::zbuf::extend(out, piece, usize::MAX);
    }
}

/// A form body in a zeroizing buffer (values may be refresh tokens or subject tokens).
pub(crate) fn form(pairs: &[(&str, &[u8])]) -> Zeroizing<Vec<u8>> {
    let hint: usize = pairs.iter().map(|(k, v)| k.len() + v.len() * 3 + 2).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(hint));
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            anykms_http::zbuf::extend(&mut out, b"&", usize::MAX);
        }
        form_encode(&mut out, k.as_bytes());
        anykms_http::zbuf::extend(&mut out, b"=", usize::MAX);
        form_encode(&mut out, v);
    }
    out
}

/// An OAuth 2.0 token response (`oauth2.googleapis.com/token`, STS, the metadata server).
#[derive(Deserialize)]
struct OAuthToken {
    access_token: Option<String>,
    expires_in: Option<serde_json::Value>,
}

/// An OAuth 2.0 error response: only the codes are kept, never the description (it may echo
/// input).
#[derive(Deserialize)]
struct OAuthError {
    error: Option<String>,
}

/// An error code fit for `BackendDetail::code`: short, `[a-z_]`.
fn safe_code(c: &str) -> Option<String> {
    (!c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        .then(|| c.to_owned())
}

/// Maps a token endpoint's failure: 5xx and 429 are `Unavailable` (the token cache returns
/// it for 5 s, then fetches again), 400 and 401 (`invalid_grant`, a revoked refresh token, a bad
/// subject token) `Unauthenticated`, 403 `PermissionDenied` (e.g. missing
/// `iam.serviceAccountTokenCreator`), 404 `Configuration`.
pub(crate) fn endpoint_error(what: &'static str, status: u16, body: &[u8]) -> Error {
    let (kind, msg) = match status {
        429 | 500..=599 => (ErrorKind::Unavailable, "token endpoint unavailable"),
        403 => (
            ErrorKind::PermissionDenied,
            "token endpoint denied the request",
        ),
        404 => (ErrorKind::Configuration, "token endpoint not found"),
        300..=399 => (
            ErrorKind::Configuration,
            "token endpoint answered with a redirect (never followed)",
        ),
        _ => (
            ErrorKind::Unauthenticated,
            "token endpoint refused the credential",
        ),
    };
    let mut detail = BackendDetail::new().with_http_status(status);
    let code = serde_json::from_slice::<OAuthError>(body)
        .ok()
        .and_then(|e| e.error)
        .as_deref()
        .and_then(safe_code)
        .or_else(|| {
            // Google APIs (IAM credentials) answer with a google.rpc.Status instead.
            crate::errors::Status::parse(body).code
        });
    if let Some(c) = code {
        detail = detail.with_code(c);
    }
    auth_err(kind, format!("{what}: {msg}")).with_detail(detail)
}

fn expires_in(v: Option<&serde_json::Value>) -> Option<Duration> {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().map(Duration::from_secs),
        Some(serde_json::Value::String(s)) => s.parse().ok().map(Duration::from_secs),
        _ => None,
    }
}

/// Decodes an OAuth 2.0 token response. A missing `expires_in` is taken as one hour.
pub(crate) fn parse_oauth_token(what: &'static str, body: &[u8]) -> Result<Expiring<Fetched>> {
    let bad = || {
        auth_err(
            ErrorKind::Unavailable,
            format!("{what}: unexpected token response"),
        )
    };
    let mut t: OAuthToken = serde_json::from_slice(body).map_err(|_| bad())?;
    let token = t.access_token.take().ok_or_else(bad)?;
    let token = Zeroizing::new(token);
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad());
    }
    let lifetime = expires_in(t.expires_in.as_ref()).unwrap_or(Duration::from_secs(3600));
    Ok(Fetched::valid_for(token, lifetime))
}

/// Sends a token request and returns the success body (bounded, zeroizing), or the mapped error.
pub(crate) async fn send(
    what: &'static str,
    req: reqwest::RequestBuilder,
) -> Result<Zeroizing<Vec<u8>>> {
    let resp = req.send().await.map_err(|e| {
        let e = anykms_http::client::transport_error(
            crate::BACKEND,
            anykms_core::Operation::Configure,
            e,
        );
        // A refused TLS certificate stays Configuration; every other failure to reach a token
        // endpoint is retryable.
        let kind = match e.kind() {
            ErrorKind::Configuration => ErrorKind::Configuration,
            ErrorKind::Timeout => ErrorKind::Timeout,
            _ => ErrorKind::Unavailable,
        };
        let msg = format!("{what}: {}", e.message());
        auth_err(kind, msg).with_source(e)
    })?;
    let status = resp.status().as_u16();
    let body = anykms_http::client::read_body(resp, MAX_TOKEN_RESPONSE)
        .await
        .map_err(|e| match e {
            anykms_http::client::BodyError::TooLarge => auth_err(
                ErrorKind::Unavailable,
                format!("{what}: token response too large"),
            ),
            anykms_http::client::BodyError::Transport(_) => auth_err(
                ErrorKind::Unavailable,
                format!("{what}: token response was interrupted"),
            ),
        })?;
    if !(200..300).contains(&status) {
        let e = endpoint_error(what, status, &body);
        drop(body);
        return Err(e);
    }
    Ok(body)
}

/// A `POST` of a form body. The caller keeps (and wipes) its zeroizing buffer.
pub(crate) fn post_form(
    http: &reqwest::Client,
    url: &url::Url,
    body: &[u8],
) -> reqwest::RequestBuilder {
    // reqwest copies the body into its own buffer; that copy is not wiped (see the crate docs on
    // zeroization limits).
    http.post(url.clone())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body.to_vec())
}

/// A bearer `Authorization` header value, marked sensitive.
pub(crate) fn bearer(token: &str) -> Result<reqwest::header::HeaderValue> {
    let mut v = Zeroizing::new(String::with_capacity(token.len() + 7));
    v.push_str("Bearer ");
    v.push_str(token);
    let mut h = reqwest::header::HeaderValue::from_str(&v).map_err(|_| {
        auth_err(
            ErrorKind::Configuration,
            "access token contains invalid characters",
        )
    })?;
    v.zeroize();
    h.set_sensitive(true);
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_are_encoded() {
        let f = form(&[("grant_type", b"refresh_token"), ("x y", b"a+b/c=d&e \xff")]);
        assert_eq!(
            &f[..],
            b"grant_type=refresh_token&x+y=a%2Bb%2Fc%3Dd%26e+%FF"
        );
    }

    #[test]
    fn token_responses() {
        let t = parse_oauth_token("t", br#"{"access_token":"ya29.x","expires_in":3599}"#).unwrap();
        assert!(t.expires_at().is_some());
        parse_oauth_token("t", br#"{"access_token":"ya29.x","expires_in":"60"}"#).unwrap();
        assert!(parse_oauth_token("t", br#"{"expires_in":3599}"#).is_err());
        assert!(parse_oauth_token("t", br#"{"access_token":"a b"}"#).is_err());
        assert!(parse_oauth_token("t", b"nope").is_err());
    }

    #[test]
    fn endpoint_errors() {
        let e = endpoint_error(
            "t",
            400,
            br#"{"error":"invalid_grant","error_description":"SECRET echo"}"#,
        );
        assert_eq!(e.kind(), ErrorKind::Unauthenticated);
        assert_eq!(e.detail().unwrap().code(), Some("invalid_grant"));
        assert!(!format!("{e} {e:?}").contains("SECRET"));
        assert_eq!(endpoint_error("t", 503, b"").kind(), ErrorKind::Unavailable);
        assert_eq!(
            endpoint_error("t", 403, b"").kind(),
            ErrorKind::PermissionDenied
        );
        let e = endpoint_error("t", 400, br#"{"error":"Bad Thing <script>"}"#);
        assert_eq!(e.detail().unwrap().code(), None);
    }
}
