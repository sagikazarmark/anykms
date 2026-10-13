//! AWS Signature Version 4 (`AWS4-HMAC-SHA256`), header-based signing.
//!
//! Verified against the AWS SigV4 test suite (vendored in `tests/data/sigv4`, see
//! `tests/sigv4_vectors.rs`). The KMS client signs `POST /` with `content-type`, `host`,
//! `x-amz-date`, `x-amz-target` and, for temporary credentials, `x-amz-security-token`.
//! The derived signing key lives in a zeroizing buffer.

use std::time::SystemTime;

use hmac::Mac as _;
use sha2::Digest as _;
use zeroize::Zeroizing;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// One request to sign. Header names may use any case; `host` must be among them.
///
/// `Debug` prints the method, the path and the header names only (a session token is a header
/// value; the payload may carry plaintext).
pub struct Request<'a> {
    /// `GET`, `POST`, ...
    pub method: &'a str,
    /// The path as sent, not yet percent-encoded (`/` for KMS).
    pub path: &'a str,
    /// Query parameters, not yet percent-encoded.
    pub query: &'a [(&'a str, &'a str)],
    /// Every header to sign, in any order; repeated names are joined with `,` in order.
    pub headers: &'a [(&'a str, &'a str)],
    /// The body.
    pub payload: &'a [u8],
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field(
                "headers",
                &self.headers.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            )
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// The credential scope.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// The signing region (for KMS, the key ARN's region).
    pub region: &'a str,
    /// The signing service name (`kms`, `sts`).
    pub service: &'a str,
    /// The signing time (already corrected for clock skew).
    pub time: SystemTime,
}

/// The values a signed request needs.
///
/// `Debug` prints the date and the credential (access key id and scope), never the
/// `Authorization` header: its signature can be replayed for about 5 minutes.
pub struct Signed {
    /// `X-Amz-Date`, which must also be among the signed headers.
    pub amz_date: String,
    /// The `Authorization` header value.
    pub authorization: String,
    /// `<access key id>/<credential scope>`, for `Debug`.
    credential: String,
}

impl std::fmt::Debug for Signed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signed")
            .field("amz_date", &self.amz_date)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[usize::from(b >> 4)] as char);
        s.push(H[usize::from(b & 15)] as char);
    }
    s
}

/// Hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha2::Sha256::digest(data))
}

fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut m = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("any key length");
    m.update(data);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

/// SigV4 URI encoding: everything but `A-Z a-z 0-9 - . _ ~` as `%XX` (and `/` too unless
/// `keep_slash`).
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A header value with leading/trailing whitespace removed and inner runs of spaces collapsed.
fn trim_all(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for (i, w) in v.split_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(w);
    }
    out
}

/// The canonical request and the signed-headers list.
pub fn canonical_request(req: &Request<'_>, payload_hash: &str) -> (String, String) {
    let path = if req.path.is_empty() { "/" } else { req.path };
    let mut query: Vec<(String, String)> = req
        .query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    query.sort();
    let query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut headers: Vec<(String, String)> = Vec::new();
    for (n, v) in req.headers {
        let n = n.to_ascii_lowercase();
        let v = trim_all(v);
        match headers.iter_mut().find(|(k, _)| *k == n) {
            Some((_, existing)) => {
                existing.push(',');
                existing.push_str(&v);
            }
            None => headers.push((n, v)),
        }
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let signed = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut c = String::with_capacity(256);
    c.push_str(req.method);
    c.push('\n');
    c.push_str(&uri_encode(path, true));
    c.push('\n');
    c.push_str(&query);
    c.push('\n');
    for (k, v) in &headers {
        c.push_str(k);
        c.push(':');
        c.push_str(v);
        c.push('\n');
    }
    c.push('\n');
    c.push_str(&signed);
    c.push('\n');
    c.push_str(payload_hash);
    (c, signed)
}

/// `<date>/<region>/<service>/aws4_request`.
fn credential_scope(amz_date: &str, scope: &Scope<'_>) -> String {
    format!(
        "{}/{}/{}/aws4_request",
        &amz_date[..8],
        scope.region,
        scope.service
    )
}

/// The string to sign for a canonical request.
pub fn string_to_sign(amz_date: &str, scope: &Scope<'_>, canonical: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{}\n{}",
        credential_scope(amz_date, scope),
        sha256_hex(canonical.as_bytes())
    )
}

/// The derived signing key `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), service),
/// "aws4_request")`.
fn signing_key(secret: &str, date: &str, scope: &Scope<'_>) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    k.extend_from_slice(b"AWS4");
    k.extend_from_slice(secret.as_bytes());
    let k = hmac(&k, date.as_bytes());
    let k = hmac(&*k, scope.region.as_bytes());
    let k = hmac(&*k, scope.service.as_bytes());
    hmac(&*k, b"aws4_request")
}

/// The hex signature of a string to sign.
pub fn signature(secret: &str, amz_date: &str, scope: &Scope<'_>, sts: &str) -> String {
    let key = signing_key(secret, &amz_date[..8], scope);
    hex(&*hmac(&*key, sts.as_bytes()))
}

/// Signs `req`. Its headers must already include `x-amz-date` with [`crate::time`]'s
/// `amz_date(scope.time)` (and `x-amz-security-token` when the credentials have a session
/// token); use [`amz_date`] to build it.
pub fn sign(access_key_id: &str, secret: &str, req: &Request<'_>, scope: &Scope<'_>) -> Signed {
    let amz_date = amz_date(scope.time);
    let (canonical, signed_headers) = canonical_request(req, &sha256_hex(req.payload));
    let sts = string_to_sign(&amz_date, scope, &canonical);
    let sig = signature(secret, &amz_date, scope, &sts);
    let credential = format!("{access_key_id}/{}", credential_scope(&amz_date, scope));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={credential}, SignedHeaders={signed_headers}, Signature={sig}"
    );
    Signed {
        amz_date,
        authorization,
        credential,
    }
}

/// The `X-Amz-Date` value for `t`.
pub fn amz_date(t: SystemTime) -> String {
    crate::time::amz_date(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn encodes() {
        assert_eq!(uri_encode("a b/c~", true), "a%20b/c~");
        assert_eq!(uri_encode("a b/c~", false), "a%20b%2Fc~");
        assert_eq!(uri_encode("ሴ", false), "%E1%88%B4");
        assert_eq!(trim_all("  a   b \t c "), "a b c");
    }

    /// The AWS SigV4 test suite (aws-c-auth `tests/aws-signing-test-suite/v4`, Apache-2.0),
    /// header-signing variant: canonical request, string to sign and signature of every vendored
    /// case. The path-normalization cases are not vendored (KMS always posts to `/`).
    #[test]
    fn aws_test_suite_vectors() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/sigv4");
        let mut cases = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let case = entry.unwrap().path();
            if !case.is_dir() {
                continue;
            }
            let read = |f: &str| std::fs::read_to_string(case.join(f)).unwrap();
            let ctx: serde_json::Value = serde_json::from_str(&read("context.json")).unwrap();
            let raw = read("request.txt");
            let (head, body) = raw.split_once("\n\n").unwrap_or((raw.as_str(), ""));
            let mut lines = head.lines();
            let first = lines.next().unwrap();
            let mut it = first.splitn(3, ' ');
            let method = it.next().unwrap();
            let target = it.next().unwrap();
            let (path, q) = target.split_once('?').unwrap_or((target, ""));
            let query: Vec<(&str, &str)> = q
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| p.split_once('=').unwrap_or((p, "")))
                .collect();
            let mut headers: Vec<(String, String)> = lines
                .map(|l| {
                    let (n, v) = l.split_once(':').unwrap();
                    (n.to_owned(), v.to_owned())
                })
                .collect();
            let creds = &ctx["credentials"];
            let ts = ctx["timestamp"].as_str().unwrap();
            let time = crate::time::parse_rfc3339(ts).unwrap();
            let date = amz_date(time);
            headers.push(("X-Amz-Date".into(), date.clone()));
            let token = creds["token"].as_str();
            if let Some(t) = token
                && !ctx["omit_session_token"].as_bool().unwrap_or(false)
            {
                headers.push(("X-Amz-Security-Token".into(), t.to_owned()));
            }
            if ctx["sign_body"].as_bool().unwrap_or(false) {
                headers.push(("X-Amz-Content-Sha256".into(), sha256_hex(body.as_bytes())));
            }
            let hdrs: Vec<(&str, &str)> = headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            let req = Request {
                method,
                path,
                query: &query,
                headers: &hdrs,
                payload: body.as_bytes(),
            };
            let scope = Scope {
                region: ctx["region"].as_str().unwrap(),
                service: ctx["service"].as_str().unwrap(),
                time,
            };
            let name = case.file_name().unwrap().to_string_lossy().into_owned();
            let (c, _) = canonical_request(&req, &sha256_hex(body.as_bytes()));
            assert_eq!(
                c,
                read("header-canonical-request.txt"),
                "{name}: canonical request"
            );
            let sts = string_to_sign(&date, &scope, &c);
            assert_eq!(
                sts,
                read("header-string-to-sign.txt"),
                "{name}: string to sign"
            );
            let secret = creds["secret_access_key"].as_str().unwrap();
            assert_eq!(
                signature(secret, &date, &scope, &sts),
                read("header-signature.txt").trim(),
                "{name}: signature"
            );
            let s = sign(
                creds["access_key_id"].as_str().unwrap(),
                secret,
                &req,
                &scope,
            );
            assert!(
                s.authorization
                    .ends_with(read("header-signature.txt").trim()),
                "{name}"
            );
            cases += 1;
        }
        assert!(cases >= 20, "only {cases} vectors found");
    }

    /// A KMS request as the client builds it, checked against an independent computation of the
    /// documented algorithm (this pins the header set the client signs).
    #[test]
    fn kms_request_shape() {
        let t = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        let date = amz_date(t);
        let body = br#"{"KeyId":"k","Plaintext":"AA=="}"#;
        let headers = [
            ("Content-Type", "application/x-amz-json-1.1"),
            ("Host", "kms.us-east-1.amazonaws.com"),
            ("X-Amz-Date", date.as_str()),
            ("X-Amz-Target", "TrentService.Encrypt"),
        ];
        let req = Request {
            method: "POST",
            path: "/",
            query: &[],
            headers: &headers,
            payload: body,
        };
        let scope = Scope {
            region: "us-east-1",
            service: "kms",
            time: t,
        };
        let (c, signed) = canonical_request(&req, &sha256_hex(body));
        assert_eq!(signed, "content-type;host;x-amz-date;x-amz-target");
        assert_eq!(
            c,
            format!(
                "POST\n/\n\ncontent-type:application/x-amz-json-1.1\nhost:kms.us-east-1.amazonaws.com\n\
                 x-amz-date:20150830T123600Z\nx-amz-target:TrentService.Encrypt\n\n\
                 content-type;host;x-amz-date;x-amz-target\n{}",
                sha256_hex(body)
            )
        );
        let s = sign(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            &req,
            &scope,
        );
        assert!(
            s.authorization.starts_with(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/kms/aws4_request, \
                 SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature="
            ),
            "{}",
            s.authorization
        );
        assert_eq!(s.amz_date, "20150830T123600Z");
    }

    /// Neither `Debug` form of `value` contains any of `secrets` (as anykms-testkit's
    /// `assert_debug_redacts`, which is a path-only dev-dependency: the packaged crate's unit
    /// tests must build without it).
    fn assert_debug_redacts(value: &dyn std::fmt::Debug, secrets: &[&str]) {
        let outputs = [format!("{value:?}"), format!("{value:#?}")];
        for s in secrets {
            assert!(!s.is_empty(), "an empty secret matches everything");
            for out in &outputs {
                assert!(
                    !out.contains(s),
                    "Debug output contains the secret {s:?}:\n{out}"
                );
            }
        }
    }

    /// P1-1: the signature can be replayed, so `Debug` never prints it (nor the request's
    /// session token or payload).
    #[test]
    fn debug_never_prints_the_signature() {
        let t = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        let date = amz_date(t);
        let headers = [
            ("Host", "kms.us-east-1.amazonaws.com"),
            ("X-Amz-Date", date.as_str()),
            ("X-Amz-Security-Token", "SESSIONTOKENSECRET"),
        ];
        let req = Request {
            method: "POST",
            path: "/",
            query: &[],
            headers: &headers,
            payload: b"PAYLOADSECRET",
        };
        let scope = Scope {
            region: "us-east-1",
            service: "kms",
            time: t,
        };
        let s = sign("AKIDEXAMPLE", "SECRETACCESSKEY", &req, &scope);
        let sig = s.authorization.rsplit('=').next().unwrap().to_owned();
        assert_eq!(sig.len(), 64);
        assert_debug_redacts(
            &s,
            &[&sig, "Signature", "SECRETACCESSKEY", &s.authorization],
        );
        let d = format!("{s:?}");
        assert!(
            d.contains("AKIDEXAMPLE/20150830/us-east-1/kms/aws4_request"),
            "{d}"
        );
        assert_debug_redacts(&req, &["SESSIONTOKENSECRET", "PAYLOADSECRET"]);
    }
}
