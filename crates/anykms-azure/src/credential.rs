//! Entra ID access tokens: the [`AzureCredential`] trait, the provider's per-scope cache, and the
//! plumbing the built-in credentials share (lazy HTTP clients, the OAuth token endpoint, error
//! mapping).

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anykms_core::{BackendDetail, BoxFuture, Error, ErrorKind, Operation, Result};
use anykms_http::HttpTransport;
use anykms_http::credentials::{Credential, CredentialCache, Expiring};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::BACKEND;

/// An Entra ID access token and when it expires. The token is held in a zeroizing buffer and
/// never appears in `Debug` output.
#[derive(Clone)]
pub struct AccessToken {
    secret: Zeroizing<String>,
    expires_at: Option<SystemTime>,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl AccessToken {
    /// A token expiring at `expires_at` (`None`: never, e.g. a static test token).
    pub fn new(secret: impl Into<Zeroizing<String>>, expires_at: Option<SystemTime>) -> Self {
        Self {
            secret: secret.into(),
            expires_at,
        }
    }

    /// The bearer token.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// When it expires.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
}

/// A source of Entra ID access tokens. Object-safe, so an application can plug in its own (for
/// example a certificate credential).
///
/// This is anykms's trait, not the Azure SDK's `azure_core::credentials::TokenCredential`: an
/// SDK credential (e.g. from `azure_identity`) plugs in through `AzureIdentity` (feature
/// `azure-identity`), which implements this trait over it.
///
/// The provider caches tokens per scope (single flight, refreshed 5 minutes before they expire)
/// and asks again after a vault rejects one with 401 (then retries the request once if the token
/// changed). Implementations therefore need no cache of their own, and must not retry: a failed
/// fetch is reported to the caller, whose `Retry` layer decides.
pub trait AzureCredential: Send + Sync + fmt::Debug {
    /// A token for `scope` (e.g. `https://vault.azure.net/.default`).
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, Result<AccessToken>>;

    /// A vault rejected `rejected` (HTTP 401). Sources with a cache of their own drop it here.
    fn invalidate(&self, scope: &str, rejected: &AccessToken) {
        let _ = (scope, rejected);
    }

    /// A short, non-secret label for logs: the `credential` field of the `anykms.azure.token`
    /// span and of the credential events. The built-in credentials' labels are stable snake_case
    /// (`workload_identity`, `client_secret`, `managed_identity`, `azure_identity`, `static`);
    /// return a snake_case label too, so one filter matches every source.
    fn kind(&self) -> &'static str {
        "custom"
    }

    /// The tenant the credential authenticates in, when known: a 401 whose challenge names
    /// another tenant then says so.
    fn tenant_id(&self) -> Option<&str> {
        None
    }

    /// The provider hands over its HTTP transport when it is built. The built-in credentials
    /// fetch their tokens through it (so one transport carries every request of a provider: its
    /// TLS trust, proxy and timeouts apply to token endpoints too) and keep the first transport
    /// they are given: a credential value belongs to one provider; clone it for another (a clone
    /// starts unbound). A credential with its own way to the network ignores it, which is the
    /// default.
    fn bind_transport(&self, transport: Arc<dyn HttpTransport>) {
        let _ = transport;
    }
}

impl<T: AzureCredential + ?Sized> AzureCredential for Arc<T> {
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, Result<AccessToken>> {
        (**self).token(scope)
    }
    fn invalidate(&self, scope: &str, rejected: &AccessToken) {
        (**self).invalidate(scope, rejected);
    }
    fn kind(&self) -> &'static str {
        (**self).kind()
    }
    fn tenant_id(&self) -> Option<&str> {
        (**self).tenant_id()
    }
    fn bind_transport(&self, transport: Arc<dyn HttpTransport>) {
        (**self).bind_transport(transport);
    }
}

/// A caller-supplied token, for tests and emulators (Lowkey Vault accepts any token). Never
/// refreshed.
#[derive(Clone)]
pub struct StaticToken(AccessToken);

impl fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticToken(<redacted>)")
    }
}

impl StaticToken {
    /// A token that never expires.
    pub fn new(token: impl Into<String>) -> Self {
        Self(AccessToken::new(Zeroizing::new(token.into()), None))
    }

    /// A token expiring at `expires_at`.
    pub fn with_expiry(token: impl Into<String>, expires_at: SystemTime) -> Self {
        Self(AccessToken::new(
            Zeroizing::new(token.into()),
            Some(expires_at),
        ))
    }
}

impl AzureCredential for StaticToken {
    fn token<'a>(&'a self, _scope: &'a str) -> BoxFuture<'a, Result<AccessToken>> {
        let t = self.0.clone();
        Box::pin(async move { Ok(t) })
    }

    fn kind(&self) -> &'static str {
        "static"
    }
}

/// The provider's token cache: one [`CredentialCache`] per scope over one credential.
pub(crate) struct Tokens {
    cred: Arc<dyn AzureCredential>,
    caches: Mutex<HashMap<String, Arc<CredentialCache<Arc<AccessToken>>>>>,
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("credential", &self.cred.kind())
            .finish_non_exhaustive()
    }
}

pub(crate) type CachedToken = Credential<Arc<AccessToken>>;

impl Tokens {
    pub(crate) fn new(cred: Arc<dyn AzureCredential>, http: &Arc<dyn HttpTransport>) -> Self {
        cred.bind_transport(http.clone());
        Self {
            cred,
            caches: Mutex::default(),
        }
    }

    pub(crate) fn credential(&self) -> &dyn AzureCredential {
        &*self.cred
    }

    fn cache(&self, scope: &str) -> Arc<CredentialCache<Arc<AccessToken>>> {
        self.caches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(scope.to_owned())
            .or_insert_with(|| Arc::new(CredentialCache::new()))
            .clone()
    }

    /// A token for `scope`, cached.
    pub(crate) async fn get(&self, scope: &str) -> Result<CachedToken> {
        let cache = self.cache(scope);
        cache
            .get(|| async {
                let fetched = self.fetch(scope).await?;
                Ok(match fetched.expires_at {
                    Some(at) => Expiring::valid_until(Arc::new(fetched), at),
                    None => Expiring::never_expires(Arc::new(fetched)),
                })
            })
            .await
    }

    async fn fetch(&self, scope: &str) -> Result<AccessToken> {
        // The token span shared by the HTTP backends.
        let credential = self.cred.kind();
        let span = anykms_http::token_span!(
            "anykms.azure.token",
            backend = BACKEND,
            credential = credential,
        );
        let started = std::time::Instant::now();
        let r = anykms_http::span::instrument(self.cred.token(scope), &span).await;
        let expires_in = r.as_ref().ok().and_then(|t| {
            t.expires_at
                .and_then(|at| at.duration_since(SystemTime::now()).ok())
        });
        anykms_http::span::finish_token(&span, started, expires_in, &r);
        // P1-8: a refresh is routine; a failure needs an operator. A token file that failed is
        // named in the error's message.
        #[cfg(feature = "tracing")]
        match &r {
            Ok(_) => tracing::debug!(
                parent: &span,
                backend = BACKEND,
                credential,
                "Azure access token obtained"
            ),
            Err(e) => tracing::warn!(
                parent: &span,
                backend = BACKEND,
                credential,
                error_kind = e.kind().as_str(),
                error = %e,
                "Azure access token could not be obtained"
            ),
        }
        r
    }

    /// A vault rejected `rejected`: the next [`get`](Self::get) fetches a new token.
    pub(crate) fn invalidate(&self, scope: &str, rejected: &CachedToken) {
        self.cache(scope).invalidate(rejected);
        self.cred.invalidate(scope, rejected.value());
    }
}

// ---------------------------------------------------------------------------------------------
// Shared plumbing for the built-in credentials.

pub(crate) fn cred_err(kind: ErrorKind, m: impl Into<Cow<'static, str>>) -> Error {
    Error::new(kind, BACKEND, Operation::Configure, m)
}

pub(crate) fn cred_config_err(m: impl Into<Cow<'static, str>>) -> Error {
    cred_err(ErrorKind::Configuration, m)
}

/// The HTTP transport a built-in credential fetches tokens through: the provider's, handed over
/// by [`AzureCredential::bind_transport`] when the provider is built (the first binding wins);
/// before that (a credential used on its own), the default transport, built on first use and
/// kept. A clone starts with an empty slot, so a cloned credential can serve another provider.
#[derive(Default)]
pub(crate) struct TransportSlot(Mutex<Option<Arc<dyn HttpTransport>>>);

impl Clone for TransportSlot {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl fmt::Debug for TransportSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportSlot")
            .field("bound", &self.0.lock().is_ok_and(|t| t.is_some()))
            .finish()
    }
}

impl TransportSlot {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Binds `transport` unless one is bound already.
    pub(crate) fn bind(&self, transport: Arc<dyn HttpTransport>) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert(transport);
    }

    pub(crate) fn get(&self) -> Result<Arc<dyn HttpTransport>> {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(t) = &*slot {
            return Ok(t.clone());
        }
        let t = anykms_http::default_transport(BACKEND, true)?;
        *slot = Some(t.clone());
        Ok(t)
    }
}

/// The most a token response may be.
pub(crate) const MAX_TOKEN_RESPONSE: usize = 64 * 1024;

/// A validated authority host (`https://login.microsoftonline.com`): https, or plain http on a
/// literal loopback IP (tests); no path, query or userinfo. Returned without a trailing slash.
pub(crate) fn validate_authority(host: &str) -> Result<String> {
    let url = anykms_http::url::Url::parse(host)
        .map_err(|_| cred_config_err("invalid authority host URL"))?;
    let loopback = match url.host() {
        Some(anykms_http::url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(anykms_http::url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    let ok_scheme = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !ok_scheme
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(cred_config_err(
            "authority host must be https://<host> (plain http only on a loopback IP)",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// A tenant id or domain: `[A-Za-z0-9.-]{1,128}`, so it can only be one path segment.
pub(crate) fn validate_tenant(t: &str) -> Result<()> {
    let ok = (1..=128).contains(&t.len())
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
        && t != "."
        && t != "..";
    if ok {
        Ok(())
    } else {
        Err(cred_config_err("invalid tenant id"))
    }
}

/// A client id: visible ASCII, at most 128 bytes.
pub(crate) fn validate_client_id(c: &str) -> Result<()> {
    if (1..=128).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_graphic()) {
        Ok(())
    } else {
        Err(cred_config_err("invalid client id"))
    }
}

/// `scope` minus `/.default`: the `resource` managed identity and the CLI take.
pub(crate) fn resource_of(scope: &str) -> &str {
    scope.strip_suffix("/.default").unwrap_or(scope)
}

#[derive(Deserialize)]
struct TokenResponse<'a> {
    #[serde(borrow)]
    access_token: Cow<'a, str>,
    #[serde(default)]
    expires_in: Option<NumOrString>,
    #[serde(default)]
    expires_on: Option<NumOrString>,
}

/// IMDS and App Service send numbers as strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum NumOrString {
    Num(u64),
    Str(String),
}

impl NumOrString {
    fn get(&self) -> Option<u64> {
        match self {
            Self::Num(n) => Some(*n),
            Self::Str(s) => s.trim().parse().ok(),
        }
    }
}

/// Decodes an OAuth/IMDS token response: `access_token` plus `expires_on` (Unix seconds) or
/// `expires_in` (seconds from now). Neither: `Unavailable` (an unusable response). The token
/// must be visible ASCII (it goes into a header).
pub(crate) fn parse_token_response(body: &[u8], kind: &'static str) -> Result<AccessToken> {
    let bad = || {
        cred_err(
            ErrorKind::Unavailable,
            format!("unexpected token response from the {kind} endpoint"),
        )
    };
    let mut r: TokenResponse<'_> = serde_json::from_slice(body).map_err(|_| bad())?;
    let token = Zeroizing::new(r.access_token.to_string());
    if let Cow::Owned(o) = &mut r.access_token {
        o.zeroize();
    }
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad());
    }
    let now = SystemTime::now();
    let expires_at = match (
        r.expires_on.as_ref().and_then(NumOrString::get),
        r.expires_in.as_ref().and_then(NumOrString::get),
    ) {
        (Some(on), _) => SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(on)),
        (None, Some(secs)) => now.checked_add(Duration::from_secs(secs)),
        (None, None) => return Err(bad()),
    };
    Ok(AccessToken::new(token, Some(expires_at.ok_or_else(bad)?)))
}

#[derive(Deserialize)]
struct OAuthError {
    error: Option<String>,
    #[serde(default)]
    error_codes: Vec<u64>,
}

/// Maps a failed token request. 400/401/403 (`invalid_client`, `AADSTS*`, unknown identity) are
/// `Unauthenticated` with the OAuth error and AADSTS code in `BackendDetail::code`; 404, 410,
/// 429 and 5xx are `Unavailable` (retryable; IMDS asks for backoff); anything else `Backend`.
/// The description is never kept (it can echo client ids and object ids).
pub(crate) fn token_error(
    kind: &'static str,
    status: u16,
    body: &[u8],
    retry_after: Option<Duration>,
) -> Error {
    let parsed = serde_json::from_slice::<OAuthError>(body).ok();
    let mut code = parsed
        .as_ref()
        .and_then(|p| p.error.as_deref())
        .filter(|c| {
            (1..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .map(str::to_owned);
    if let Some(n) = parsed.as_ref().and_then(|p| p.error_codes.first()) {
        let aadsts = format!("AADSTS{n}");
        code = Some(match code {
            Some(c) => format!("{c}/{aadsts}"),
            None => aadsts,
        });
    }
    let (ek, msg): (ErrorKind, Cow<'static, str>) = match status {
        400 | 401 | 403 => (
            ErrorKind::Unauthenticated,
            format!("the {kind} token request was rejected").into(),
        ),
        404 | 410 | 429 | 500..=599 => (
            ErrorKind::Unavailable,
            format!("the {kind} token endpoint is unavailable").into(),
        ),
        _ => (
            ErrorKind::Backend,
            format!("unexpected response from the {kind} token endpoint").into(),
        ),
    };
    let mut d = BackendDetail::new().with_http_status(status);
    if let Some(c) = code {
        d = d.with_code(c);
    }
    let mut e = cred_err(ek, msg).with_detail(d);
    if let Some(r) = retry_after {
        e = e.with_retry_after(r);
    }
    e
}

/// Sends a token request through `http` and decodes the response; transport errors keep
/// anykms-http's fixed messages.
pub(crate) async fn send_token_request(
    http: &dyn HttpTransport,
    req: anykms_http::http::Result<anykms_http::transport::Request>,
    kind: &'static str,
) -> Result<AccessToken> {
    use anykms_http::SendError;
    let resp = anykms_http::client::send(http, req, MAX_TOKEN_RESPONSE)
        .await
        .map_err(|e| match e {
            SendError::TooLarge { .. } => cred_err(
                ErrorKind::Unavailable,
                format!("{kind} token response too large"),
            ),
            e => e.into_error(BACKEND, Operation::Configure),
        })?;
    let status = resp.status;
    let retry_after = anykms_http::client::retry_after(&resp.headers);
    let body = resp.body;
    if !status.is_success() {
        return Err(token_error(kind, status.as_u16(), &body, retry_after));
    }
    parse_token_response(&body, kind)
}

/// `application/x-www-form-urlencoded` body in a zeroizing buffer sized up front (each byte
/// encodes to at most 3), so it never reallocates.
pub(crate) fn form_body(pairs: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    let cap: usize = pairs.iter().map(|(k, v)| (k.len() + v.len()) * 3 + 2).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(cap));
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        for part in anykms_http::url::form_urlencoded::byte_serialize(k.as_bytes()) {
            out.extend_from_slice(part.as_bytes());
        }
        out.push(b'=');
        for part in anykms_http::url::form_urlencoded::byte_serialize(v.as_bytes()) {
            out.extend_from_slice(part.as_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_responses() {
        let t = parse_token_response(
            br#"{"token_type":"Bearer","expires_in":3599,"access_token":"abc"}"#,
            "t",
        )
        .unwrap();
        assert_eq!(t.secret(), "abc");
        let left = t
            .expires_at()
            .unwrap()
            .duration_since(SystemTime::now())
            .unwrap();
        assert!(left > Duration::from_secs(3500));
        let t = parse_token_response(
            br#"{"access_token":"x\/y","expires_on":"1700000000","expires_in":"86399"}"#,
            "t",
        )
        .unwrap();
        assert_eq!(t.secret(), "x/y");
        assert_eq!(
            t.expires_at(),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );
        for bad in [
            &br#"{"access_token":"abc"}"#[..],
            br#"{"access_token":"","expires_in":1}"#,
            br#"{"access_token":"a b","expires_in":1}"#,
            br#"{"expires_in":1}"#,
            b"nope",
        ] {
            assert_eq!(
                parse_token_response(bad, "t").unwrap_err().kind(),
                ErrorKind::Unavailable
            );
        }
        assert!(!format!("{t:?}").contains("x/y"));
    }

    #[test]
    fn token_errors() {
        let e = token_error(
            "workload-identity",
            400,
            br#"{"error":"invalid_client","error_description":"AADSTS700016: app 1234 secret","error_codes":[700016]}"#,
            None,
        );
        assert_eq!(e.kind(), ErrorKind::Unauthenticated);
        assert_eq!(
            e.detail().unwrap().code(),
            Some("invalid_client/AADSTS700016")
        );
        assert!(!format!("{e:?}").contains("1234"));
        assert_eq!(
            token_error("m", 503, b"", Some(Duration::from_secs(2))).kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(
            token_error("m", 404, b"", None).kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(token_error("m", 302, b"", None).kind(), ErrorKind::Backend);
        let e = token_error("m", 400, br#"{"error":"bad code!"}"#, None);
        assert_eq!(e.detail().unwrap().code(), None);
    }

    #[test]
    fn validation() {
        assert_eq!(
            validate_authority("https://login.microsoftonline.com/").unwrap(),
            "https://login.microsoftonline.com"
        );
        assert_eq!(
            validate_authority("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        for bad in [
            "http://login.microsoftonline.com",
            "https://login.microsoftonline.com/tenant",
            "https://u:p@login.microsoftonline.com",
            "https://login.microsoftonline.com?x=1",
            "ftp://x",
            "nope",
        ] {
            assert!(validate_authority(bad).is_err(), "{bad}");
        }
        assert!(validate_tenant("72f988bf-86f1-41af-91ab-2d7cd011db47").is_ok());
        assert!(validate_tenant("contoso.onmicrosoft.com").is_ok());
        for bad in ["", "..", "a/b", "a?b", "a b"] {
            assert!(validate_tenant(bad).is_err(), "{bad}");
        }
        assert_eq!(
            resource_of("https://vault.azure.net/.default"),
            "https://vault.azure.net"
        );
        assert_eq!(
            &form_body(&[("a b", "c&d=e/f"), ("x", "y")])[..],
            b"a+b=c%26d%3De%2Ff&x=y"
        );
    }
}
