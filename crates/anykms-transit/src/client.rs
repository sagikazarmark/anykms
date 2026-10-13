//! The thin HTTP client: one per configured server.

use std::sync::Arc;

use anykms_core::{BackendDetail, Error, ErrorKind, Operation, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::config::{HttpVersion, Proxy, ServerConfig};
use crate::errors::{Failure, classify};
use crate::token::{Token, TokenSource};

/// Warnings known to be harmless. Ships empty: every entry needs a test and a written reason.
/// Matched as exact strings.
const HARMLESS_WARNINGS: &[&str] = &[];

pub(crate) struct Server {
    pub(crate) alias: String,
    pub(crate) cfg: ServerConfig,
    base: reqwest::Url,
    http: reqwest::Client,
    /// `cfg.token`, or the login source when `cfg.login` is set.
    token: Arc<dyn TokenSource>,
    /// The semantics of this server's handles, by key family.
    pub(crate) semantics: crate::semantics::ServerSemantics,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("alias", &self.alias)
            .field(
                "address",
                &anykms_http::redact::url_origin(&self.cfg.address),
            )
            .finish()
    }
}

/// Where a request's key version came from (P1-4): only a request that addressed the handle's
/// own key may drop its cached key type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The handle's own key or current version: encrypt, data keys, sign, MAC, metadata reads,
    /// `public_key`.
    Handle,
    /// A version taken from input: decrypt and rewrap (the ciphertext's version), verify and MAC
    /// verification (the signature's or tag's version), `public_key_version`.
    Input,
}

/// One request.
pub(crate) struct Call<'a> {
    pub(crate) method: Method,
    /// Path segments below `/v1/`, from validated parts only. Each is percent-encoded again when
    /// the URL is built (defence in depth), so no segment can add path structure.
    pub(crate) segments: Vec<&'a str>,
    pub(crate) namespace: Option<&'a str>,
    pub(crate) body: Option<Zeroizing<Vec<u8>>>,
    pub(crate) op: Operation,
    /// A `GET keys/:name`: 404 means the key does not exist.
    pub(crate) key_read: bool,
    /// The key's resource string (the span's `resource`): server alias, mount, key name and
    /// namespace.
    pub(crate) resource: &'a str,
    /// The key version the request names, when known (the span's `key_version`).
    pub(crate) key_version: Option<u64>,
}

fn config_err(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

/// The rustls client configuration: `ca_pem` or the system roots (required for `https://`), the
/// optional client certificate, ALPN per `http_version`, and the crypto provider chosen by
/// [`anykms_http::tls::select_provider`] (`ServerConfig::crypto_provider`, the process default,
/// aws-lc-rs, ring).
fn tls_config(cfg: &ServerConfig, require_roots: bool) -> Result<rustls::ClientConfig> {
    anykms_http::tls::TlsOptions::new()
        .ca_pem(cfg.ca_pem.as_deref())
        .client_identity(
            cfg.client_identity
                .as_ref()
                .map(|(cert, key)| (&cert[..], &key[..])),
        )
        .crypto_provider(cfg.crypto_provider.clone(), "ServerConfig::crypto_provider")
        .require_roots(require_roots)
        .http2(cfg.http_version == HttpVersion::Http2)
        .build(BACKEND)
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct WarningsOnly {
    #[serde(default)]
    warnings: Option<serde_json::Value>,
}

/// Unexpected warnings, failing closed on any shape other than a list of allow-listed strings.
fn unexpected_warning(w: &Option<serde_json::Value>) -> Option<String> {
    match w {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(items)) => items.iter().find_map(|i| match i.as_str() {
            Some(s) if HARMLESS_WARNINGS.contains(&s) => None,
            Some(s) => Some(s.to_owned()),
            None => Some("<non-string warning>".to_owned()),
        }),
        Some(_) => Some("<malformed warnings field>".to_owned()),
    }
}

/// Classifies a reqwest failure (no response): fixed messages, the URL stripped from the source.
pub(crate) fn transport_error(op: Operation, e: reqwest::Error) -> Error {
    anykms_http::client::transport_error(BACKEND, op, e)
}

/// Sends `req` through [`anykms_http::client::send`] (which records `http_status` into the
/// current span) and classifies a failure to get a whole response: a transport error, or a body
/// over `limit`, an unusable response with the message `too_large`.
pub(crate) async fn send(
    req: reqwest::RequestBuilder,
    limit: usize,
    op: Operation,
    alias: &str,
    too_large: &'static str,
) -> Result<anykms_http::client::Response> {
    use anykms_http::client::SendError;
    anykms_http::client::send(req, limit)
        .await
        .map_err(|e| match e {
            SendError::NoRuntime => anykms_http::client::no_runtime_error(BACKEND, op),
            SendError::Transport(e) => transport_error(op, e),
            SendError::TooLarge { status } => {
                crate::errors::unusable_response(op, alias, Some(status.as_u16()), too_large)
            }
        })
}

impl Server {
    pub(crate) fn new(alias: String, cfg: ServerConfig) -> Result<Self> {
        let base = cfg.validate()?;
        // Always preconfigured: no process-global rustls provider is installed or required.
        // Plain-HTTP (loopback) servers never use it, so they do not need trusted roots.
        let tls = tls_config(&cfg, base.scheme() == "https")?;
        let http = anykms_http::client::ClientOptions::new()
            .connect_timeout(cfg.connect_timeout)
            .request_timeout(cfg.request_timeout)
            .pool_idle_timeout(cfg.pool_idle_timeout)
            .tcp_keepalive(cfg.tcp_keepalive)
            .http2(cfg.http_version != HttpVersion::Http1)
            .proxy(match &cfg.proxy {
                Proxy::None => None,
                Proxy::Url(u) => Some(u.as_str().to_owned()),
            })
            .build(BACKEND, tls)?;
        let token: Arc<dyn TokenSource> = match &cfg.login {
            Some(login) => Arc::new(crate::auth::LoginSource::new(
                login.clone(),
                http.clone(),
                base.clone(),
                cfg.namespace.clone(),
                alias.clone(),
            )),
            None => cfg.token.clone(),
        };
        Ok(Self {
            alias,
            semantics: crate::semantics::ServerSemantics::new(cfg.flavor),
            cfg,
            base,
            http,
            token,
        })
    }

    /// `<base>/v1/<segments...>`, each segment percent-encoded as a single path segment. Empty,
    /// `.` and `..` segments are refused (URI and mount validation already rule them out).
    fn url(&self, segments: &[&str]) -> Result<reqwest::Url> {
        if segments.iter().any(|s| matches!(*s, "" | "." | "..")) {
            return Err(config_err("invalid request path"));
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| config_err("invalid request path"))?
            .pop_if_empty()
            .push("v1")
            .extend(segments);
        Ok(url)
    }

    async fn send(
        &self,
        call: &Call<'_>,
        token: &Option<Token>,
    ) -> Result<(StatusCode, HeaderMap, Zeroizing<Vec<u8>>)> {
        let url = self.url(&call.segments)?;
        let mut req = self
            .http
            .request(call.method.clone(), url)
            .header("X-Vault-Request", "true");
        if let Some(t) = token {
            let mut v = HeaderValue::from_str(t.expose()).map_err(|_| {
                Error::new(
                    ErrorKind::Configuration,
                    BACKEND,
                    call.op,
                    "token contains invalid characters",
                )
            })?;
            v.set_sensitive(true);
            req = req.header("X-Vault-Token", v);
        }
        if let Some(ns) = call.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        if let Some(body) = &call.body {
            // reqwest copies the body into its own buffer; that copy cannot be zeroized (see the
            // zeroization limits in docs/guarantees.md).
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        // `http_status` is recorded for every response, success included; the 403-refresh retry
        // overwrites it with the final attempt's status. Content-Length is a hint from the
        // server, trusted only up to a small cap, so a lying header cannot make us allocate up
        // front; the body grows into fresh zeroizing buffers (the old one is wiped), never
        // beyond the limit.
        let r = send(
            req,
            self.cfg.max_response_bytes,
            call.op,
            &self.alias,
            "response exceeds the maximum size",
        )
        .await?;
        Ok((r.status, r.headers, r.body))
    }

    /// Performs a call, retrying once after a 403 if the token source yields a new token.
    /// Returns the success body; every non-success response is classified.
    /// Runs inside the request span (`anykms.transit`, the shared schema of
    /// [`anykms_http::span`]).
    pub(crate) async fn call(&self, call: Call<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let version = call.key_version.map(|v| v.to_string());
        let span = anykms_http::request_span!(
            "anykms.transit",
            backend = BACKEND,
            op = call.op.as_str(),
            resource = call.resource,
            key_version = version.as_deref(),
        );
        let guard = anykms_http::span::start_request(&span);
        let r = anykms_http::span::instrument(self.call_inner(&call), &span).await;
        guard.finish(None, &r);
        r
    }

    async fn call_inner(&self, call: &Call<'_>) -> Result<Zeroizing<Vec<u8>>> {
        // First: outside a Tokio runtime the credential sources and reqwest would panic.
        anykms_http::client::require_runtime(BACKEND, call.op)?;
        let source = &self.token;
        let token = source
            .token()
            .await
            .map_err(|e| e.with_operation(call.op))?;
        anykms_http::span::record_attempt(1);
        let (mut status, mut headers, mut body) = self.send(call, &token).await?;
        if status == StatusCode::FORBIDDEN
            && let Some(rejected) = &token
        {
            source.invalidate(rejected);
            // If the source cannot produce a token now, report the original 403 rather
            // than the (possibly retryable) token-source error.
            if let Ok(fresh) = source.token().await {
                let changed = match &fresh {
                    Some(f) => f.expose() != rejected.expose(),
                    None => true,
                };
                if changed {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(reason = "token refreshed after 403", "retrying once");
                    anykms_http::span::record_attempt(2);
                    (status, headers, body) = self.send(call, &fresh).await?;
                }
            }
        }
        if status.is_success() {
            if !body.is_empty() {
                // Valid JSON that does not parse here (a duplicate `warnings` key, a non-object)
                // could hide a warning from this check while the handler's own, lenient parse
                // still accepts it: fail closed. Malformed JSON is left to the handler, which
                // reports an unusable response.
                let warning = match serde_json::from_slice::<WarningsOnly>(&body) {
                    Ok(w) => unexpected_warning(&w.warnings),
                    Err(_) if serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_ok() => {
                        Some("<unparsable warnings>".to_owned())
                    }
                    Err(_) => None,
                };
                if let Some(first) = warning {
                    let msg = crate::errors::redact(&first);
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        op = call.op.as_str(),
                        backend = BACKEND,
                        resource = call.resource,
                        server_message = %msg,
                        "transit response carried warnings; failing closed"
                    );
                    drop(body);
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        BACKEND,
                        call.op,
                        "the server ignored or warned about request parameters; failing closed",
                    )
                    .with_detail(
                        BackendDetail::new()
                            .with_http_status(status.as_u16())
                            .with_server_message(msg),
                    ));
                }
            }
            return Ok(body);
        }
        let messages = serde_json::from_slice::<ErrorBody>(&body)
            .map(|b| b.errors)
            .unwrap_or_default();
        let mut e = classify(Failure {
            status: status.as_u16(),
            messages: &messages,
            retry_after: anykms_http::client::retry_after(&headers),
            op: call.op,
            alias: &self.alias,
            key_read: call.key_read,
        });
        if matches!(call.op, Operation::Verify | Operation::VerifyMac)
            && e.kind() == ErrorKind::DecryptFailed
        {
            let mut v = Error::new(
                ErrorKind::VerificationFailed,
                BACKEND,
                call.op,
                "verification failed",
            )
            .with_detail(e.detail().cloned().unwrap_or_default());
            if let Some(h) = e.retry_hint() {
                v = v.with_retry_hint(h);
            }
            e = v;
        }
        Err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built without a provider feature (and with no process default installed in this test
    /// binary), building a server fails with guidance instead of panicking in reqwest.
    #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    #[test]
    fn no_crypto_provider_is_a_configuration_error() {
        let e = Server::new(
            "a".into(),
            ServerConfig::new("http://127.0.0.1:8200", crate::Flavor::Vault).allow_loopback_http(),
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert!(e.to_string().contains("rustls-aws-lc-rs"), "{e}");
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn url_segments_are_encoded() {
        let s = Server::new(
            "a".into(),
            ServerConfig::new("http://127.0.0.1:8200/", crate::Flavor::Vault).allow_loopback_http(),
        )
        .unwrap();
        assert_eq!(
            s.url(&["team", "transit", "encrypt", "my-key.v2"])
                .unwrap()
                .as_str(),
            "http://127.0.0.1:8200/v1/team/transit/encrypt/my-key.v2"
        );
        assert_eq!(
            s.url(&["transit", "encrypt", "a/b?c#d%"]).unwrap().as_str(),
            "http://127.0.0.1:8200/v1/transit/encrypt/a%2Fb%3Fc%23d%25"
        );
        for bad in ["", ".", ".."] {
            assert!(s.url(&["transit", "encrypt", bad]).is_err(), "{bad:?}");
        }
    }
}
