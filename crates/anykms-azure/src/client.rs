//! The Key Vault REST client: bearer tokens from the provider's cache, the refresh-once-on-401
//! rule, bounded zeroizing bodies, no redirects, error classification.

use std::sync::Arc;

use anykms_core::{Error, ErrorKind, Operation, Result};
use reqwest::header::HeaderValue;
use reqwest::{Method, StatusCode};
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::config::{ApiVersion, Target};
use crate::credential::{CachedToken, Tokens};
use crate::errors::{ErrorBody, Failure, ReqClass, classify};

/// Shared by every handle of a provider.
pub(crate) struct Client {
    pub(crate) http: reqwest::Client,
    /// For test hosts (their CA, plain HTTP on loopback); `None` without test hosts.
    pub(crate) test_http: Option<reqwest::Client>,
    pub(crate) tokens: Tokens,
    pub(crate) api_version: ApiVersion,
    pub(crate) max_response_bytes: usize,
    /// Hosts that refused a versionless operation (`POST /keys/<name>/<op>`) with 405: writes on
    /// their unversioned URIs then name the current version from the cached key bundle (Lowkey
    /// Vault does this; Azure accepts versionless operations: §24.4 probe T3).
    /// Per host, so one test host does not change how production vaults are called.
    versionless_refused: std::sync::Mutex<std::collections::HashSet<String>>,
    /// How long a key bundle read for the key-type check (and the current version) is trusted.
    pub(crate) cache_ttl: std::time::Duration,
    /// Counts every vault request (conformance fixtures).
    pub(crate) requests: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("tokens", &self.tokens)
            .field("api_version", &self.api_version)
            .finish_non_exhaustive()
    }
}

/// One request.
pub(crate) struct Call<'a> {
    pub(crate) method: Method,
    pub(crate) url: reqwest::Url,
    pub(crate) body: Option<Zeroizing<Vec<u8>>>,
    pub(crate) op: Operation,
    pub(crate) class: ReqClass,
    /// The key-type check has read the key (a 404 on an input version then means the version).
    pub(crate) key_seen: bool,
    /// The handle's resource (its key URI), for the span.
    pub(crate) resource: &'a str,
    /// The key version the request names, for the span (a versionless write records the
    /// version of the response `kid`).
    pub(crate) key_version: Option<&'a str>,
}

/// `x-ms-request-id`, through the shared filter (P1-9: 1–128 visible ASCII characters): the
/// header is server-controlled, so anything else is dropped before it reaches errors or logs.
fn request_id(headers: &reqwest::header::HeaderMap) -> Option<&str> {
    headers
        .get("x-ms-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(anykms_http::redact::request_id)
}

/// The version a success body's `kid` names (tracing only; nothing else is read from the body).
#[cfg(feature = "tracing")]
fn kid_version(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Kid {
        #[serde(default)]
        kid: Option<String>,
    }
    let k: Kid = serde_json::from_slice(body).ok()?;
    crate::uri::AzureKeyRef::from_key_id(&k.kid?)
        .ok()?
        .version()
        .map(str::to_owned)
}

fn config_err(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, op, m)
}

impl Client {
    pub(crate) fn new(
        http: reqwest::Client,
        test_http: Option<reqwest::Client>,
        tokens: Tokens,
        api_version: ApiVersion,
        max_response_bytes: usize,
        cache_ttl: std::time::Duration,
    ) -> Self {
        Self {
            http,
            test_http,
            tokens,
            api_version,
            max_response_bytes,
            versionless_refused: std::sync::Mutex::default(),
            cache_ttl,
            requests: None,
        }
    }

    /// Whether `host` refused a versionless operation.
    pub(crate) fn versionless_refused(&self, host: &str) -> bool {
        self.versionless_refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(host)
    }

    /// Records that `host` refuses versionless operations.
    pub(crate) fn refuse_versionless(&self, host: &str) {
        self.versionless_refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(host.to_owned());
    }

    /// `<base>/<segments...>?api-version=...`, each segment percent-encoded as one path segment
    /// (validated parts only; defence in depth).
    pub(crate) fn url(&self, target: &Target, segments: &[&str]) -> Result<reqwest::Url> {
        if segments.iter().any(|s| matches!(*s, "" | "." | "..")) {
            return Err(config_err(Operation::Configure, "invalid request path"));
        }
        let mut url = reqwest::Url::parse(&target.base_url())
            .map_err(|_| config_err(Operation::Configure, "invalid vault host"))?;
        url.path_segments_mut()
            .map_err(|()| config_err(Operation::Configure, "invalid vault host"))?
            .pop_if_empty()
            .extend(segments);
        url.query_pairs_mut()
            .append_pair("api-version", self.api_version.as_str());
        Ok(url)
    }

    fn http_for(&self, target: &Target) -> Result<&reqwest::Client> {
        if target.test {
            self.test_http
                .as_ref()
                .ok_or_else(|| config_err(Operation::Configure, "no client for test hosts"))
        } else {
            Ok(&self.http)
        }
    }

    async fn send(
        &self,
        target: &Target,
        call: &Call<'_>,
        token: &CachedToken,
    ) -> Result<(StatusCode, reqwest::header::HeaderMap, Zeroizing<Vec<u8>>)> {
        let secret = token.value().secret();
        let mut bearer = Zeroizing::new(String::with_capacity(7 + secret.len()));
        bearer.push_str("Bearer ");
        bearer.push_str(secret);
        // The header value is a copy anykms cannot wipe (see the crate docs).
        let mut auth = HeaderValue::from_str(&bearer)
            .map_err(|_| config_err(call.op, "access token contains invalid characters"))?;
        auth.set_sensitive(true);
        let mut req = self
            .http_for(target)?
            .request(call.method.clone(), call.url.clone())
            .header(reqwest::header::AUTHORIZATION, auth)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = &call.body {
            // reqwest copies the body into its own buffer; that copy cannot be wiped (see the
            // crate docs on zeroization limits).
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        if let Some(n) = &self.requests {
            n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        // `send` records `http_status` into the request span.
        use anykms_http::client::SendError;
        let resp = anykms_http::client::send(req, self.max_response_bytes)
            .await
            .map_err(|e| match e {
                SendError::NoRuntime => anykms_http::client::no_runtime_error(BACKEND, call.op),
                SendError::Transport(e) => {
                    anykms_http::client::transport_error(BACKEND, call.op, e)
                }
                SendError::TooLarge { status } => crate::errors::unusable_response(
                    call.op,
                    &target.host,
                    Some(status.as_u16()),
                    "response exceeds the maximum size",
                ),
            })?;
        Ok((resp.status, resp.headers, resp.body))
    }

    /// Performs a call, retrying once after a 401 if the credential then yields a new token.
    /// Returns the success body; every non-success response is classified.
    pub(crate) async fn call(&self, target: &Target, call: Call<'_>) -> Result<Zeroizing<Vec<u8>>> {
        // The shared span schema (docs/operations-azure.md, "Tracing").
        let span = anykms_http::request_span!(
            "anykms.azure",
            backend = BACKEND,
            op = call.op.as_str(),
            resource = call.resource,
            key_version = call.key_version,
        );
        let guard = anykms_http::span::start_request(&span);
        let r = anykms_http::span::instrument(self.call_inner(target, &call), &span).await;
        let (r, request_id) = match r {
            Ok((body, id)) => (Ok(body), id),
            Err(e) => (Err(e), None),
        };
        #[cfg(feature = "tracing")]
        if let Ok(body) = &r
            && call.key_version.is_none()
            && call.method == Method::POST
            && let Some(v) = kid_version(body)
        {
            span.record("key_version", v.as_str());
        }
        guard.finish(request_id.as_deref(), &r);
        r
    }

    /// The success body and its request id, or the classified failure.
    async fn call_inner(
        &self,
        target: &Target,
        call: &Call<'_>,
    ) -> Result<(Zeroizing<Vec<u8>>, Option<String>)> {
        // First: outside a Tokio runtime the credential sources and reqwest would panic.
        anykms_http::client::require_runtime(BACKEND, call.op)?;
        let scope = target.scope.as_str();
        let token = self
            .tokens
            .get(scope)
            .await
            .map_err(|e| e.with_operation(call.op))?;
        anykms_http::span::record_attempt(1);
        let (mut status, mut headers, mut body) = self.send(target, call, &token).await?;
        if status == StatusCode::UNAUTHORIZED {
            self.tokens.invalidate(scope, &token);
            // If no new token can be had now, report the original 401 rather than the
            // (possibly retryable) credential error.
            if let Ok(fresh) = self.tokens.get(scope).await
                && fresh.value().secret() != token.value().secret()
            {
                #[cfg(feature = "tracing")]
                tracing::debug!(reason = "token refreshed after 401", "retrying once");
                anykms_http::span::record_attempt(2);
                (status, headers, body) = self.send(target, call, &fresh).await?;
            }
        }
        if status.is_success() {
            return Ok((body, request_id(&headers).map(str::to_owned)));
        }
        let request_id = request_id(&headers);
        let tenant_hint = if status == StatusCode::UNAUTHORIZED {
            let challenged = headers
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .and_then(crate::errors::challenge_tenant);
            match (challenged, self.tokens.credential().tenant_id()) {
                (Some(c), Some(mine)) if !c.eq_ignore_ascii_case(mine) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        backend = BACKEND,
                        resource = call.resource,
                        challenge_tenant = c,
                        "the vault's tenant differs from the credential's"
                    );
                    Some(c)
                }
                _ => None,
            }
        } else {
            None
        };
        let parsed = ErrorBody::parse(&body);
        drop(body);
        Err(classify(&Failure {
            status: status.as_u16(),
            body: &parsed,
            retry_after: anykms_http::client::retry_after(&headers),
            request_id,
            op: call.op,
            class: call.class,
            key_seen: call.key_seen,
            tenant_hint,
            host: &target.host,
        }))
    }
}

/// Shared handle to the client.
pub(crate) type SharedClient = Arc<Client>;
