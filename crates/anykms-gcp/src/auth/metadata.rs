//! The metadata server (GCE, GKE Workload Identity, Cloud Run, Cloud Functions).
//!
//! `GET http://<host>/computeMetadata/v1/instance/service-accounts/default/token` with
//! `Metadata-Flavor: Google`; the response must carry `Metadata-Flavor: Google` too. Plain HTTP
//! only to `169.254.169.254`, `metadata.google.internal`, the `GCE_METADATA_HOST` override or the
//! [`AuthEndpoints::custom`](super::AuthEndpoints::custom) origin; never a redirect.

use std::time::Duration;

use anykms_core::{BoxFuture, ErrorKind, Result};
use std::sync::Arc;

use anykms_http::credentials::Expiring;
use anykms_http::http::Method;
use anykms_http::url::Url;
use anykms_http::{HttpTransport, RequestTimeout};

use super::{AuthCtx, Cached, Fetch, Fetched, auth_err, config_err, oauth};

/// The default metadata server address: the link-local IP, which needs no DNS.
pub(crate) const DEFAULT_HOST: &str = "169.254.169.254";

/// The metadata server origin: the custom auth origin, `GCE_METADATA_HOST` (`host[:port]`), or
/// [`DEFAULT_HOST`].
pub(crate) fn origin(ctx: &AuthCtx) -> Result<Url> {
    if let Some(m) = &ctx.endpoints.metadata {
        return Ok(m.clone());
    }
    let host = match ctx.env.get("GCE_METADATA_HOST") {
        Some(h) => h
            .into_string()
            .map_err(|_| config_err("GCE_METADATA_HOST must be host[:port]"))?,
        None => DEFAULT_HOST.to_owned(),
    };
    if host.contains(['/', '?', '#', '@']) {
        return Err(config_err("GCE_METADATA_HOST must be host[:port]"));
    }
    Url::parse(&format!("http://{host}/"))
        .map_err(|_| config_err("GCE_METADATA_HOST must be host[:port]"))
}

pub(crate) struct Metadata {
    http: Arc<dyn HttpTransport>,
    token_url: Url,
}

/// The per-request timeout of every metadata-server request (a
/// [`RequestTimeout`](anykms_http::RequestTimeout)): the server is link-local and answers in
/// milliseconds, so an absent one must not stall the credential chain for the transport's full
/// request timeout.
pub(crate) const METADATA_TIMEOUT: Duration = Duration::from_secs(3);

/// A `GET` of a metadata URL with the `Metadata-Flavor: Google` header and [`METADATA_TIMEOUT`].
fn metadata_get(url: &Url) -> anykms_http::http::Result<anykms_http::transport::Request> {
    anykms_http::client::request(Method::GET, url)
        .header("Metadata-Flavor", "Google")
        .extension(RequestTimeout(METADATA_TIMEOUT))
        .body(anykms_http::client::empty())
}

/// Whether a metadata server can be reached from this target at all. It is link-local, so on a
/// JS host (a Cloudflare Worker) it cannot be, and the host's `fetch` need not honour
/// [`METADATA_TIMEOUT`]: nothing is sent there.
const REACHABLE: bool = !cfg!(all(target_arch = "wasm32", target_os = "unknown"));

pub(crate) fn source(ctx: &AuthCtx) -> Result<Cached<Metadata>> {
    if !REACHABLE {
        return Err(config_err(
            "the metadata server is not reachable from this target (wasm32-unknown-unknown): \
             configure credentials explicitly",
        ));
    }
    let base = origin(ctx)?;
    let token_url = base
        .join("/computeMetadata/v1/instance/service-accounts/default/token")
        .map_err(|_| config_err("invalid metadata server address"))?;
    Ok(Cached::new(Metadata {
        http: ctx.http.clone(),
        token_url,
    }))
}

/// Whether a metadata server answers at `base` (any response with `Metadata-Flavor: Google`)
/// within [`METADATA_TIMEOUT`]. `false` without a probe where none can be reached.
pub(crate) async fn probe(ctx: &AuthCtx) -> bool {
    if !REACHABLE {
        return false;
    }
    let Ok(base) = origin(ctx) else {
        return false;
    };
    match anykms_http::client::send(&*ctx.http, metadata_get(&base), 4096).await {
        Ok(r) => r
            .headers
            .get("Metadata-Flavor")
            .is_some_and(|v| v.as_bytes() == b"Google"),
        Err(_) => false,
    }
}

const WHAT: &str = "metadata server";

impl Fetch for Metadata {
    fn kind(&self) -> &'static str {
        "metadata"
    }

    fn endpoint_host(&self) -> Option<String> {
        self.token_url.host_str().map(str::to_owned)
    }

    fn fetch(&self) -> BoxFuture<'_, Result<Expiring<Fetched>>> {
        Box::pin(async move {
            use anykms_http::SendError;
            let resp = anykms_http::client::send(
                &*self.http,
                metadata_get(&self.token_url),
                super::MAX_TOKEN_RESPONSE,
            )
            .await
            .map_err(|e| match e {
                SendError::TooLarge { .. } | SendError::Body(_) => {
                    auth_err(ErrorKind::Unavailable, "metadata server: response unusable")
                }
                e => {
                    let e = e.into_error(crate::BACKEND, anykms_core::Operation::Configure);
                    let kind = if e.kind() == ErrorKind::Timeout {
                        ErrorKind::Timeout
                    } else {
                        ErrorKind::Unavailable
                    };
                    auth_err(kind, format!("{WHAT}: {}", e.message())).with_source(e)
                }
            })?;
            let status = resp.status.as_u16();
            let flavor_ok = resp
                .headers
                .get("Metadata-Flavor")
                .is_some_and(|v| v.as_bytes() == b"Google");
            let body = resp.body;
            if !(200..300).contains(&status) {
                return Err(match status {
                    404 => auth_err(
                        ErrorKind::Configuration,
                        "metadata server: no service account is attached to this workload",
                    ),
                    _ => oauth::endpoint_error(WHAT, status, &body),
                });
            }
            if !flavor_ok {
                return Err(auth_err(
                    ErrorKind::Unavailable,
                    "metadata server: response lacks Metadata-Flavor: Google",
                ));
            }
            oauth::parse_oauth_token(WHAT, &body)
        })
    }
}
