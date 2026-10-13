//! The metadata server (GCE, GKE Workload Identity, Cloud Run, Cloud Functions).
//!
//! `GET http://<host>/computeMetadata/v1/instance/service-accounts/default/token` with
//! `Metadata-Flavor: Google`; the response must carry `Metadata-Flavor: Google` too. Plain HTTP
//! only to `169.254.169.254`, `metadata.google.internal`, the `GCE_METADATA_HOST` override or the
//! [`AuthEndpoints::custom`](super::AuthEndpoints::custom) origin; never a redirect.

use std::time::Duration;

use anykms_core::{BoxFuture, ErrorKind, Result};
use anykms_http::credentials::Expiring;

use super::{AuthCtx, Cached, Fetch, Fetched, auth_err, config_err, oauth};

/// The default metadata server address: the link-local IP, which needs no DNS.
pub(crate) const DEFAULT_HOST: &str = "169.254.169.254";

/// The metadata server origin: the custom auth origin, `GCE_METADATA_HOST` (`host[:port]`), or
/// [`DEFAULT_HOST`].
pub(crate) fn origin(ctx: &AuthCtx) -> Result<url::Url> {
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
    url::Url::parse(&format!("http://{host}/"))
        .map_err(|_| config_err("GCE_METADATA_HOST must be host[:port]"))
}

pub(crate) struct Metadata {
    http: reqwest::Client,
    token_url: url::Url,
}

pub(crate) fn source(ctx: &AuthCtx) -> Result<Cached<Metadata>> {
    let base = origin(ctx)?;
    let token_url = base
        .join("/computeMetadata/v1/instance/service-accounts/default/token")
        .map_err(|_| config_err("invalid metadata server address"))?;
    Ok(Cached::new(Metadata {
        http: ctx.metadata_http.clone(),
        token_url,
    }))
}

/// Whether a metadata server answers at `base` (any response with `Metadata-Flavor: Google`),
/// within the metadata client's 1 s connect timeout and a 3 s overall limit.
pub(crate) async fn probe(ctx: &AuthCtx) -> bool {
    let Ok(base) = origin(ctx) else {
        return false;
    };
    match ctx
        .metadata_http
        .get(base)
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_secs(3))
        .send()
        .await
    {
        Ok(r) => r
            .headers()
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
            let req = self
                .http
                .get(self.token_url.clone())
                .header("Metadata-Flavor", "Google");
            let resp = req.send().await.map_err(|e| {
                let e = anykms_http::client::transport_error(
                    crate::BACKEND,
                    anykms_core::Operation::Configure,
                    e,
                );
                let kind = if e.kind() == ErrorKind::Timeout {
                    ErrorKind::Timeout
                } else {
                    ErrorKind::Unavailable
                };
                auth_err(kind, format!("{WHAT}: {}", e.message())).with_source(e)
            })?;
            let status = resp.status().as_u16();
            let flavor_ok = resp
                .headers()
                .get("Metadata-Flavor")
                .is_some_and(|v| v.as_bytes() == b"Google");
            let body = anykms_http::client::read_body(resp, super::MAX_TOKEN_RESPONSE)
                .await
                .map_err(|_| {
                    auth_err(ErrorKind::Unavailable, "metadata server: response unusable")
                })?;
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
