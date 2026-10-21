//! Service-account impersonation: a source credential's token exchanged for the target service
//! account's at `iamcredentials.googleapis.com` (`generateAccessToken`). Used by
//! `impersonated_service_account` files, by `external_account` files with a
//! `service_account_impersonation_url`, and by [`Credentials::impersonated`](super::Credentials::impersonated).

use std::sync::Arc;
use std::time::Duration;

use anykms_core::{BoxFuture, ErrorKind, Result};
use anykms_http::HttpTransport;
use anykms_http::credentials::Expiring;
use anykms_http::http::Method;
use anykms_http::http::header::{AUTHORIZATION, CONTENT_TYPE};
use anykms_http::url::Url;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    AuthEndpoints, CLOUD_PLATFORM_SCOPE, CredentialSource, Fetch, Fetched, auth_err, config_err,
    oauth,
};

/// The `generateAccessToken` URL for `target` (a service-account email).
pub(crate) fn generate_url(endpoints: &AuthEndpoints, target: &str) -> Result<Url> {
    let ok = !target.is_empty()
        && target.len() <= 254
        && target.contains('@')
        && target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'-' | b'_'));
    if !ok {
        return Err(config_err(
            "the service account to impersonate must be an email address",
        ));
    }
    let mut u = endpoints.iam_credentials.clone();
    u.path_segments_mut()
        .map_err(|()| config_err("invalid IAM credentials endpoint"))?
        .pop_if_empty()
        .extend([
            "v1",
            "projects",
            "-",
            "serviceAccounts",
            &format!("{target}:generateAccessToken"),
        ]);
    Ok(u)
}

/// Exchanges `source_token` for an impersonated token at `url`.
pub(crate) async fn exchange(
    http: &dyn HttpTransport,
    url: &Url,
    source_token: &str,
    delegates: &[String],
    lifetime: Duration,
) -> Result<Expiring<Fetched>> {
    const WHAT: &str = "IAM credentials endpoint";
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resp {
        access_token: Option<String>,
        expire_time: Option<String>,
    }
    let delegates: Vec<String> = delegates
        .iter()
        .map(|d| {
            if d.starts_with("projects/") {
                d.clone()
            } else {
                format!("projects/-/serviceAccounts/{d}")
            }
        })
        .collect();
    let mut body = serde_json::json!({
        "scope": [CLOUD_PLATFORM_SCOPE],
        "lifetime": format!("{}s", lifetime.as_secs()),
    });
    if !delegates.is_empty() {
        body["delegates"] = delegates.into();
    }
    let req = anykms_http::client::request(Method::POST, url)
        .header(AUTHORIZATION, oauth::bearer(source_token)?)
        .header(CONTENT_TYPE, "application/json")
        .body(Zeroizing::new(body.to_string().into_bytes()));
    let resp = oauth::send(WHAT, http, req).await?;
    let bad = || {
        auth_err(
            ErrorKind::Unavailable,
            format!("{WHAT}: unexpected token response"),
        )
    };
    let mut r: Resp = serde_json::from_slice(&resp).map_err(|_| bad())?;
    let token = Zeroizing::new(r.access_token.take().ok_or_else(bad)?);
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad());
    }
    match r.expire_time.as_deref().and_then(super::parse_rfc3339) {
        Some(secs) => Ok(Fetched::valid_until(
            token,
            std::time::UNIX_EPOCH + Duration::from_secs(secs),
        )),
        None => Ok(Fetched::valid_for(token, lifetime)),
    }
}

/// A source token from another credential, impersonated.
pub(crate) struct Impersonate {
    pub(crate) http: Arc<dyn HttpTransport>,
    pub(crate) source: Arc<dyn CredentialSource>,
    pub(crate) url: Url,
    pub(crate) delegates: Vec<String>,
    pub(crate) lifetime: Duration,
    pub(crate) quota_project: Option<String>,
}

impl Fetch for Impersonate {
    fn kind(&self) -> &'static str {
        "impersonated_service_account"
    }

    fn endpoint_host(&self) -> Option<String> {
        self.url.host_str().map(str::to_owned)
    }

    fn fetch(&self) -> BoxFuture<'_, Result<Expiring<Fetched>>> {
        Box::pin(async move {
            let source = self.source.token().await?.ok_or_else(|| {
                auth_err(
                    ErrorKind::Configuration,
                    "the impersonation source credential has no token",
                )
            })?;
            let r = exchange(
                &*self.http,
                &self.url,
                source.expose(),
                &self.delegates,
                self.lifetime,
            )
            .await;
            if let Err(e) = &r
                && e.kind() == ErrorKind::Unauthenticated
            {
                // The source token may have been revoked; let the next fetch get a new one.
                self.source.invalidate(&source);
            }
            r
        })
    }

    fn quota_project(&self) -> Option<&str> {
        self.quota_project
            .as_deref()
            .or_else(|| self.source.quota_project())
    }
}
