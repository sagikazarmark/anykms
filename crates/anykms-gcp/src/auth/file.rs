//! Credential JSON files: parsing by `type` and the lazy file source.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anykms_core::{BoxFuture, Result};
use anykms_http::HttpTransport;
use anykms_http::url::Url;
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

use super::{
    AuthCtx, Cached, CredentialSource, MAX_CREDENTIAL_FILE, Token, UrlField, config_err,
    external_account, impersonated, oauth,
};

/// A secret string field: zeroized on drop, redacted in `Debug`. (serde_json's own scratch
/// buffers for escaped strings are not wiped; see the crate docs on zeroization limits.)
#[derive(Clone)]
pub(crate) struct Secret(pub(crate) Zeroizing<String>);

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(|s| Secret(Zeroizing::new(s)))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Every field of every supported credential type (one struct, so no untagged buffering of
/// secrets).
#[derive(Deserialize, Default)]
pub(crate) struct CredFile {
    #[serde(rename = "type")]
    pub(crate) kind: Option<String>,
    pub(crate) universe_domain: Option<String>,
    pub(crate) quota_project_id: Option<String>,
    // service_account (read with the `service-account-key` feature)
    #[cfg_attr(not(feature = "service-account-key"), allow(dead_code))]
    pub(crate) client_email: Option<String>,
    #[cfg_attr(not(feature = "service-account-key"), allow(dead_code))]
    pub(crate) private_key: Option<Secret>,
    #[cfg_attr(not(feature = "service-account-key"), allow(dead_code))]
    pub(crate) private_key_id: Option<String>,
    // authorized_user
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<Secret>,
    pub(crate) refresh_token: Option<Secret>,
    pub(crate) token_uri: Option<String>,
    // external_account
    pub(crate) audience: Option<String>,
    pub(crate) subject_token_type: Option<String>,
    pub(crate) token_url: Option<String>,
    pub(crate) service_account_impersonation_url: Option<String>,
    pub(crate) service_account_impersonation: Option<ImpersonationOptions>,
    pub(crate) credential_source: Option<external_account::CredentialSourceSpec>,
    pub(crate) workforce_pool_user_project: Option<String>,
    // impersonated_service_account
    pub(crate) source_credentials: Option<Box<CredFile>>,
    pub(crate) delegates: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
pub(crate) struct ImpersonationOptions {
    pub(crate) token_lifetime_seconds: Option<u64>,
}

/// A parsed credential: its source and type name.
pub(crate) struct Built {
    pub(crate) source: Arc<dyn CredentialSource>,
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    pub(crate) kind: &'static str,
}

fn require<T>(v: Option<T>, kind: &str, field: &'static str) -> Result<T> {
    v.ok_or_else(|| config_err(format!("{kind} credentials lack the `{field}` field")))
}

/// Builds the source for a parsed credential file. `depth` guards nested
/// `source_credentials`.
pub(crate) fn build(f: CredFile, ctx: &AuthCtx, depth: u8) -> Result<Built> {
    if let Some(u) = f.universe_domain.as_deref()
        && u != "googleapis.com"
    {
        return Err(config_err(
            "credentials for universe domains other than googleapis.com are not supported",
        ));
    }
    let kind = f
        .kind
        .clone()
        .ok_or_else(|| config_err("credential file has no `type` field"))?;
    let quota = f.quota_project_id.clone();
    match kind.as_str() {
        "service_account" => service_account(f, ctx),
        "authorized_user" => {
            let token_url = match f.token_uri.as_deref() {
                Some(u) => ctx.endpoints.checked_url(u, UrlField::TokenUri)?,
                None => ctx.endpoints.oauth2_token.clone(),
            };
            Ok(Built {
                source: Arc::new(Cached::new(AuthorizedUser {
                    http: ctx.http.clone(),
                    token_url,
                    client_id: require(f.client_id, &kind, "client_id")?,
                    client_secret: require(f.client_secret, &kind, "client_secret")?,
                    refresh_token: require(f.refresh_token, &kind, "refresh_token")?,
                    quota_project: quota,
                })),
                kind: "authorized_user",
            })
        }
        "external_account" => Ok(Built {
            source: Arc::new(external_account::from_file(f, ctx)?),
            kind: "external_account",
        }),
        "impersonated_service_account" => {
            if depth > 0 {
                return Err(config_err(
                    "nested impersonated_service_account credentials are not supported",
                ));
            }
            let url = require(
                f.service_account_impersonation_url.as_deref(),
                &kind,
                "service_account_impersonation_url",
            )?;
            let url = ctx.endpoints.checked_url(url, UrlField::Impersonation)?;
            let src = require(f.source_credentials, &kind, "source_credentials")?;
            let source = build(*src, ctx, depth + 1)?.source;
            Ok(Built {
                source: Arc::new(Cached::new(impersonated::Impersonate {
                    http: ctx.http.clone(),
                    source,
                    url,
                    delegates: f.delegates.unwrap_or_default(),
                    lifetime: Duration::from_secs(3600),
                    quota_project: quota,
                })),
                kind: "impersonated_service_account",
            })
        }
        "external_account_authorized_user" | "gdch_service_account" => Err(config_err(format!(
            "credential type `{kind}` is not built in; use google-cloud-auth's through the \
             anykms-gcp `google-cloud-auth` feature (`Credentials::google_cloud_auth`)"
        ))),
        _ => Err(config_err("unknown credential file `type`")),
    }
}

#[cfg(feature = "service-account-key")]
fn service_account(f: CredFile, _ctx: &AuthCtx) -> Result<Built> {
    let kind = "service_account";
    Ok(Built {
        source: Arc::new(Cached::new(super::service_account::SelfSignedJwt::new(
            require(f.client_email, kind, "client_email")?,
            f.private_key_id,
            &require(f.private_key, kind, "private_key")?,
            f.quota_project_id,
        )?)),
        kind,
    })
}

#[cfg(not(feature = "service-account-key"))]
fn service_account(_f: CredFile, _ctx: &AuthCtx) -> Result<Built> {
    Err(config_err(
        "service-account key files need the anykms-gcp `service-account-key` feature",
    ))
}

/// Parses a credential document (the `expected` type, when given) and builds its source.
pub(crate) fn parse(json: &[u8], expected: Option<&str>, ctx: &AuthCtx) -> Result<Built> {
    let f: CredFile = serde_json::from_slice(json)
        .map_err(|_| config_err("credential file is not valid credentials JSON"))?;
    if let (Some(want), Some(got)) = (expected, f.kind.as_deref())
        && want != got
    {
        return Err(config_err(format!(
            "credential file has type `{got}`, expected `{want}`"
        )));
    }
    build(f, ctx, 0)
}

/// Reads a credential file (bounded); errors name the path and the I/O reason, never contents.
pub(crate) fn read(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>> {
    anykms_http::zbuf::read_file(path, MAX_CREDENTIAL_FILE).map_err(|e| {
        let why = if e.kind() == std::io::ErrorKind::InvalidData {
            "larger than 64 KiB".to_owned()
        } else {
            e.kind().to_string()
        };
        config_err(format!(
            "cannot read credential file {}: {why}",
            path.display()
        ))
    })
}

/// Where a lazy credential comes from.
pub(crate) enum Origin {
    Path(PathBuf),
    Json(Arc<Zeroizing<Vec<u8>>>),
}

/// A credential file (or document) parsed on first use; a failure is not cached.
pub(crate) struct FileSource {
    origin: Origin,
    expected: Option<&'static str>,
    ctx: AuthCtx,
    resolved: tokio::sync::OnceCell<Arc<dyn CredentialSource>>,
}

impl fmt::Debug for FileSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("FileCredentials");
        match &self.origin {
            Origin::Path(p) => d.field("path", p),
            Origin::Json(_) => d.field("json", &"<redacted>"),
        };
        d.field("type", &self.expected).finish_non_exhaustive()
    }
}

impl FileSource {
    pub(crate) fn new(origin: Origin, expected: Option<&'static str>, ctx: AuthCtx) -> Self {
        Self {
            origin,
            expected,
            ctx,
            resolved: tokio::sync::OnceCell::new(),
        }
    }

    async fn source(&self) -> Result<&Arc<dyn CredentialSource>> {
        self.resolved
            .get_or_try_init(|| async {
                let built = match &self.origin {
                    Origin::Path(p) => {
                        let json = read(p)?;
                        parse(&json, self.expected, &self.ctx)
                            .map_err(|e| config_err(format!("{}: {}", p.display(), e.message())))?
                    }
                    Origin::Json(j) => parse(j, self.expected, &self.ctx)?,
                };
                #[cfg(feature = "tracing")]
                tracing::info!(
                    backend = crate::BACKEND,
                    credential = built.kind,
                    "GCP credentials loaded"
                );
                Ok(built.source)
            })
            .await
    }
}

impl CredentialSource for FileSource {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async move { self.source().await?.token().await })
    }

    fn invalidate(&self, rejected: &Token) {
        if let Some(s) = self.resolved.get() {
            s.invalidate(rejected);
        }
    }

    fn quota_project(&self) -> Option<&str> {
        self.resolved.get()?.quota_project()
    }
}

/// `authorized_user`: a refresh token exchanged at the OAuth 2.0 token endpoint.
pub(crate) struct AuthorizedUser {
    http: Arc<dyn HttpTransport>,
    token_url: Url,
    client_id: String,
    client_secret: Secret,
    refresh_token: Secret,
    quota_project: Option<String>,
}

impl super::Fetch for AuthorizedUser {
    fn kind(&self) -> &'static str {
        "authorized_user"
    }

    fn endpoint_host(&self) -> Option<String> {
        self.token_url.host_str().map(str::to_owned)
    }

    fn fetch(&self) -> BoxFuture<'_, Result<anykms_http::credentials::Expiring<super::Fetched>>> {
        Box::pin(async move {
            const WHAT: &str = "OAuth token endpoint";
            let body = oauth::form(&[
                ("grant_type", b"refresh_token"),
                ("client_id", self.client_id.as_bytes()),
                ("client_secret", self.client_secret.0.as_bytes()),
                ("refresh_token", self.refresh_token.0.as_bytes()),
            ]);
            let req = oauth::post_form(&self.token_url, &body);
            drop(body);
            let resp = oauth::send(WHAT, &*self.http, req).await?;
            oauth::parse_oauth_token(WHAT, &resp)
        })
    }

    fn quota_project(&self) -> Option<&str> {
        self.quota_project.as_deref()
    }
}
