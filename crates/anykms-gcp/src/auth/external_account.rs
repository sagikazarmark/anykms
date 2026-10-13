//! `external_account` credentials (workload identity federation) with a `file` or `url` subject
//! token: the subject token (an OIDC ID token or a SAML assertion from GitHub Actions, AKS, EKS,
//! an on-premises Kubernetes cluster, ...) is exchanged at STS for a federated access token,
//! which is then optionally exchanged for a service account's token (impersonation).

use std::collections::BTreeMap;
use std::time::Duration;

use anykms_core::{BoxFuture, ErrorKind, Result};
use anykms_http::credentials::Expiring;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::file::CredFile;
use super::{
    AuthCtx, CLOUD_PLATFORM_SCOPE, Cached, Fetch, Fetched, MAX_CREDENTIAL_FILE, UrlField, auth_err,
    config_err, impersonated, oauth,
};

#[derive(Deserialize, Default)]
pub(crate) struct CredentialSourceSpec {
    file: Option<String>,
    url: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    format: Option<FormatSpec>,
    environment_id: Option<String>,
    executable: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct FormatSpec {
    #[serde(rename = "type")]
    kind: Option<String>,
    subject_token_field_name: Option<String>,
}

enum SubjectFormat {
    Text,
    Json(String),
}

enum Subject {
    File(std::path::PathBuf),
    Url {
        url: url::Url,
        headers: reqwest::header::HeaderMap,
    },
}

pub(crate) struct ExternalAccount {
    http: reqwest::Client,
    subject: Subject,
    format: SubjectFormat,
    audience: String,
    subject_token_type: String,
    token_url: url::Url,
    impersonation_url: Option<url::Url>,
    lifetime: Duration,
    user_project: Option<String>,
    quota_project: Option<String>,
}

pub(crate) fn from_file(f: CredFile, ctx: &AuthCtx) -> Result<Cached<ExternalAccount>> {
    let need = |v: Option<String>, field: &'static str| {
        v.filter(|s| !s.is_empty()).ok_or_else(|| {
            config_err(format!(
                "external_account credentials lack the `{field}` field"
            ))
        })
    };
    let audience = need(f.audience, "audience")?;
    let subject_token_type = need(f.subject_token_type, "subject_token_type")?;
    let token_url = match f.token_url.as_deref() {
        Some(u) => ctx.endpoints.checked_url(u, UrlField::StsTokenUrl)?,
        None => ctx.endpoints.sts_token.clone(),
    };
    let impersonation_url = f
        .service_account_impersonation_url
        .as_deref()
        .map(|u| ctx.endpoints.checked_url(u, UrlField::Impersonation))
        .transpose()?;
    let cs = f.credential_source.ok_or_else(|| {
        config_err("external_account credentials lack the `credential_source` field")
    })?;
    if cs
        .environment_id
        .as_deref()
        .is_some_and(|e| e.starts_with("aws"))
    {
        return Err(config_err(
            "external_account credentials with an AWS credential source are not built in; use \
             google-cloud-auth's through the anykms-gcp `google-cloud-auth` feature",
        ));
    }
    if cs.executable.is_some() {
        return Err(config_err(
            "external_account credentials with an executable credential source are not built \
             in; use google-cloud-auth's through the anykms-gcp `google-cloud-auth` feature",
        ));
    }
    let subject = match (cs.file, cs.url) {
        (Some(p), None) => Subject::File(p.into()),
        (None, Some(u)) => {
            let url = url::Url::parse(&u).map_err(|_| {
                config_err("external_account credential_source.url is not a valid URL")
            })?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(config_err(
                    "external_account credential_source.url must be http:// or https://",
                ));
            }
            let mut headers = reqwest::header::HeaderMap::new();
            for (k, v) in cs.headers {
                let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).map_err(|_| {
                    config_err("external_account credential_source.headers has an invalid name")
                })?;
                let mut value = reqwest::header::HeaderValue::from_str(&v).map_err(|_| {
                    config_err("external_account credential_source.headers has an invalid value")
                })?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
            Subject::Url { url, headers }
        }
        _ => {
            return Err(config_err(
                "external_account credential_source must have exactly one of `file` or `url`",
            ));
        }
    };
    let format = match cs.format {
        None => SubjectFormat::Text,
        Some(f) => match f.kind.as_deref() {
            None | Some("text") => SubjectFormat::Text,
            Some("json") => SubjectFormat::Json(f.subject_token_field_name.ok_or_else(|| {
                config_err(
                    "external_account credential_source.format of type json needs \
                     subject_token_field_name",
                )
            })?),
            Some(_) => {
                return Err(config_err(
                    "external_account credential_source.format.type must be text or json",
                ));
            }
        },
    };
    let lifetime = Duration::from_secs(
        f.service_account_impersonation
            .and_then(|o| o.token_lifetime_seconds)
            .unwrap_or(3600)
            .clamp(600, 43_200),
    );
    Ok(Cached::new(ExternalAccount {
        http: ctx.http.clone(),
        subject,
        format,
        audience,
        subject_token_type,
        token_url,
        impersonation_url,
        lifetime,
        user_project: f.workforce_pool_user_project,
        quota_project: f.quota_project_id,
    }))
}

impl ExternalAccount {
    /// The subject token, in zeroizing memory.
    ///
    /// A subject token **file** is classified like every token file (P1-2): missing is
    /// `Unavailable` (a projected token that a kubelet or CI runner rewrites: a rotation race),
    /// anything else (unreadable, too large, not UTF-8, not JSON, no field, empty) is
    /// `Configuration`, and the error names the path. A subject token **URL** that answers with
    /// an unusable body stays `Unavailable` (the endpoint may recover).
    async fn subject_token(&self) -> Result<Zeroizing<String>> {
        let (raw, file) = match &self.subject {
            Subject::File(p) => {
                let raw = anykms_http::zbuf::read_file(p, MAX_CREDENTIAL_FILE).map_err(|e| {
                    auth_err(
                        anykms_http::zbuf::token_file_error_kind(&e),
                        format!(
                            "cannot read the subject token file {}: {}",
                            p.display(),
                            e.kind()
                        ),
                    )
                })?;
                (raw, Some(p))
            }
            Subject::Url { url, headers } => {
                let req = self.http.get(url.clone()).headers(headers.clone());
                (oauth::send("subject token URL", req).await?, None)
            }
        };
        let unusable = |what: &str| match file {
            Some(p) => auth_err(
                ErrorKind::Configuration,
                format!("the subject token file {} {what}", p.display()),
            ),
            None => auth_err(
                ErrorKind::Unavailable,
                format!("the subject token response {what}"),
            ),
        };
        let token = match &self.format {
            SubjectFormat::Text => {
                let s = std::str::from_utf8(&raw).map_err(|_| unusable("is not UTF-8"))?;
                Zeroizing::new(s.trim().to_owned())
            }
            SubjectFormat::Json(field) => {
                let mut v: serde_json::Value =
                    serde_json::from_slice(&raw).map_err(|_| unusable("is not JSON"))?;
                let t = match v.get_mut(field.as_str()).map(serde_json::Value::take) {
                    Some(serde_json::Value::String(s)) => Zeroizing::new(s),
                    _ => return Err(unusable("lacks the subject token field")),
                };
                v.zeroize_strings();
                t
            }
        };
        if token.is_empty() {
            return Err(unusable("holds an empty subject token"));
        }
        Ok(token)
    }
}

/// Wipes every string in a JSON value (best effort; serde_json's parse buffers are not reached).
trait ZeroizeStrings {
    fn zeroize_strings(&mut self);
}

impl ZeroizeStrings for serde_json::Value {
    fn zeroize_strings(&mut self) {
        match self {
            serde_json::Value::String(s) => s.zeroize(),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|v| v.zeroize_strings()),
            serde_json::Value::Object(o) => o.values_mut().for_each(|v| v.zeroize_strings()),
            _ => {}
        }
    }
}

impl Fetch for ExternalAccount {
    fn kind(&self) -> &'static str {
        "external_account"
    }

    fn endpoint_host(&self) -> Option<String> {
        self.token_url.host_str().map(str::to_owned)
    }

    fn fetch(&self) -> BoxFuture<'_, Result<Expiring<Fetched>>> {
        Box::pin(async move {
            const WHAT: &str = "STS token endpoint";
            let subject = self.subject_token().await?;
            let options = self
                .user_project
                .as_ref()
                .filter(|_| self.impersonation_url.is_none())
                .map(|p| serde_json::json!({"userProject": p}).to_string());
            let mut pairs: Vec<(&str, &[u8])> = vec![
                (
                    "grant_type",
                    b"urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("audience", self.audience.as_bytes()),
                ("scope", CLOUD_PLATFORM_SCOPE.as_bytes()),
                (
                    "requested_token_type",
                    b"urn:ietf:params:oauth:token-type:access_token",
                ),
                ("subject_token", subject.as_bytes()),
                ("subject_token_type", self.subject_token_type.as_bytes()),
            ];
            if let Some(o) = &options {
                pairs.push(("options", o.as_bytes()));
            }
            let body = oauth::form(&pairs);
            drop(subject);
            let resp =
                oauth::send(WHAT, oauth::post_form(&self.http, &self.token_url, body)).await?;
            let federated = oauth::parse_oauth_token(WHAT, &resp)?;
            drop(resp);
            match &self.impersonation_url {
                None => Ok(federated),
                Some(url) => {
                    impersonated::exchange(
                        &self.http,
                        url,
                        federated.value().secret(),
                        &[],
                        self.lifetime,
                    )
                    .await
                }
            }
        })
    }

    fn quota_project(&self) -> Option<&str> {
        self.quota_project.as_deref()
    }
}
