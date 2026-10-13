//! Credentials that exchange a secret or an assertion at the Entra ID token endpoint
//! (`POST {authority}/{tenant}/oauth2/v2.0/token`, client-credentials grant): workload identity
//! and client secret.

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anykms_core::{BoxFuture, ErrorKind, Result};
use zeroize::Zeroizing;

use super::EnvGet;
use crate::config::AzureCloud;
use crate::credential::{
    AccessToken, AzureCredential, LazyClient, cred_config_err, cred_err, form_body,
    send_token_request, validate_authority, validate_client_id, validate_tenant,
};

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The most a federated token file may hold.
const MAX_TOKEN_FILE: usize = 64 * 1024;

fn entra_client() -> LazyClient {
    LazyClient::new(Duration::from_secs(5), Duration::from_secs(30), true)
}

/// A set, non-empty variable.
fn env(get: EnvGet<'_>, name: &str) -> Option<String> {
    get(name).filter(|v| !v.is_empty())
}

fn authority_from_env(get: EnvGet<'_>) -> Result<String> {
    match env(get, "AZURE_AUTHORITY_HOST") {
        Some(h) => validate_authority(&h),
        None => Ok(AzureCloud::Public.authority_host().to_owned()),
    }
}

/// The parts every client-credentials exchange shares.
#[derive(Clone, Debug)]
struct Client {
    tenant: String,
    client_id: String,
    authority: String,
    http: LazyClient,
}

impl Client {
    fn new(tenant: String, client_id: String) -> Result<Self> {
        validate_tenant(&tenant)?;
        validate_client_id(&client_id)?;
        Ok(Self {
            tenant,
            client_id,
            authority: AzureCloud::Public.authority_host().to_owned(),
            http: entra_client(),
        })
    }

    async fn exchange(
        &self,
        scope: &str,
        secret_field: (&str, &str),
        extra: Option<(&str, &str)>,
        kind: &'static str,
    ) -> Result<AccessToken> {
        let mut pairs = vec![
            ("client_id", self.client_id.as_str()),
            ("scope", scope),
            ("grant_type", "client_credentials"),
        ];
        if let Some(e) = extra {
            pairs.push(e);
        }
        pairs.push(secret_field);
        let body = form_body(&pairs);
        let url = format!("{}/{}/oauth2/v2.0/token", self.authority, self.tenant);
        let req = self
            .http
            .get()?
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            // reqwest copies the body into its own buffer, which cannot be wiped.
            .body(body.to_vec());
        send_token_request(req, kind).await
    }
}

/// AKS workload identity: exchanges the projected service-account token in
/// `AZURE_FEDERATED_TOKEN_FILE` for an Entra ID token of the app registration or user-assigned
/// identity `AZURE_CLIENT_ID` in `AZURE_TENANT_ID`.
///
/// The file is read **at each exchange** (Kubernetes rotates it), never at construction. It must
/// be at most 64 KiB; its contents never appear in errors or logs. With the `tracing` feature a
/// warning is logged once when the file is group- or world-readable.
#[derive(Debug)]
pub struct WorkloadIdentity {
    client: Client,
    token_file: PathBuf,
    warned: AtomicBool,
}

impl WorkloadIdentity {
    /// Workload identity for `client_id` in `tenant_id`, with the federated token in
    /// `token_file`, against the public cloud's authority host.
    pub fn new(
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        token_file: impl Into<PathBuf>,
    ) -> Result<Self> {
        Ok(Self {
            client: Client::new(tenant_id.into(), client_id.into())?,
            token_file: token_file.into(),
            warned: AtomicBool::new(false),
        })
    }

    /// From `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE` and (optional)
    /// `AZURE_AUTHORITY_HOST`, as the AKS workload-identity webhook sets them. A missing variable
    /// is `Configuration`. Nothing is read from the file here.
    pub fn from_env() -> Result<Self> {
        Self::from_get(&super::process_env)
    }

    pub(crate) fn from_get(get: EnvGet<'_>) -> Result<Self> {
        let need = |n: &'static str| {
            env(get, n).ok_or_else(|| {
                cred_config_err(format!("workload identity needs {n} (not set or empty)"))
            })
        };
        let me = Self::new(
            need("AZURE_TENANT_ID")?,
            need("AZURE_CLIENT_ID")?,
            need("AZURE_FEDERATED_TOKEN_FILE")?,
        )?;
        me.authority_host(&authority_from_env(get)?)
    }

    /// The Entra ID authority host (default `https://login.microsoftonline.com`). Plain http is
    /// accepted only on a loopback IP (tests).
    pub fn authority_host(mut self, host: &str) -> Result<Self> {
        self.client.authority = validate_authority(host)?;
        Ok(self)
    }

    /// The authority host of `cloud`.
    pub fn cloud(mut self, cloud: AzureCloud) -> Self {
        self.client.authority = cloud.authority_host().to_owned();
        self
    }

    fn read_assertion(&self) -> Result<Zeroizing<String>> {
        let path = &self.token_file;
        // P1-2: missing is a rotation race (`Unavailable`); anything else is `Configuration`.
        let raw = anykms_http::zbuf::read_file(path, MAX_TOKEN_FILE).map_err(|e| {
            cred_err(
                anykms_http::zbuf::token_file_error_kind(&e),
                format!(
                    "cannot read the federated token file {}: {}",
                    path.display(),
                    if e.kind() == std::io::ErrorKind::InvalidData {
                        "larger than 64 KiB".to_owned()
                    } else {
                        e.kind().to_string()
                    }
                ),
            )
        })?;
        self.warn_permissions();
        let trimmed = raw.trim_ascii();
        if trimmed.is_empty() || !trimmed.iter().all(|b| b.is_ascii_graphic()) {
            return Err(cred_err(
                ErrorKind::Configuration,
                format!(
                    "the federated token file {} is empty or not a token",
                    path.display()
                ),
            ));
        }
        let mut s = Zeroizing::new(String::with_capacity(trimmed.len()));
        s.push_str(std::str::from_utf8(trimmed).expect("ASCII"));
        Ok(s)
    }

    fn warn_permissions(&self) {
        #[cfg(all(unix, feature = "tracing"))]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&self.token_file)
                .map(|m| m.permissions().mode())
                .unwrap_or(0);
            if mode & 0o077 != 0 && !self.warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    backend = crate::BACKEND,
                    credential = "workload_identity",
                    "the federated token file is group- or world-accessible"
                );
            }
        }
        let _ = &self.warned;
        let _ = Ordering::Relaxed;
    }
}

impl AzureCredential for WorkloadIdentity {
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, Result<AccessToken>> {
        Box::pin(async move {
            let assertion = self.read_assertion()?;
            self.client
                .exchange(
                    scope,
                    ("client_assertion", assertion.as_str()),
                    Some(("client_assertion_type", JWT_BEARER)),
                    "workload-identity",
                )
                .await
        })
    }

    fn kind(&self) -> &'static str {
        "workload_identity"
    }

    fn tenant_id(&self) -> Option<&str> {
        Some(&self.client.tenant)
    }
}

/// An app registration's client secret (`AZURE_CLIENT_SECRET`). The secret is held in a
/// zeroizing buffer and never appears in `Debug` output, errors or logs.
pub struct ClientSecret {
    client: Client,
    secret: Zeroizing<String>,
}

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSecret")
            .field("tenant", &self.client.tenant)
            .field("client_id", &self.client.client_id)
            .field("authority", &self.client.authority)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl ClientSecret {
    /// A client secret for `client_id` in `tenant_id`, against the public cloud's authority.
    pub fn new(
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<Self> {
        let secret = Zeroizing::new(secret.into());
        if secret.is_empty() {
            return Err(cred_config_err("the client secret is empty"));
        }
        Ok(Self {
            client: Client::new(tenant_id.into(), client_id.into())?,
            secret,
        })
    }

    /// From `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` and (optional)
    /// `AZURE_AUTHORITY_HOST`.
    pub fn from_env() -> Result<Self> {
        Self::from_get(&super::process_env)
    }

    pub(crate) fn from_get(get: EnvGet<'_>) -> Result<Self> {
        let need = |n: &'static str| {
            env(get, n).ok_or_else(|| {
                cred_config_err(format!(
                    "client secret credential needs {n} (not set or empty)"
                ))
            })
        };
        let secret = Zeroizing::new(need("AZURE_CLIENT_SECRET")?);
        let me = Self::new(
            need("AZURE_TENANT_ID")?,
            need("AZURE_CLIENT_ID")?,
            secret.as_str(),
        )?;
        me.authority_host(&authority_from_env(get)?)
    }

    /// The Entra ID authority host (see [`WorkloadIdentity::authority_host`]).
    pub fn authority_host(mut self, host: &str) -> Result<Self> {
        self.client.authority = validate_authority(host)?;
        Ok(self)
    }

    /// The authority host of `cloud`.
    pub fn cloud(mut self, cloud: AzureCloud) -> Self {
        self.client.authority = cloud.authority_host().to_owned();
        self
    }
}

impl AzureCredential for ClientSecret {
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, Result<AccessToken>> {
        Box::pin(async move {
            self.client
                .exchange(
                    scope,
                    ("client_secret", self.secret.as_str()),
                    None,
                    "client-secret",
                )
                .await
        })
    }

    fn kind(&self) -> &'static str {
        "client_secret"
    }

    fn tenant_id(&self) -> Option<&str> {
        Some(&self.client.tenant)
    }
}
