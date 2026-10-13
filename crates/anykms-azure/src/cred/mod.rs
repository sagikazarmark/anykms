//! Built-in credentials and the environment-driven selection (`docs/cloud/azure.md` §4.6).

mod entra;
mod managed_identity;
#[cfg(feature = "azure-identity")]
mod sdk;

use std::sync::Arc;

use anykms_core::Result;

pub use entra::{ClientSecret, WorkloadIdentity};
pub use managed_identity::{IMDS_ENDPOINT, ManagedIdentity};
#[cfg(feature = "azure-identity")]
pub use sdk::AzureIdentity;

use crate::credential::{AccessToken, AzureCredential, cred_config_err};

/// Which credential [`credential_from_env`] picks, without building it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvCredentialKind {
    /// [`WorkloadIdentity`].
    Workload,
    /// [`ManagedIdentity`].
    Managed,
    /// [`ClientSecret`].
    Secret,
    /// Disabled with `ANYKMS_AZURE_CREDENTIAL=none`.
    Disabled,
}

impl EnvCredentialKind {
    /// The name used in `ANYKMS_AZURE_CREDENTIAL` and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Managed => "managed",
            Self::Secret => "secret",
            Self::Disabled => "none",
        }
    }
}

/// Reads one environment variable (`None` when unset or not UTF-8).
pub(crate) type EnvGet<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The process environment, as an [`EnvGet`].
pub(crate) fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The credential the environment selects, deterministically and without network probing:
///
/// 1. `ANYKMS_AZURE_CREDENTIAL` = `workload`, `managed`, `secret` or `none` forces one
///    (`none` disables the Azure provider);
/// 2. else `AZURE_FEDERATED_TOKEN_FILE` set: workload identity;
/// 3. else `AZURE_CLIENT_SECRET` set: client secret;
/// 4. else `IDENTITY_ENDPOINT` set or `ANYKMS_AZURE_MANAGED_IDENTITY=1`: managed identity;
/// 5. else `Ok(None)`: no Azure credential configured.
///
/// Plain IMDS is never chosen without the opt-in: on a host off Azure it would wait for the
/// connect timeout at every operation. An unknown `ANYKMS_AZURE_CREDENTIAL` is `Configuration`.
pub fn env_credential_kind() -> Result<Option<EnvCredentialKind>> {
    kind_from(&process_env)
}

/// Like [`env_credential_kind`], reading variables from `lookup` instead of the process
/// environment.
pub fn env_credential_kind_with(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<EnvCredentialKind>> {
    kind_from(&lookup)
}

pub(crate) fn kind_from(get: EnvGet<'_>) -> Result<Option<EnvCredentialKind>> {
    let set = |n: &str| get(n).is_some_and(|v| !v.is_empty());
    if let Some(v) = get("ANYKMS_AZURE_CREDENTIAL")
        && !v.is_empty()
    {
        return Ok(Some(match v.as_str() {
            "workload" => EnvCredentialKind::Workload,
            "managed" => EnvCredentialKind::Managed,
            "secret" => EnvCredentialKind::Secret,
            "none" => EnvCredentialKind::Disabled,
            "cli" => {
                return Err(cred_config_err(
                    "ANYKMS_AZURE_CREDENTIAL=cli: the Azure CLI credential is not built in; use \
                     azure_identity's through the anykms-azure `azure-identity` feature",
                ));
            }
            _ => {
                return Err(cred_config_err(
                    "ANYKMS_AZURE_CREDENTIAL must be workload, managed, secret or none",
                ));
            }
        }));
    }
    Ok(if set("AZURE_FEDERATED_TOKEN_FILE") {
        Some(EnvCredentialKind::Workload)
    } else if set("AZURE_CLIENT_SECRET") {
        Some(EnvCredentialKind::Secret)
    } else if set("IDENTITY_ENDPOINT")
        || get("ANYKMS_AZURE_MANAGED_IDENTITY").is_some_and(|v| v == "1")
    {
        Some(EnvCredentialKind::Managed)
    } else {
        None
    })
}

const NO_CREDENTIAL: &str = "no Azure credential configured (set AZURE_FEDERATED_TOKEN_FILE, \
                             AZURE_CLIENT_SECRET or IDENTITY_ENDPOINT, or ANYKMS_AZURE_CREDENTIAL)";

/// The credential of a provider built from an environment that configures none: every token
/// request is `Configuration`, naming the variables. Keeps `from_env` lazy, as on AWS and GCP.
#[derive(Debug)]
pub(crate) struct Unconfigured;

impl AzureCredential for Unconfigured {
    fn token<'a>(&'a self, _scope: &'a str) -> anykms_core::BoxFuture<'a, Result<AccessToken>> {
        Box::pin(std::future::ready(Err(cred_config_err(NO_CREDENTIAL))))
    }

    fn kind(&self) -> &'static str {
        "unconfigured"
    }
}

/// Builds the credential [`env_credential_kind`] selects. No credential, or
/// `ANYKMS_AZURE_CREDENTIAL=none`, is `Configuration`. Nothing is read or fetched beyond
/// environment variables. The choice is logged at INFO (kind only) with the `tracing` feature.
pub fn credential_from_env() -> Result<Arc<dyn AzureCredential>> {
    credential_from(&process_env)
}

/// Like [`credential_from_env`], reading variables from `lookup` instead of the process
/// environment. Every variable is read here; the credential keeps nothing from the lookup.
pub fn credential_from_env_with(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Arc<dyn AzureCredential>> {
    credential_from(&lookup)
}

pub(crate) fn credential_from(get: EnvGet<'_>) -> Result<Arc<dyn AzureCredential>> {
    let kind = kind_from(get)?.ok_or_else(|| cred_config_err(NO_CREDENTIAL))?;
    #[cfg(feature = "tracing")]
    tracing::info!(
        backend = crate::BACKEND,
        credential = kind.as_str(),
        "Azure credential selected from the environment"
    );
    Ok(match kind {
        EnvCredentialKind::Workload => Arc::new(WorkloadIdentity::from_get(get)?),
        EnvCredentialKind::Secret => Arc::new(ClientSecret::from_get(get)?),
        EnvCredentialKind::Managed => Arc::new(ManagedIdentity::from_get(get)?),
        EnvCredentialKind::Disabled => {
            return Err(cred_config_err(
                "the Azure provider is disabled (ANYKMS_AZURE_CREDENTIAL=none)",
            ));
        }
    })
}
