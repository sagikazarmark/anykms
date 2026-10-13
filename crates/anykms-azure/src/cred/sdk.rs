//! Access tokens from the Azure SDK (feature `azure-identity`).

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anykms_core::{BoxFuture, ErrorKind, Result};
use azure_core::credentials::TokenCredential;
use azure_core::error::ErrorKind as SdkErrorKind;
use zeroize::Zeroizing;

use crate::credential::{AccessToken, AzureCredential, cred_err};

/// Access tokens from any Azure SDK credential (`azure_core::credentials::TokenCredential`),
/// typically one from `azure_identity`: the Azure CLI, certificates, Azure Pipelines, Azure Arc
/// and the rest:
///
/// ```no_run
/// # // `azure_identity` is not a dependency: a stand-in returning a type its
/// # // `Arc<AzureCliCredential>` coerces to.
/// # mod azure_identity {
/// #     pub struct AzureCliCredential;
/// #     impl AzureCliCredential {
/// #         pub fn new(
/// #             _: Option<()>,
/// #         ) -> azure_core::Result<std::sync::Arc<dyn azure_core::credentials::TokenCredential>> {
/// #             unimplemented!()
/// #         }
/// #     }
/// # }
/// # use anykms_azure::{AzureIdentity, AzureProviderBuilder};
/// # fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// let cli = azure_identity::AzureCliCredential::new(None)?;
/// let provider = AzureProviderBuilder::default()
///     .credential(AzureIdentity::new(cli))
///     .build()?;
/// # Ok(()) }
/// ```
///
/// Only tokens come from the SDK: Key Vault calls stay on this crate's client, and the provider
/// caches each token until shortly before the expiry the SDK reports, as for the built-in
/// credentials. The SDK fetches with its own HTTP client, TLS provider and retries
/// (`azure_identity`'s credential options turn the retries off). Errors carry the SDK error as
/// their source.
#[derive(Clone)]
pub struct AzureIdentity(Arc<dyn TokenCredential>);

impl AzureIdentity {
    /// Tokens from `credential`. No I/O until the first operation.
    pub fn new(credential: Arc<dyn TokenCredential>) -> Self {
        Self(credential)
    }
}

impl fmt::Debug for AzureIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AzureIdentity").field(&self.0).finish()
    }
}

impl AzureCredential for AzureIdentity {
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, Result<AccessToken>> {
        Box::pin(async move {
            let t = self.0.get_token(&[scope], None).await.map_err(|e| {
                // Unreachable endpoints and server-side failures may pass; anything else (a
                // refused or unusable credential) will not.
                let transient = matches!(e.kind(), SdkErrorKind::Connection | SdkErrorKind::Io)
                    || e.http_status().is_some_and(|s| {
                        let s = u16::from(s);
                        s == 429 || s >= 500
                    });
                let (kind, m) = if transient {
                    (
                        ErrorKind::Unavailable,
                        "the Azure SDK credential could not fetch a token",
                    )
                } else {
                    (
                        ErrorKind::Unauthenticated,
                        "the Azure SDK credential did not issue a token",
                    )
                };
                cred_err(kind, m).with_source(e)
            })?;
            // Seconds since the epoch; a time before it is treated as already expired.
            let secs = u64::try_from(t.expires_on.unix_timestamp()).unwrap_or(0);
            let expires_at = UNIX_EPOCH + Duration::from_secs(secs);
            Ok(AccessToken::new(
                Zeroizing::new(t.token.secret().to_owned()),
                Some(expires_at),
            ))
        })
    }

    fn kind(&self) -> &'static str {
        "azure_identity"
    }
}
