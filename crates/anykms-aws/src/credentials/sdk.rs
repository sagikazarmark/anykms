//! Credentials from the AWS SDK (feature `sdk-credentials`).

use std::fmt;

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};

use super::{CredentialSource, Credentials, SourceContext};
use crate::BACKEND;

/// Credentials from an AWS SDK credentials provider, typically the one `aws-config` loads
/// (IAM Identity Center/SSO, role chaining, `credential_process` and the rest of the SDK chain):
///
/// ```no_run
/// # // `aws-config` is not a dependency: a stand-in returning the type it returns.
/// # mod aws_config {
/// #     pub struct BehaviorVersion;
/// #     impl BehaviorVersion { pub fn latest() -> Self { Self } }
/// #     pub struct SdkConfig;
/// #     impl SdkConfig {
/// #         pub fn credentials_provider(
/// #             &self,
/// #         ) -> Option<aws_credential_types::provider::SharedCredentialsProvider> {
/// #             unimplemented!()
/// #         }
/// #     }
/// #     pub async fn load_defaults(_: BehaviorVersion) -> SdkConfig { SdkConfig }
/// # }
/// # use anykms_aws::AwsProvider;
/// # use anykms_aws::credentials::SdkCredentials;
/// # async fn demo() -> anykms_core::Result<()> {
/// let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
/// let provider = AwsProvider::builder()
///     .credentials(SdkCredentials::new(sdk.credentials_provider().unwrap()))
///     .build()?;
/// # Ok(()) }
/// ```
///
/// Only the credentials come from the SDK: KMS calls stay on this crate's client, and the
/// provider caches what the SDK returns until shortly before it expires, as for the built-in
/// sources. The SDK fetches with its own HTTP client, TLS provider and retries (they run under
/// any [`RetryLayer`](anykms_core::RetryLayer); `aws-config`'s
/// `ConfigLoader::retry_config(RetryConfig::disabled())` turns the SDK's off). Errors carry the
/// SDK error as their source.
#[derive(Clone)]
pub struct SdkCredentials(SharedCredentialsProvider);

impl SdkCredentials {
    /// Credentials from `provider` (any `ProvideCredentials`, including a
    /// `SharedCredentialsProvider`). No I/O until the first operation.
    pub fn new(provider: impl ProvideCredentials + 'static) -> Self {
        Self(SharedCredentialsProvider::new(provider))
    }
}

impl fmt::Debug for SdkCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SdkCredentials").field(&self.0).finish()
    }
}

/// The error for a failed SDK credentials fetch: misconfiguration is `Configuration`, a timeout
/// `Timeout`, anything else `Unavailable` (the SDK does not say whether it would last).
fn sdk_err(e: CredentialsError) -> Error {
    let (kind, m) = match &e {
        CredentialsError::CredentialsNotLoaded(_) => (
            ErrorKind::Configuration,
            "the AWS SDK credentials provider found no credentials",
        ),
        CredentialsError::InvalidConfiguration(_) => (
            ErrorKind::Configuration,
            "the AWS SDK credentials provider is misconfigured",
        ),
        CredentialsError::ProviderTimedOut(_) => (
            ErrorKind::Timeout,
            "the AWS SDK credentials provider timed out",
        ),
        _ => (
            ErrorKind::Unavailable,
            "the AWS SDK credentials provider failed",
        ),
    };
    Error::new(kind, BACKEND, Operation::Configure, m).with_source(e)
}

impl CredentialSource for SdkCredentials {
    fn kind(&self) -> &'static str {
        "sdk"
    }

    fn credentials<'a>(&'a self, _: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(async move {
            let c = self.0.provide_credentials().await.map_err(sdk_err)?;
            let out = Credentials::new(
                c.access_key_id(),
                c.secret_access_key(),
                c.session_token().map(str::to_owned),
            )
            .with_expiry(c.expiry());
            out.validate()?;
            Ok(out)
        })
    }
}
