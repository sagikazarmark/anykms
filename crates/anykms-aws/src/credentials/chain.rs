//! The default credential chain.

use std::sync::{Arc, Mutex};

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};

use super::{
    ContainerCredentials, CredentialSource, Credentials, EnvCredentials, ImdsCredentials,
    ProfileCredentials, SourceContext, Vars, WebIdentityCredentials,
};
use crate::BACKEND;

/// The default chain: the first configured source of
///
/// 1. the environment (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`);
/// 2. the shared files' profile (`AWS_PROFILE`, else `default` when a file has it);
/// 3. web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`);
/// 4. the container endpoint (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `_FULL_URI`);
/// 5. EC2 instance metadata (IMDSv2), unless `AWS_EC2_METADATA_DISABLED=true`.
///
/// A configured source that fails is reported (the chain does not fall through to the next
/// one, which could silently pick other credentials). The variables are read when the chain is
/// created; files and endpoints on the first fetch. The source that worked is kept for later
/// refreshes. Instance metadata is the last resort: while it has never answered, its failure is
/// reported as `Configuration` ("no credentials found"); after it has worked, as `Unavailable`.
#[derive(Debug, Clone)]
pub struct DefaultChain {
    vars: Vars,
    chosen: Arc<Mutex<Option<Arc<dyn CredentialSource>>>>,
}

impl DefaultChain {
    /// A snapshot of the process environment.
    pub fn new() -> Self {
        Self::from_vars(Vars::from_env())
    }

    /// Like `new`, reading variables from `lookup` instead of the process environment (empty
    /// values count as unset).
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self::from_vars(Vars::from_fn(lookup))
    }

    pub(crate) fn from_vars(vars: Vars) -> Self {
        Self {
            vars,
            chosen: Arc::default(),
        }
    }

    /// The source to use, with whether it is the IMDS fallback.
    fn select(&self) -> Result<(Arc<dyn CredentialSource>, bool)> {
        let v = &self.vars;
        if EnvCredentials::configured(v) {
            return Ok((Arc::new(EnvCredentials::from_vars(v.clone())), false));
        }
        let profile = ProfileCredentials::from_vars(v.clone());
        if profile.configured()? {
            return Ok((Arc::new(profile), false));
        }
        if WebIdentityCredentials::configured(v) {
            return Ok((
                Arc::new(WebIdentityCredentials::from_vars(v.clone())?),
                false,
            ));
        }
        if ContainerCredentials::configured(v) {
            return Ok((Arc::new(ContainerCredentials::from_vars(v.clone())), false));
        }
        if v.flag("AWS_EC2_METADATA_DISABLED")? == Some(true) {
            return Err(no_credentials());
        }
        Ok((Arc::new(ImdsCredentials::from_vars(v.clone())), true))
    }
}

fn no_credentials() -> Error {
    Error::new(
        ErrorKind::Configuration,
        BACKEND,
        Operation::Configure,
        "no AWS credentials found (environment, shared profile, web identity, container \
         endpoint; instance metadata disabled or unreachable)",
    )
}

impl Default for DefaultChain {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialSource for DefaultChain {
    fn kind(&self) -> &'static str {
        "default_chain"
    }

    fn credentials<'a>(&'a self, cx: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(async move {
            let chosen = self
                .chosen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(s) = chosen {
                return s.credentials(cx).await;
            }
            let (source, imds) = self.select()?;
            #[cfg(feature = "tracing")]
            tracing::info!(
                backend = BACKEND,
                source = source.kind(),
                "AWS credential source selected"
            );
            match source.credentials(cx).await {
                Ok(c) => {
                    *self
                        .chosen
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
                    Ok(c)
                }
                Err(e) if imds && e.kind() != ErrorKind::Unauthenticated => {
                    Err(no_credentials().with_source(e))
                }
                Err(e) => Err(e),
            }
        })
    }
}
