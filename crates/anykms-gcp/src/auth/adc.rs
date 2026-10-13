//! Application Default Credentials: the chain of the [module docs](super), resolved on the first
//! token request. A failed resolution is not cached: the next request tries again.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use anykms_core::{BoxFuture, Result};

use super::file;
use super::{AuthCtx, CredentialSource, EnvVars, Token, config_err, metadata};

pub(crate) struct AdcSource {
    ctx: AuthCtx,
    resolved: tokio::sync::OnceCell<Arc<dyn CredentialSource>>,
}

impl fmt::Debug for AdcSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationDefaultCredentials")
            .field("resolved", &self.resolved.get())
            .finish()
    }
}

/// The gcloud ADC file: `$CLOUDSDK_CONFIG/application_default_credentials.json`, else
/// `$HOME/.config/gcloud/…` (`%APPDATA%\gcloud\…` on Windows).
pub(crate) fn well_known_file(env: &EnvVars) -> Option<PathBuf> {
    const NAME: &str = "application_default_credentials.json";
    let var = |v: &str| env.get(v);
    if let Some(dir) = var("CLOUDSDK_CONFIG") {
        return Some(PathBuf::from(dir).join(NAME));
    }
    if cfg!(windows) {
        return var("APPDATA").map(|d| PathBuf::from(d).join("gcloud").join(NAME));
    }
    var("HOME").map(|h| PathBuf::from(h).join(".config").join("gcloud").join(NAME))
}

impl AdcSource {
    pub(crate) fn new(ctx: AuthCtx) -> Self {
        Self {
            ctx,
            resolved: tokio::sync::OnceCell::new(),
        }
    }

    async fn resolve(&self) -> Result<Arc<dyn CredentialSource>> {
        let log = |_step: &'static str| {
            #[cfg(feature = "tracing")]
            tracing::info!(
                backend = crate::BACKEND,
                source = _step,
                "GCP application default credentials selected"
            );
        };
        if let Some(p) = self.ctx.env.get("GOOGLE_APPLICATION_CREDENTIALS") {
            log("GOOGLE_APPLICATION_CREDENTIALS");
            return self.load_path(PathBuf::from(p)).await;
        }
        if let Some(p) = well_known_file(&self.ctx.env)
            && p.is_file()
        {
            log("gcloud ADC file");
            return self.load_path(p).await;
        }
        if metadata::probe(&self.ctx).await {
            log("metadata server");
            return Ok(Arc::new(metadata::source(&self.ctx)?));
        }
        Err(config_err(
            "no GCP credentials found: set GOOGLE_APPLICATION_CREDENTIALS, run `gcloud auth \
             application-default login`, or run where a metadata server is reachable",
        ))
    }

    /// The file at `p`, read and parsed now (so a broken file fails this resolution).
    async fn load_path(&self, p: PathBuf) -> Result<Arc<dyn CredentialSource>> {
        let json = file::read(&p)?;
        let built = file::parse(&json, None, &self.ctx)
            .map_err(|e| config_err(format!("{}: {}", p.display(), e.message())))?;
        drop(json);
        #[cfg(feature = "tracing")]
        tracing::info!(
            backend = crate::BACKEND,
            credential = built.kind,
            "GCP credentials loaded"
        );
        Ok(built.source)
    }

    async fn source(&self) -> Result<&Arc<dyn CredentialSource>> {
        self.resolved.get_or_try_init(|| self.resolve()).await
    }
}

impl CredentialSource for AdcSource {
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
