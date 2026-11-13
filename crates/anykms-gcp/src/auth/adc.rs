//! Application Default Credentials: the chain of the [module docs](super), resolved on the first
//! token request. A failed resolution is not cached: the next request tries again.
//!
//! Concurrent first requests share one resolution (one metadata-server probe), but wait for it
//! no longer than the transport's follower bound
//! ([`HttpTransport::follower_wait`](anykms_http::HttpTransport::follower_wait)): a resolving
//! caller that is alive but no longer polled would otherwise strand every later caller before
//! they reach the (equally bounded) token cache. A caller that gives up resolves for itself;
//! the first resolution to finish is kept.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anykms_core::{BoxFuture, Result};
use anykms_http::cache::SingleFlight;

use super::file;
use super::{AuthCtx, CredentialSource, EnvVars, Token, config_err, metadata};

pub(crate) struct AdcSource {
    ctx: AuthCtx,
    resolved: OnceLock<Arc<dyn CredentialSource>>,
    /// The resolution in progress, bounded by the transport's follower wait.
    resolving: SingleFlight<(), Result<Arc<dyn CredentialSource>>>,
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
        let resolving = SingleFlight::new();
        resolving.bound_by(&*ctx.http);
        Self {
            ctx,
            resolved: OnceLock::new(),
            resolving,
        }
    }

    async fn resolve(&self) -> Result<Arc<dyn CredentialSource>> {
        let log = |step: &'static str| {
            #[cfg(feature = "tracing")]
            tracing::info!(
                backend = crate::BACKEND,
                source = step,
                "GCP application default credentials selected"
            );
            #[cfg(not(feature = "tracing"))]
            let _ = step;
        };
        if let Some(p) = self.ctx.env.get("GOOGLE_APPLICATION_CREDENTIALS") {
            log("GOOGLE_APPLICATION_CREDENTIALS");
            return self.load_path(Path::new(&p));
        }
        if let Some(p) = well_known_file(&self.ctx.env)
            && p.is_file()
        {
            log("gcloud ADC file");
            return self.load_path(&p);
        }
        // A GCE_METADATA_HOST that is unusable (malformed, or plain HTTP to a remote host
        // without the opt-in) is named, not skipped as "no metadata server".
        metadata::origin(&self.ctx)?;
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
    fn load_path(&self, p: &Path) -> Result<Arc<dyn CredentialSource>> {
        let json = file::read(p)?;
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
        if let Some(s) = self.resolved.get() {
            return Ok(s);
        }
        let s = self
            .resolving
            .run(&(), || async {
                // A resolution that finished after the check above is kept.
                match self.resolved.get() {
                    Some(s) => Ok(s.clone()),
                    None => self.resolve().await,
                }
            })
            .await?;
        // The first resolution wins, so every caller shares one source and its token cache.
        Ok(self.resolved.get_or_init(|| s))
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
