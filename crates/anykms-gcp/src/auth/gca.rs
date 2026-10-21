//! Access tokens from Google's official auth library (feature `google-cloud-auth`).

use std::fmt;

use anykms_core::time::Instant;
use anykms_core::{BoxFuture, ErrorKind, Result};
use google_cloud_auth::credentials::AccessTokenCredentials;

use super::{CredentialSource, Token, auth_err};
use crate::BACKEND;

/// The `credential` of its token span.
const KIND: &str = "google_cloud_auth";

/// [`Credentials::google_cloud_auth`](super::Credentials::google_cloud_auth). Not behind
/// [`Cached`](super::Cached): the library caches and refreshes its tokens itself and does not
/// report their expiry, so each request asks it for the current token, inside a token span
/// (`anykms.gcp.token`, `credential = "google_cloud_auth"`) like the built-in sources' fetches.
pub(crate) struct GoogleCloudAuth(pub(crate) AccessTokenCredentials);

impl fmt::Debug for GoogleCloudAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GoogleCloudAuth").field(&self.0).finish()
    }
}

impl GoogleCloudAuth {
    async fn fetch(&self) -> Result<Option<Token>> {
        let t = self.0.access_token().await.map_err(|e| {
            // Transient: the token endpoint or metadata server failed; otherwise the credential
            // was refused or is unusable.
            let (kind, m) = if e.is_transient() {
                (
                    ErrorKind::Unavailable,
                    "google-cloud-auth could not fetch an access token",
                )
            } else {
                (
                    ErrorKind::Unauthenticated,
                    "google-cloud-auth refused to issue an access token",
                )
            };
            auth_err(kind, m).with_source(e)
        })?;
        Ok(Some(Token::new(t.token, None)))
    }
}

impl CredentialSource for GoogleCloudAuth {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async move {
            let span =
                anykms_http::token_span!("anykms.gcp.token", backend = BACKEND, credential = KIND);
            let started = Instant::now();
            let r = anykms_http::span::instrument(self.fetch(), &span).await;
            anykms_http::span::finish_token(&span, started, None, &r);
            #[cfg(feature = "tracing")]
            if let Err(e) = &r {
                tracing::warn!(
                    parent: &span,
                    backend = BACKEND,
                    credential = KIND,
                    error_kind = e.kind().as_str(),
                    error = %e,
                    "access token fetch failed"
                );
            }
            r
        })
    }
}
