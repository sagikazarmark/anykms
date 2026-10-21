//! Runs the anykms conformance suite against real Cloud KMS. Skipped (every case reported as
//! `skip`) unless `ANYKMS_GCP_LIVE=1`; `ANYKMS_REQUIRE_FIXTURE=1` (the nightly job) turns a
//! missing configuration into a failure.
//!
//! - `ANYKMS_GCP_KEY_RING`: `projects/<p>/locations/<l>/keyRings/<r>`, where the fixture creates
//!   its keys (`t-<run>-<n>`, versions scheduled for destruction after 24 h by
//!   `scripts/gcp-test-setup.sh sweep`);
//! - data-plane credentials: Application Default Credentials (in CI, the workload identity
//!   federation file written by `google-github-actions/auth`);
//! - admin token: `ANYKMS_GCP_ADMIN_TOKEN`, else `gcloud auth print-access-token`;
//! - optional `ANYKMS_GCP_DATA_TOKEN`: a data-plane token for the request-counting provider
//!   (which needs a static token), when the admin identity cannot use keys (signerVerifier);
//!   defaults to the admin token;
//! - optional `ANYKMS_GCP_UNAUTHORIZED_TOKEN`: a token of an identity without Cloud KMS roles.

mod common;

use std::time::Duration;

use anykms_gcp::GcpProvider;
use common::fixture::{Admin, GcpFixture, Mode};

async fn live() -> Result<GcpFixture, String> {
    if std::env::var("ANYKMS_GCP_LIVE").as_deref() != Ok("1") {
        return Err("ANYKMS_GCP_LIVE is not 1".into());
    }
    let ring = std::env::var("ANYKMS_GCP_KEY_RING")
        .map_err(|_| "ANYKMS_GCP_KEY_RING is not set".to_owned())?;
    let project = ring
        .split('/')
        .nth(1)
        .ok_or("ANYKMS_GCP_KEY_RING must be projects/<p>/locations/<l>/keyRings/<r>")?
        .to_owned();
    let admin_token = match std::env::var("ANYKMS_GCP_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            let out = std::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .output()
                .map_err(|e| format!("gcloud: {e}"))?;
            if !out.status.success() {
                return Err("gcloud auth print-access-token failed".into());
            }
            String::from_utf8(out.stdout)
                .map_err(|_| "token is not UTF-8")?
                .trim()
                .to_owned()
        }
    };
    let builder = GcpProvider::builder()
        .allowed_projects([project])
        .public_key_ttl(Duration::ZERO)
        .http_transport(
            anykms_gcp::anykms_http::ReqwestTransport::builder()
                .request_timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| e.to_string())?,
        );
    let counting_token = std::env::var("ANYKMS_GCP_DATA_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| admin_token.clone());
    let unauthorized_token = std::env::var("ANYKMS_GCP_UNAUTHORIZED_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    Ok(GcpFixture::new(
        Mode::Live { unauthorized_token },
        Admin::new("https://cloudkms.googleapis.com", admin_token.clone()),
        ring,
        builder,
        counting_token,
    ))
}

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(live)
}
