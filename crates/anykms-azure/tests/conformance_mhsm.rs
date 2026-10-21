//! The conformance suite against a real Managed HSM: `ANYKMS_AZURE_LIVE=1`,
//! `ANYKMS_AZURE_MHSM_URL` (`https://<pool>.managedhsm.azure.net`) and a credential with
//! `Managed HSM Crypto Officer` and `Crypto User` (local RBAC). Declares AEAD (A256GCM) and, with
//! the `mhsm-hmac` feature, MAC. Manual / release-gated (an MHSM costs ~$3.20/h; see
//! `scripts/azure-test-setup.sh mhsm-up`). Skipped without them.

mod common;

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(async || common::AzureFixture::live(true))
}
