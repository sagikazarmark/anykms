//! The conformance suite against a real Azure key vault: `ANYKMS_AZURE_LIVE=1`,
//! `ANYKMS_AZURE_VAULT_URL` (`https://<vault>.vault.azure.net`) and a credential the environment
//! selects (`AZURE_*`, see `anykms_azure::credential_from_env`) with `Key Vault Crypto Officer`
//! on the vault (the fixture creates, rotates, disables and deletes keys named
//! `anykms-<time>-<pid>-<n>`; `scripts/azure-test-setup.sh janitor` purges leftovers). Skipped
//! without them (a failure with `ANYKMS_REQUIRE_FIXTURE=1`).

mod common;

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(async || common::AzureFixture::live(false).await)
}
