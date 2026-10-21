//! The conformance suite against Lowkey Vault (a standard-vault emulator): signing (ECDSA,
//! RSA-PSS, RSA PKCS#1 v1.5), RSA-OAEP-256 key wrapping, data keys over it, describe, rotation.
//! Error messages come from the emulator, so message-derived cases are not applicable; AEAD and
//! MAC keys do not exist on standard vaults.
//!
//! Start Lowkey Vault with `docker compose --profile azure up -d lowkey-vault`. Without it every
//! case is skipped (a failure with `ANYKMS_REQUIRE_FIXTURE=1`).

mod common;

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(async || common::AzureFixture::lowkey())
}
