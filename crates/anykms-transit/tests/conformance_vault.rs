//! Conformance suite against a HashiCorp Vault dev server (`ANYKMS_VAULT_ADDR`, default
//! http://127.0.0.1:8200; start it with scripts/dev-up.sh).

mod common;

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(async || {
        common::TransitFixture::connect("vault", anykms_transit::Flavor::Vault).await
    })
}
