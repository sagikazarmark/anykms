//! Runs the conformance suite against an Azure-Key-Vault-shaped provider over local keys (signing
//! and native key-wrapping keys only, opaque versions, emulator error messages; see
//! `shaped/azure.rs`): proof that a backend of that shape passes without `Unsupported` stubs.

mod shaped;

fn main() -> std::process::ExitCode {
    anykms_conformance::run(async || shaped::azure::AzFixture::new())
}
