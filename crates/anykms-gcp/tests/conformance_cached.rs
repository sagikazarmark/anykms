//! Runs the anykms conformance suite against the in-process fake Cloud KMS server with the
//! provider's default public-key cache (`tests/conformance.rs` runs it with none), so the cases
//! that count requests also hold when public keys are cached, as in production.

mod common;

fn main() -> std::process::ExitCode {
    anykms_conformance::run(async || common::fixture::GcpFixture::fake_cached().await)
}
