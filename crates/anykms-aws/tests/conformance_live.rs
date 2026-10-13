//! The conformance suite against real AWS KMS, gated on ANYKMS_AWS_LIVE=1 (see tests/e2e/mod.rs).
//! Skipped otherwise.

mod e2e;

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(async || e2e::AwsFixture::live().await)
}
