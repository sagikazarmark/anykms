//! The conformance suite against an AWS KMS emulator (Floci by default; see tests/e2e/mod.rs).
//! Skipped when none is running unless ANYKMS_REQUIRE_FIXTURE=1.

mod e2e;

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(async || e2e::AwsFixture::emulator().await)
}
