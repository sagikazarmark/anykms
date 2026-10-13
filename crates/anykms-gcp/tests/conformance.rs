//! Runs the anykms conformance suite against the in-process fake Cloud KMS server
//! (`tests/common/fake.rs`), on every PR. See `tests/common/fixture.rs` for the declarations.

mod common;

fn main() -> std::process::ExitCode {
    anykms_conformance::run(async || common::fixture::GcpFixture::fake().await)
}
