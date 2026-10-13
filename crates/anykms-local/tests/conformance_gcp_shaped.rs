//! Runs the conformance suite against a GCP-Cloud-KMS-shaped provider over local keys (no
//! rewrap, no data keys, version-addressed signing and MAC keys, per-version state; see
//! `shaped/gcp.rs`): proof that a backend of that shape passes without `Unsupported` stubs.

mod shaped;

fn main() -> std::process::ExitCode {
    anykms_conformance::run(async || shaped::gcp::GcpFixture::new())
}
