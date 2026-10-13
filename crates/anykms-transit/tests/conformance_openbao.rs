//! Conformance suite against an OpenBao dev server (`ANYKMS_OPENBAO_ADDR`, default
//! http://127.0.0.1:8300; start it with scripts/dev-up.sh).

mod common;

fn main() -> std::process::ExitCode {
    anykms_conformance::run_or_skip(async || {
        common::TransitFixture::connect("openbao", anykms_transit::Flavor::OpenBao).await
    })
}
