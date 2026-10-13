# anykms-conformance

The shared conformance suite every anykms backend runs, through typed handles and through the
registry. A backend implements a `Fixture` and wires the suite up as a `harness = false` test
target:

```rust,ignore
// tests/conformance.rs
fn main() -> std::process::ExitCode {
    anykms_conformance::run(async || MyFixture::new().await)
}
```

Cases are gated on the capabilities the fixture declares in `Fixture::probe` (`Feature::Aead`,
`Mac`, `KeyWrap`, `Signing(alg)`, `Rewrap`, `DataKeys`, `RotateSigning`, `DisableVersion`, ...),
so a backend with only some key families (no AEAD keys, no rewrap, versions that are not
numbers) passes without `Unsupported` stubs. A feature the suite needs that the fixture did not
declare fails the run, so a capability added to the suite later is never silently skipped.

Most cases also run through the backend's typed handles (`Fixture::typed`). `TypedHandles`
bridges each typed handle, shared as an `Arc`, into the handles of its key family, then adds the
other parts it implements, its semantics and its own preflight check:

```rust,ignore
fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
    let k = Arc::new(self.0.aead_key(uri)?);
    let s = k.semantics().clone();
    Ok(AeadKeyHandles::bridge(k.clone())
        .with_rewrap(k.clone())
        .with_semantics(s)
        .with_preflight(k))
}
```

`KeyWrapKeyHandles`, `DigestKeyHandles`, `MessageKeyHandles` and `MacKeyHandles` work the same
way; the `typed_handles!` macro (feature `fixture-helpers`) writes the signing and MAC methods.

Run with `ANYKMS_FAIL_ON_SKIP=1` in CI so that a feature the fixture lacks in that environment
fails too; only features declared not applicable stay ignored.

For a complete, runnable starting point, see
[`examples/minimal_backend.rs`](https://github.com/sagikazarmark/anykms/blob/main/crates/anykms-conformance/examples/minimal_backend.rs):
a toy in-memory KMS with AES-256-GCM keys, its typed handle (`Aead`, `Describe`), its `Provider`
and a fixture that declares every feature, in about 250 lines, passing the suite on both paths
(`cargo run -p anykms-conformance --example minimal_backend`). It is a test target too, so CI
runs it. The `Provider` rustdoc lists the error kinds the suite expects (its "Errors" section),
and each capability trait the kinds of its own operations.

**Stability.** The fixture API may change in minor releases while backends are added. New
`Feature`s and new cases land only in a `0.(x+1)` release, never in a patch: a fixture must
declare every feature (an undeclared one fails the run), so a patch release never adds a feature
or case that a passing fixture has not declared or met.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management
services that keeps their differences visible.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
