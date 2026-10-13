# 0.1.0 release plan

Source: the pre-release review in [`release-review.md`](release-review.md) (HEAD `ee91665`), plus
the maintainer's decisions on every finding (2026-10-13). Finding ids (`R-n`) refer to that report,
which holds the evidence. This plan records what was decided and in what order to do it.

Effort: XS < 1h, S ≈ half a day, M ≈ 1–3 days.

**Scope.** The review rated 2 findings Blocker and 11 Should-fix, about 2–3 days of work. The
maintainer pulled several 0.1.x and Later items forward, mostly because breaking changes are free
until the first publish, which brings the total to roughly **8–12 working days**. Phase 1 holds
every breaking change; once it lands, the API is frozen for 0.1.0.

## Implementation status

Every item of Phases 1–4 is done on the `release-remediation` branch (`git log 6794f33..`); what
is left is `docs/releasing.md`, as amended. Commits per item, and where the implementation
departs from the plan below:

| Item | Commits | Deviations and additions |
|---|---|---|
| 1.1 | `cbf30ec` | `AAD_CONTEXT_KEY` keeps its name (value `associatedData`). The optional Tink interop test is not in CI: an emulator test checks the raw Tink-shaped context both ways, and Tink Python 1.12.0 was checked by hand against Floci (both directions). |
| 1.2 | `250b97a` | — |
| 1.3 | `56faaae` | `KeyWrapDataKeys::kek()` became `inner()`. |
| 1.4 | `3d928cb` | — |
| 1.5 | `0dc2594` | — |
| 1.6 | `63077f8` | `Preflight`, `ExtensionCalls` and AWS's `EncryptionContextAead` require `Send + Sync` too. |
| 1.7 | `1751d68` | — |
| 1.8 | `10c7139` | `AeadBridge`/`KeyWrapBridge` became `AeadKeyHandles`/`KeyWrapKeyHandles`; every handle set's `bridge` takes an `Arc`. |
| 1.9 | `9729f50` | Variants are built with constructors (`Fault::throttled(n)`, ..., `Fault::of_kind`) and `Fault` stays `Copy`; the target operation and the error live in the keyset's queue. |
| 1.10 | `cefcb7f` | — |
| 2.1 | `ffa7cac` (R-30), `24a57b9` (R-34) | Single flight also covers the transit key-type cache and GCP's key-type checks, not only AWS and Azure (supersedes `review-plan.md` 3.10). |
| 2.2 | `ddab606` | — |
| 2.3 | `7fa2611` | The skip also logs a `tracing` warning. |
| 2.4 | `438194a` | `anykms_http::client::send` returns `SendError::NoRuntime`; `client::require_runtime` runs before the credential fetch. |
| 2.5 | `1ddcb19` | The registry also hints at pasted Cloud KMS REST URLs and bare AWS ARNs. |
| 2.6 | `60d1a30` | `EnvelopeKeyring::rewrap_to_primary` is gone: it became `rewrap_local`, which also moves envelopes on older versions of the primary. `EnvelopeKeyring`'s default KEK type is `KeyWrapKey` (was `Arc<dyn DynKeyWrap>`), so a KEK keeps its rewrap part. |
| 2.7 | `2c7ebe5` | A separate method, `rewrap_verified(&ct, aad)`, rather than an option on `rewrap_current`. |
| 2.8 | `206693a` | New `Feature::DescribeVersionState`, which the case `describe::generic_preflight_disabled_primary` needs. |
| 2.9 | `2ba172f` | — |
| 2.10 | `8691173` | — |
| 3.1, 3.3, 3.17 | `0b66734` | — |
| 3.2, 3.12, 3.15 | `91e3145` | — |
| 3.4, 3.5, 3.6 | `d556f04` | — |
| 3.7, 3.8, 3.9, 3.10 | `ddbac75` | — |
| 3.11 | `c842850` | — |
| 3.13 | `fa09836` | The facade's `doc_snippets` test holds verbatim copies of every `rust` block of the READMEs and `docs/operations*.md` and fails when one drifts (not a rustdoc include, so the READMEs need no hidden lines); the server-free snippets run. `aws-config` and `azure_identity` are stand-in modules, not dependencies. The rustdoc bridge examples are `no_run` doctests. The conformance README's `rust,ignore` fixture fragments stay unchecked (the `minimal_backend` example covers them). |
| 3.14 | `5f7caaf` | KEK is "key-wrapping key" everywhere (after `KeyWrap`), not "key-encryption key". |
| 3.16 | `49f6855` | — |
| 3.18 | `1095841` | — |
| 4.1 | `44ecca8` | Every crate's metadata also passes `--cfg docsrs`; `scripts/docs-rs.sh` fails when a hand-written feature list leaves out a public feature; CI job `docs-rs`. |
| 4.2 | `4cf15c3` | — |
| 4.3 | `2118da8` | LocalStack was dropped from the gates (its skip is now a warning) rather than made to fail. |
| 4.4 | `6c29913` | — |

## Decisions

| # | Decision | Supersedes |
|---|---|---|
| D1 | AWS AAD is sent as Tink's encryption context `{"associatedData": lowercase_hex(aad)}`, omitted for empty AAD. Verified against Tink's source: Java (`BinaryUtils.toHex`, which is `Base16Lower`), Python (`binascii.hexlify`), C++ (`absl::BytesToHexString`) and Go's default (`hex.EncodeToString`) all use this key and lowercase hex. Go's legacy `additionalData` is not supported; an option for it would be additive. | Settled #57 (`anykms-aad`, base64url) |
| D2 | `JwtSigner`/`sign_jwt` refuse to sign when there is no TTL, the claims carry no `exp`, and the caller did not call `JwtOptions::without_expiry()`. | — (settled #86 is about claim policy, not signing defaults) |
| R-8 | Capability traits require `Send + Sync`. | The Send-only bound |
| R-33 | A cloud TLS-roots failure in `with_default_providers()` skips that provider instead of failing the registry. | `docs/cloud/shared.md` P1-12, for the facade defaults only |
| R-34 | Key-metadata caches become single-flight, together with the credential cache. | `docs/review-plan.md` 3.10 ("single-flight not added") |
| R-24 | Lockstep versioning stays for 0.1; anykms-http's stability wording is aligned with what CI enforces. Independent versioning stays possible after publish. | — |
| R-27 | Facade defaults stay as they are; library authors are told to use `default-features = false`. | — |

## Phase 1: breaking changes and wire contracts (the API freeze)

Do these first: later phases build on the renamed and re-shaped API.

| # | Item | Change | Files | Effort |
|---|---|---|---|---|
| 1.1 | D1 + R-50 | Encode AAD as `{"associatedData": lowercase_hex(aad)}`; omit the context for empty AAD (unchanged). Reserve `associatedData` in `EncryptionContextAead`. Apply the 3072-byte AAD cap only to producing operations (Encrypt, GenerateDataKey*), not Decrypt, so "may only rise" is safe across mixed fleets. Recheck the headroom: hex doubles the length (6144 + 14 characters, under the measured 8140). Update the vectors, `operations-aws.md` (the IAM pin becomes `kms:EncryptionContextKeys ["associatedData"]`), the rustdoc in `lib.rs`/`context.rs`/`handles.rs`, and the CHANGELOG. Add a byte-exact context test. Optional but worthwhile: a floci interop test where Tink Python encrypts and anykms decrypts, and the reverse. | `anykms-aws/src/{context,handles,lib,extension}.rs`, tests, `docs/operations-aws.md` | S |
| 1.2 | D2 / R-11 | Add `JwtOptions::without_expiry()`. In `JwtOptions::payload`, return `InvalidArgument` when `ttl` is unset, the claims have no `exp`, and `without_expiry` was not called; name `with_ttl` and `without_expiry()` in the message. `Default` behaves like `new()`. Update `tests/verify_jose.rs:909`, the examples and the jose rustdoc. | `anykms-recipes/src/jose.rs`, tests, examples | S |
| 1.3 | R-3 | Make the fields of `EmulatedDataKeys`, `KeyWrapDataKeys` and `ClientRewrap` private; add `new`/`inner`/`into_inner`, as core's `AeadKeyWrap` has. Update the call sites (`anykms-azure/src/provider.rs:683`, `handles.rs:1567`, `conformance cases/recipes.rs:357`, `docs/cloud/gcp.md:523`). | `anykms-recipes/src/{datakeys,rewrap}.rs` | XS |
| 1.4 | R-6 | Make the credential `kind()` labels snake_case: `workload_identity`, `client_secret`, `managed_identity`, `azure_identity`, `google_cloud_auth`. Update the pinned tests (`anykms-azure provider.rs:754-760`) and the docs tables. Document `kind()` as a stable snake_case label, and document the two meanings of `attempt` (credential refresh on request spans, retry attempt on retry events). Leave the `ANYKMS_AZURE_CREDENTIAL` values unchanged. | azure `entra.rs`, `managed_identity.rs`, `cred/sdk.rs`; gcp `auth/gca.rs`; docs | XS |
| 1.5 | R-7 | Rename anykms-recipes' features `aws-lc-rs` → `rsa-aws-lc-rs` and `rsa` → `rsa-rustcrypto`, with no aliases. Update the forwards in the facade and the aws, gcp and azure manifests, the workspace comments and the README. | `crates/*/Cargo.toml`, README | XS |
| 1.6 | R-8 | Add `Sync` to the capability traits (and their `Dyn*` mirrors), so that `Arc<K: Aead>` crosses tasks without an extra bound. Check every implementor (typed handles, `Retry<T>`, decorators, local test fakes, conformance helpers) and drop now-redundant `+ Sync` bounds. Record the decision. | `anykms-core/src/{traits,dynamic}.rs`, implementors | S |
| 1.7 | R-5 | Rename anykms-azure's `TokenCredential` trait to `AzureCredential`, removing the clash with `azure_core::credentials::TokenCredential`. Update the re-exports, docs and `operations-azure.md`. | `anykms-azure/src/credential.rs` and users | XS–S |
| 1.8 | R-52 | Keep one conformance bridging style, the builder style (`DigestKeyHandles::bridge(..).with_preflight(..)`), and convert the struct-style bridges (`AeadBridge`, `KeyWrapBridge`, …) to it. Update the backends' conformance fixtures and the conformance README. | `anykms-conformance/src/{fixture,helpers,lib}.rs`, backend tests | S |
| 1.9 | R-53 | Rework local `Fault`: variant-level `#[non_exhaustive]`, `Fault::Kind { kind, times }` (any `ErrorKind`, including caller-class and `Unauthenticated`), `inject_error(Error, times)` for Retry-After or hints, and `inject_on(Operation, ..)` to target one operation. | `anykms-local/src/keyset.rs`, handles | S |
| 1.10 | R-46 | Add `SkippedProvider::cause() -> SkipCause` (`#[non_exhaustive]`: `FeatureDisabled`, `NotConfigured`, `OptedOut`, plus `TlsRoots` from 2.3). Filter on it in the README snippet so a transit-only app prints nothing for features it never enabled. | `crates/anykms/src/lib.rs`, README | S |

## Phase 2: behaviour fixes

| # | Item | Change | Files | Effort |
|---|---|---|---|---|
| 2.1 | R-30 + R-34 | Make the shared credential cache truly single-flight: one fetch in flight, every waiter gets its result (success **or** failure), failures are cached briefly (transit uses 5 s), and refresh-ahead is non-blocking (holders of a valid token keep using it while one task refreshes). Reuse the same primitive for the AWS and Azure key-metadata caches, so 20 concurrent encrypts make one metadata request. Fix the module doc's promise. Test both with concurrency tests (8 callers on a source that fails after 1 s must take about 1 s, not 8). | `anykms-http/src/{credentials,cache}.rs`, aws/azure `provider.rs`/`handles.rs` | M |
| 2.2 | R-32 | Add a drop guard in `ObserveLayer` that reports a cancelled call (`is_ok() == false`, a cancelled outcome), and set `outcome=cancelled` on request spans. | `anykms-core/src/observe.rs`, `anykms-http/src/span.rs` | S |
| 2.3 | R-33 | In the facade's `with_default_providers()`, turn a cloud provider's TLS-roots failure into a `SkippedProvider` (cause `TlsRoots`) instead of an error. Explicitly configured providers keep failing closed. Correct the "does no I/O" wording (`crates/anykms/src/lib.rs:126`). | `crates/anykms/src/lib.rs`, aws/gcp/azure `client.rs` | S |
| 2.4 | R-35 | In `anykms-http`'s `send`, check `tokio::runtime::Handle::try_current()` and return a `Configuration` error that names the fix, instead of panicking. Add a "From synchronous code" README snippet that uses a `current_thread` runtime. | `anykms-http/src/client.rs`, README | XS |
| 2.5 | R-39 | Error messages: attach the URI as the resource on typed opener paths (parse inside `with_resource`); state the GCP project-ID rules in the message; add hints for `azure-kv://https://…` and for a pasted `https://….vault.azure.net/keys/…`; name the `LocalKeyKind` in local mismatch errors. | transit/aws/gcp/azure `provider.rs`, `uri.rs`; `anykms-local/src/handles.rs`; registry | S |
| 2.6 | R-44 | Rotation tooling: `rewrap_current` on `EnvelopeAead` and `EnvelopeKeyring` (server-side rewrap where supported, otherwise `rewrap_local`, and it also moves older primary versions); `EnvelopeKeyring::primary_id()`/`kek_ids()`; a documented completion scan via `Envelope::parse().kek_id()`; an `Unsupported` message that names `rewrap_local` (`dynamic.rs:1596-1600`). | `anykms-recipes/src/envelope.rs`, `anykms-core/src/dynamic.rs`, `docs/operations.md` | S–M |
| 2.7 | R-47 | Add a verifying rewrap, e.g. `rewrap_verified(&ct, aad)`, that decrypts with the row's AAD (catching swapped rows and corrupted payloads) before rewrapping. Correct the `rewrap_local` docs: it checks the key commitment and that the DEK unwraps, and never sees the AAD or the payload. | `anykms-recipes/src/envelope.rs` | S |
| 2.8 | R-49 | In core's generic `check_preflight`, refuse a non-Enabled primary version when `KeyInfo` lists one. Add a conformance case. | `anykms-core/src/dynamic.rs`, conformance | S |
| 2.9 | R-29 | Require `zeroize = "1.9.1"` (1.9.0's `Zeroizing` `Debug` prints the bytes), update `Cargo.lock`, and add a canary test that formats a `decrypt` result with `{:?}` and asserts the plaintext is absent. | `Cargo.toml`, `Cargo.lock`, recipes tests | XS |
| 2.10 | R-23 | Require `google-cloud-auth = "1.3"`. | `anykms-gcp/Cargo.toml` | XS |

## Phase 3: documentation

Docs.rs and the crates.io README are frozen for each published version, so these land before the tag.
Do 3.13 last, so it compiles the final README.

| # | Item | Change | Effort |
|---|---|---|---|
| 3.1 | R-2 | Wherever the envelope's writer set is described, say that with a public-key (RSA) KEK, every holder of the public key can write envelopes: the envelope then gives confidentiality only, and AAD does not authenticate the writer. Places: `envelope-format.md:118-120`, the envelope module rustdoc (`envelope.rs:18-21`), the recipes crate table, `operations.md` "Retiring envelope KEKs", `operations-aws.md:43`, and the envelope notes in `operations-azure.md` and `operations-gcp.md:40`. Add to the retirement advice that a symmetric primary does not protect a keyring that keeps an RSA secondary. | XS–S |
| 3.2 | R-12 | Fix `jose.rs:9-11`: AWS kids and `AKT` tags carry the full key ARN. Add a note on this to `operations-aws.md`, with the compact-tag pattern (`as_bytes()` + `Tag::from_parts(alg, None, ..)`). | XS |
| 3.3 | R-17 | One-line status note ("v1 is frozen and always decrypts; external review pending; not yet recommended for long-lived data") in the envelope module rustdoc, the `EnvelopeAead`/`EnvelopeKeyring` docs, the recipes README and the facade's recipes section. Say how promotion will be announced. The quick start links to it. | XS |
| 3.4 | R-19 | Rewrite the README's error-to-HTTP prose in `class()` order (caller, hinted, retryable, config) and move the `CachedVerifier` example out of the 503 clause. Add: 400 applies when the input came from the request; a caller-class error on the application's own stored ciphertext is a data-integrity 500 and should alert. | XS |
| 3.5 | R-20 + R-43 | `RetryPolicy::interactive()` rustdoc and `operations.md:470-474`: the worst case is the deadline plus one in-flight attempt, up to the provider's `request_timeout` (10 s by default), plus any credential wait. To bound it, lower `request_timeout` or wrap the call in `tokio::time::timeout`. In the README, show `retry_layer().with_policy(RetryPolicy::interactive())` for registries that serve requests. | XS |
| 3.6 | R-31 | Correct "per-backend bound" (README.md:558-561, `operations.md:122-127`): one budget is shared by every backend behind a registry layer. | XS |
| 3.7 | R-18 | Qualify "(e.g. a FIPS build)" in the README, and add a "FIPS scope" paragraph: KMS operations run in the KMS; TLS follows a FIPS provider only when one is configured or installed through the re-exported rustls 0.23; the envelope, SigV4 and local verification use RustCrypto and are not FIPS-validated. | XS |
| 3.8 | R-22 | Add the missing rows to the README's "Public dependencies": `aws-credential-types` (`SdkCredentials`), `google-cloud-auth` (`Credentials::google_cloud_auth`), `azure_core` (`AzureIdentity`), and anykms-http's `http`, `rustls-pki-types` and `tracing`. | XS |
| 3.9 | R-24 + R-25 | Make anykms-http's stability wording match what lockstep and the blocking semver job enforce. For anykms-conformance, state that new `Feature`s and cases land only in a `0.(x+1)` release, and put the stability caveat into its rustdoc. | XS |
| 3.10 | R-27 | Add a "For library authors" paragraph to the README's features section: depend on anykms (or the backend crates) with `default-features = false` and let the application choose the TLS and RSA backends. | XS |
| 3.11 | R-36 | One "When to use this crate" paragraph in every published `lib.rs`; the conformance caveat in its rustdoc; the full facade features table in the facade's rustdoc. | XS–S |
| 3.12 | R-37 | Fix the stale statements: `operations-azure.md:239` (`az` output), `:202` (versionless support, accepted per `research/azure-kv.md:21`), the `anykms-aws/Cargo.toml:43-47` MSRV comment, `PLAN.md:18-20` (cloud backends ship in 0.1.0), and `operations-gcp.md:44` (`publicKeyViewer` is still unverified). | XS |
| 3.13 | R-21 | Replace `gcp-kms://projects/p/…` with `projects/my-project` (README.md:226, `anykms-gcp/README.md:17`). Add a test target that holds the README snippets verbatim and compiles them, plus a compile-only check for the ```` ```ignore ```` bridge snippets, and run it in CI. | S |
| 3.14 | R-38 | Add a glossary (KEK, key wrap, data key, DEK, handle, provider, registry, part, layer) and use one term per concept across the READMEs, rustdoc and operations docs. | S |
| 3.15 | R-48 | Add a per-backend JWKS rotation section (alias repoint on AWS, new version on transit and GCP, overlap period) and a "cache the JWKS" sentence. | XS |
| 3.16 | R-51 | Add "Errors" sections for implementers on `Provider` and the capability traits. Fix the `verify_mac` contract (`traits.rs:353-356`) to match conformance (`InvalidArgument` for a tag of another algorithm). Add a `minimal_backend` example of about 250 LOC that passes `anykms-conformance`. | S–M |
| 3.17 | R-55 | In `envelope-format.md` "Future versions", require v2 readers to cap the number of wrapped-key slots, and require a reader-first rollout. | XS |
| 3.18 | — | Record the superseded decisions (see the Decisions table) in PLAN.md and `docs/review-plan.md`, and add every change to the CHANGELOG's `Unreleased` section. | S |

## Phase 4: release process

| # | Item | Change | Effort |
|---|---|---|---|
| 4.1 | R-16 | Add `sdk-credentials` to anykms-aws's `[package.metadata.docs.rs]` features. Add `#![cfg_attr(docsrs, feature(doc_cfg))]` to every published `lib.rs`. Add a release step, and ideally a CI check, that builds each crate's docs with its docs.rs metadata on nightly with `--cfg docsrs`. | XS–S |
| 4.2 | R-15 | Replace the one-command publish in `releasing.md` with dependency-order batches: 5 crates (the crates.io new-crate burst), then one every 10 minutes, facade last. Document how to resume with `-p`/`--exclude` after an interruption. | XS |
| 4.3 | R-40 | Fix the release gates. Either drop the LocalStack job from `releasing.md:49-52` or make it fail without a token. Set `ANYKMS_FAIL_ON_SKIP` on the Floci job and declare its IAM cases n/a. Correct `credentials-plan.md:199-201`, which records LocalStack as passed. | S |
| 4.4 | R-14 | Add a releasing.md step: enable GitHub private vulnerability reporting when the repository goes public. The account-level `SECURITY.md` covers the rest. | XS |

## Release checklist additions

- Before starting Phase 1, re-run the Verifier's reproductions for any finding whose code moved.
- After Phase 4, follow `docs/releasing.md` as amended. The tag is not gated on a dispatched live
  cloud run (R-41, declined).

## After 0.1.0 (0.1.x)

Additive follow-ups the maintainer kept out of 0.1.0:

| Item | Change |
|---|---|
| R-20 | Optional `attempt_timeout` on `RetryPolicy`, without racing `instant_sleep()` in tests |
| R-31 | A budget per `LayerCx::backend()`, an `anykms retry suppressed` event, and an attempts or stop-reason accessor on `Error` |
| R-6 | `resource` on the retry event |
| R-12 | `JwtSigner::with_kid_fn` |
| R-48 | `jose::jwks_union` / `JwtSigner::also_publish`, and optionally `cached_jwks(ttl)` |
| R-54 | A "Key URIs from other tools" table (sigstore, Go CDK, Tink-hcvault, SOPS) and a hint in the path-less `hashivault` error |
| R-40 | A failure notifier for scheduled CI runs; fix or remove Scorecard (needs the public repo) |
| R-2 | An opt-in that refuses public-key KEKs (`require_private_wrap()` or a wrap-authority field) |
| R-16 | Facade `doc_cfg` badge naming; `#[doc(no_inline)] pub use rustls` |
| R-18 | A `fips` feature and a strict no-fallback opt-in |

## Later

| Item | Note |
|---|---|
| R-45 | Seeded or persisted local keys for development databases |
| R-5 | A cross-backend credential vocabulary (only the Azure trait rename is in 0.1.0) |

## Not doing

| Item | Reason |
|---|---|
| R-14 (beyond 4.4) | The account-level `SECURITY.md` is enough; no repo-local file, yank section or supported-versions statement |
| R-26 | No MSRV-bump or defaults-change policy text for now |
| R-27 (defaults) | Facade defaults stay; only the library-author note (3.10) |
| R-41 | No live cloud run gating the tag |
| R-4, R-9, R-10, R-13, R-28, R-42 | Rejected by the review panel; see `release-review.md` §5 |
