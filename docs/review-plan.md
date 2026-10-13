# Review remediation plan

Source: a multi-agent review (architecture, security and crypto, KMS domain, Rust engineering,
and integration UX), followed by a second agent pass that re-checked every recommendation against
the code, PLAN.md's stated reasons, and vendor docs. This plan keeps only the items that survived
that second pass. Items PLAN.md already schedules are marked **(PLAN)**.

Effort: XS < 1h, S ≈ half a day, M ≈ 1–3 days.

Baseline at review time: all checks clean. Build, clippy, tests, docs and ten feature combinations
pass; MSRV 1.85 holds; conformance passes on OpenBao (325) and Vault (303). There are no Critical
or High security findings. A test integration rated the library 3/10 to integrate (easy).

## Implementation status (branch `review-remediation`)

All Phase 0–3 items are done, and so are the Phase 4 items that apply to code that exists today.
Verified on the merged tree: fmt, clippy `-D warnings` (all features), docs `-D warnings`,
`--no-default-features` on all six crates, and the full test suite, including conformance on
Vault (307 passed, 22 n/a) and OpenBao (329 passed).

Decisions taken on the open questions:

- **1.1:** `Unauthenticated` is a config error and maps to HTTP 500.
- **1.7:** full layer replay, not just the doc rule.
- **2.5:** `preflight` is on opaque handles only.
- **0.2:** the external envelope review is recorded as a release gate.

Done differently from the plan, or deliberately skipped:

| Item | Outcome |
|---|---|
| 0.3 | Decided as unpadded base64url under `anykms-aad`. **Superseded** by [release plan](release-plan.md) 1.1 (D1): the AAD is Tink's encryption context `{"associatedData": lowercase_hex(aad)}`, still omitted for empty AAD, and the cap binds only the operations that produce a ciphertext (R-50). |
| 1.1 | Vault adds `invalid token` to its 403, so transit reports `Unauthenticated` there. OpenBao's plain 403 stays `PermissionDenied`. The conformance case accepts either, as long as it is a config error. |
| 1.7 | `layer` takes `&L where L: Layer + Clone + 'static` (or an `Arc`) instead of `&dyn Layer`. |
| 1.8 | Already present in CI. That job will flag the deliberate Phase 1 breaks on the PR. |
| 2.8 | Docs only; no `REWRAP_WITH_AAD` capability bit. |
| 3.8 | `# Panics` sections already existed; `try_new` not added. |
| 3.10 | TTL jitter plus a precomputed cache key; single-flight not added. **Superseded** by [release plan](release-plan.md) 2.1 (R-34): concurrent misses of the transit key-type cache (and of the AWS, GCP and Azure metadata caches) now share one read through `anykms_http::cache::SingleFlight`. |
| 4.1 | Kubernetes and JWT login with renewal (`ServerConfig::login`, `ANYKMS_AUTH*`). Transit now depends on tokio (sync feature only). |
| 4.2 | `CachingKeyWrap`, a decorator over `KeyWrap`. |
| 4.3 | `ObserveLayer` / `OpEvent` in `core::observe`. |
| 4.4 | Blocking helpers skipped (they would need their own runtime); a `spawn_blocking` example is documented instead. Streaming waits for envelope v2. |
| 4.9 | Only the AES-128 KEK warning. Batch and derived keys remain non-goals. |
| 4.11 | `KeyUri` normalization skipped: an empty authority means the provider's default server, which need not be named `default`. `without_query` is now public. `OpenOptions` in `describe` is documented as having no effect. |
| 4.5–4.8, 4.10 | Need backends that don't exist yet; recorded as design notes in PLAN Appendix A, M5 and §21. |

---

## Phase 0: decisions and spec text (docs only, before 0.1)

These fix wire formats or trait contracts. Changing them after release is expensive.

| # | Item | Change | Effort |
|---|---|---|---|
| 0.1 | Envelope v1 has a single wrapped-key slot | In `envelope-format.md` "Future versions", commit that v2 may carry N wrapped-key slots *and* streaming frames together, and reserve the flag bits for that. | XS |
| 0.2 | Envelope format has had no external review | Finish the pending external review (`envelope-format.md:3-6`) before promoting 0.1 for long-lived data. An ESDK-compatible *reader* is a later option. Adopting the ESDK format wholesale was rejected. | external |
| 0.3 | AWS encryption-context encoding of AAD | Decide and document in PLAN Appendix A how arbitrary AAD bytes map to the reserved context value (base64url, plus a size check). Every AWS ciphertext will depend on it. Do not cite an EC size limit until verified. | XS |
| 0.4 | Message size limits on `Mac` / `MessageSigner` | Document in `anykms-core/src/traits.rs` that backends cap raw input: AWS `GenerateMac`/`Sign` RAW 4096 B (verified); GCP limit unverified. Portable code must not assume transit's limits. | XS |
| 0.5 | PQC input shape | One line in PLAN §12: ML-DSA external μ will be a separate `MuSigner` trait, not a third mode on existing traits. | XS |
| 0.6 | Semver-coupled public deps | Add a "Public dependencies" section to the README and crate docs: `rustls 0.23` (re-exported by transit), `zeroize 1`. Note that adding a handle part breaks `full` callers while on 0.x. | XS |
| 0.7 | Appendix A corrections | Azure: standard vaults have no `Aead` (data keys need a KeyWrap-based emulation, see 4.6); Premium oct-HSM AES and HMAC are *preview*. AWS: asymmetric `KeyVersion` = resolved key ARN; encryption context is not allowed on asymmetric/HMAC keys; `ED25519_PH_SHA_512`+`DIGEST` double-hashes. Fix PLAN drift: §3.6 is missing `KeyVersionUnusable` and has the wrong `is_config_error` list; §3.4 says `allow_ephemeral_local_keys` lives on the registry (it is on `LocalProvider`); the §3.3 example needs `?` on `build()`; §2 omits `base64`. | S |

## Phase 1: API shape before 0.1 (breaking or semver-sensitive)

Order matters; dependencies are listed.

| # | Item | Fix | Files | Effort | Deps |
|---|---|---|---|---|---|
| 1.1 | No `Unauthenticated` error kind | Add `ErrorKind::Unauthenticated`: a config error, not retryable, with a "refresh credentials" hint. Update the class table in `error.rs`, the HTTP mapping in `operations.md`, and transit's mapping. Vault/OpenBao return **403** for bad tokens, so transit sets it only on 401, or on 403 after a failed token reload. Add a revoked-token conformance case. | `core/src/error.rs`, `transit/src/errors.rs`, `docs/operations.md`, conformance | S | — |
| 1.2 | TLS features override the app's process-wide rustls provider | Precedence: `cfg.crypto_provider` → `CryptoProvider::get_default()` → aws-lc → ring → error. Emit a `tracing::debug!` naming the chosen provider. Update the transit lib.rs table, README features, Cargo comments and `PLAN.md:1406`. Test in its own test binary, because the default is process-global. | `transit/src/client.rs:62-82`, `lib.rs`, `tests/tls.rs`, README | S | — |
| 1.3 | `EnvelopeKeyring` accepts AEAD keys (and `Arc<EnvelopeAead>`) as KEKs implicitly | Remove the `IntoKek` impls for `Arc<T: Aead>`, `Arc<dyn DynAead>` and `AeadKey`. Keep the ones for `KeyWrapKey` and `AeadKeyWrap<T>`. Add `IntoKek` for `Arc<T: KeyWrap>`, plus an `on_unimplemented` hint pointing to `.into_key_wrap()`. Update the doc example at `envelope.rs:604-613` and `PLAN.md:1179`. | `recipes/src/envelope.rs` | S | — |
| 1.4 | Blanket `impl<S: DigestSigner> PinnedVerifier for S` blocks `Retry<CachedVerifier>` and `Arc<LocalVerifier>` | Move `PinnedVerifier` into core next to `DigestVerifier`. Implement it explicitly for `Arc`/`Box`/`&T`/`Retry<T>` (forwarding), for `DigestSignerKey`/`DigestVerifierKey`, for the transit and local typed signers, and for `LocalVerifier`/`CachedVerifier`. Recipes re-exports it. | `core/src/{traits,retry,dynamic}.rs`, `recipes/src/{hashed,verify,cached}.rs`, transit/local `handles.rs` | M | — |
| 1.5 | `verify_jws(&v, alg, jws)` repeats the pinned algorithm | `verify_jws(&v, jws)` bounded on `PinnedVerifier`; keep `verify_jws_as(&v, alg, jws)`; same for `verify_jws_for_key`. Follows the existing `verify_message_hashed`/`_as` convention. | `recipes/src/jose.rs:855-869`, README | S | 1.4 |
| 1.6 | Hand-written forwarders silently drop new `Provider` methods; backend plumbing is duplicated | Add a `provider_methods!` callback macro that generates the trait defaults, `impl Provider for Arc<P>` and a public `forward_provider!` for decorators (the facade's `Unconfigured` uses it). Move the duplicated `check_signing_alg` into core as `SignatureAlgorithm::require_shape(Shape, backend)`. Fallback (S): a test that calls every method through `Arc` and `Unconfigured`. | `core/src/provider.rs`, `anykms/src/lib.rs`, transit/local `provider.rs` | M | — |
| 1.7 | A part added after `layer()` misses every layer; a per-handle retry is silently skipped | Now: add a doc rule plus a `debug_assert!` that parts must be added before layering. Then: record applied layers (`Vec<Arc<dyn Layer>>`) and have `with_*` apply them to new parts; add `replace_retry(&RetryLayer)`; `tracing::debug!` when a retry layer is skipped. Do **not** just reset `retried`, which would double-retry the main part. | `core/src/{dynamic,provider,retry}.rs` | S → M | — |
| 1.8 | No API-stability guard | **Already present** (missed by the review): CI job `semver` runs `cargo-semver-checks` against the PR base until publication, then crates.io. No change needed. | CI | — | — |

## Phase 2: additive integration UX (can ship in 0.1.x)

| # | Item | Fix | Effort | Deps |
|---|---|---|---|---|
| 2.1 | Users hand-write the error → HTTP mapping (~35 LOC) and can get the order wrong | `Error::class() -> ErrorClass { Hinted(Duration), Retryable(Option<Duration>), Config, Caller }`, encoding the `operations.md` table order (hint first). Status codes go in the facade docs, not core. The forged-`kid` → 503 mapping stays (deliberate, `operations.md:408`). | S | 1.1 |
| 2.2 | `JwtSigner`, `CachedVerifier` and `LocalVerifier` aren't `Clone` | `LocalVerifier`: derive `Clone` or wrap its state in an `Arc`. `CachedVerifier`: move state behind an `Arc<Shared>` so clones **share** the cache (document this). `JwtSigner<S: Clone>`: put `KidCache` behind an `Arc`. | M | — |
| 2.3 | No serde support | Optional `serde` feature on core, forwarded by the facade: `Ciphertext`/`Signature`/`Tag` use the canonical base64 when human-readable, raw bytes otherwise. `to_base64` stays fallible (deliberate). | S–M | — |
| 2.4 | Default retry policy is too slow for request handlers | `RetryPolicy::interactive()`: 50 ms base, 500 ms cap, 3 attempts, 2 s deadline. Document that the deadline must exceed `CachedVerifier`'s `latest_refresh` plus backoff. Show it in the `operations.md` HTTP section. | S | — |
| 2.5 | Lazy open hides key-type mismatches until first use | A portable `preflight().await -> Result<KeyInfo>` on opaque handles (Describe plus a check that the main part's capability is present; `Unsupported` without Describe). Transit's `verify_with_describe` becomes its implementation. Document it in the README's config-driven section. `KeyMismatch` stays as is: it is already a config error. | M | — |
| 2.6 | Local-backend errors lack the key URI | Label local handle errors with the resource. Add a conformance assertion that every operation error has `resource().is_some()`, so future backends inherit the contract. | S | — |
| 2.7 | ECDSA `verify_message` on `LocalVerifier`/`CachedVerifier` fails only at run time | Keep the refusal (PLAN §3.2 signer split). Change the error to name `verify_message_hashed`. | XS | — |
| 2.8 | Transit `supports_rewrap()` is true, but rewrap with AAD is `Unsupported` | Document it on `supports_rewrap` and `Rewrap::rewrap`. Optional: a `Capabilities::REWRAP_WITH_AAD` bit in `describe()`. | XS / S | — |
| 2.9 | Doc papercuts | tokio `test-util` needed for `start_paused`; JWT snippet should use `ok_or_else(\|\| anyhow!(..))`; "generic over encrypt" example with `Arc<dyn DynAead>` and `A: Aead + ?Sized`; note that `LocalKeyset::aead_key` skips the ephemeral opt-in. | S | — |

## Phase 3: hardening and small correctness fixes

All Low or Info, each S unless noted, each with a regression test where one is practical.

| # | Item | Fix | Test |
|---|---|---|---|
| 3.1 | A duplicate `warnings` key bypasses the fail-closed check (`transit/src/client.rs:513`) | If the `WarningsOnly` parse fails on a non-empty success body, fail closed with `Unsupported`. Don't fix it by parsing to `Value` (last duplicate wins). | wiremock body with duplicate keys → `Unsupported` |
| 3.2 | `CachedVerifier` caches any version the source returns (`recipes/src/cached.rs:709-719`) | Require `pk.version() == Some(v)` (canonical compare), else `Backend` and don't cache. Mirrors `jose.rs:191`. | Fake source returns v2 for v1 → error, and the next call refetches |
| 3.3 | HKDF/HMAC state derived from the DEK is not zeroized | Enable `sha2/zeroize` and `hmac/zeroize` in the workspace `Cargo.toml` (`Hkdf` wraps `Hmac`, so drop glue wipes it). Verify the trait bound compiles first. | Compile-time assertion of `ZeroizeOnDrop` |
| 3.4 | RNG failure panics | Return `ErrorKind::Backend` at `recipes/src/envelope.rs:264` and `datakeys.rs:29`. Keep the panic in `local/src/keyset.rs:111` (test-only backend). | — (RNG isn't injectable) |
| 3.5 | RSA bit size is rounded to whole bytes (`recipes/src/verify.rs:80`) | Use `parts.bits()`. | 3071-bit SPKI → `Rsa{bits:3071}` and accepted; 2047-bit SPKI rejected |
| 3.6 | Rewrap errors are labelled `Operation::Encrypt` (`envelope.rs:227,235`) | Pass `op` into `serialize`. | Oversized wrapped key in rewrap → `op() == Rewrap` |
| 3.7 | Zero values accepted in transit config (`config.rs:323`) | Reject `max_response_bytes == 0` and zero timeouts in `validate()`. | One config error per zero value |
| 3.8 | Panicking `kek_id` constructors are undocumented | Add `# Panics` docs to `with_kek_id`, `EnvelopeKeyring::new`/`typed`; optional `try_new`. The panic itself is deliberate. | — |
| 3.9 | Retry jitter is likely identical across wasm clients | Mix clock nanoseconds, a per-layer counter and a per-layer address into the jitter hash, or add `RetryLayer::with_rng`. Don't add `getrandom` to core. | Two layers produce different delays |
| 3.10 | Transit key-type cache: synchronized expiry stampede (`transit/src/handles.rs:290-300`) | ±10% jitter on the 600 s TTL (S). Single-flight is optional (M). | Mock: N concurrent calls after expiry → 1 GET (if single-flight) |
| 3.11 | RSA key cloned per verify (`rsa_backend.rs:136`) | Precompute the `VerifyingKey` enum in `new`. Nice-to-have. | — |

## Phase 4: next milestone (M5) and roadmap

| # | Item | Notes |
|---|---|---|
| 4.1 | Transit login and token renewal (Kubernetes, JWT auth) **(PLAN M5)** | Put it first in M5, ahead of cloud backends. |
| 4.2 | Data-key caching **(PLAN M5)** | Start decrypt-side only: key `(kek_id, wrapped_dek)`, TTL, max entries. Leave out encrypt-side reuse for now. |
| 4.3 | Metrics layer **(PLAN M5)** plus layered extension APIs | Downcast and extension calls bypass layers today (`dynamic.rs:651-655`). The AWS native encryption-context path needs a layered extension, not a raw downcast. |
| 4.4 | Streaming envelope **(PLAN M5)** | Together with multi-slot v2 (0.1). Until then, consider `encrypt_blocking`/`spawn_blocking` helpers for large blobs. |
| 4.5 | AWS backend specifics | Use the resolved key ARN as `KeyVersion` (fixes JWKS `kid` collision on alias swap); a handle accepts only its own key's ARN as a version (second review: an attacker's `kid` must not select another key; see PLAN Appendix A). Map `IncorrectKeyException` → `DecryptFailed` with an "alias repointed? use `EnvelopeKeyring`" hint. Document the multi-region-key pattern (one replica ARN per region, shared logical `kek_id`); no MRK-aware matching is needed. Add a 4 KiB+1 conformance case for `Mac`/`MessageSigner`. |
| 4.6 | Azure standard vaults | `EmulatedDataKeys` over `KeyWrap` (refuse non-empty AAD). Host allowlist covering Managed HSM and sovereign clouds. Map `nbf`/`exp` to `KeyStateInvalid`. |
| 4.7 | GCP signing-key rotation | Opt-in "newest ENABLED version, re-resolved on an interval" mode. Backends relying on `LocalVerifier` must depend on an RSA feature explicitly. |
| 4.8 | Algorithms **(PLAN)** | secp256k1, HMAC-SHA224 (additive, `#[non_exhaustive]`). |
| 4.9 | Transit-only extensions **(PLAN non-goals)** | Batch, derived/convergent keys with an explicit `context`, AES-128 KEK warning on the key-wrap path. Later. |
| 4.10 | wasm `Send`-less trait variant | Only if a browser-fetch backend is pursued. |
| 4.11 | Smaller items | `KeyUri` normalization (`hashivault:///` vs `default`) and a public `without_query`; warn when both `VAULT_ADDR` and `BAO_ADDR` are set; honour `OpenOptions` in `describe`; `Error::backend()` naming consistency; transit `cache_key` precompute. |

## Dropped after the second pass

| Recommendation | Reason |
|---|---|
| Remove the facade glob `pub use anykms_core::*` | Local items shadow glob imports predictably; the real risk (`Unconfigured`) is covered by 1.6. |
| Wrap `rustls`/`zeroize` to hide them | Re-exporting rustls is the ecosystem norm; documented instead (0.6). |
| Forged `kid` → 503 is a bug | Deliberate: an above-latest `kid` is indistinguishable from rotation lag (`operations.md:408`). |
| Make `KeyMismatch` from registry handles `Unsupported` | Both are already config errors; callers handle them the same way. |
| Make `Signature`/`Tag::to_base64` infallible | Needs a bounded `KeyVersion` at construction: a breaking change for no practical gain. |
| `LocalVerifier::verify_message` should hash for ECDSA | Breaks the Ed25519-only message-signer split (PLAN §3.2); improve the error instead (2.7). |
| `Tag` `PartialEq` constant-time | Already documented as not constant-time (`types.rs:598`); `verify_mac` is the API. |
| `RetryLayer::new` panics on wasm (`std_clock`) | Documented in three places. |
| Throttle token-file re-stat | Microseconds on tmpfs, and it is what picks up rotated tokens immediately. |
| MRK-aware key matching for AWS | The envelope's `kek_id` is logical; per-region config already works (doc only, 4.5). |
| Adopt the AWS Encryption SDK format for envelope v2 | Large AWS-centric dependency; external review (0.2) plus an optional reader instead. |
| `kek_id` constructors should return `Result` | The panic is deliberate (config bug); documented instead (3.8). |

## Open questions

Resolved; see "Implementation status" above.
