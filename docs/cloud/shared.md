# Cloud backends: shared prerequisites

Status: **implemented** (2026-10-06); see PLAN §18 and §24. §5 and §6.2 carry the conventions
agreed after the cloud reviews (D1–D6 in `review-consistency.md` §0). Covers what AWS KMS, GCP Cloud KMS and Azure Key Vault /
Managed HSM need from the shared crates (`anykms-core`, `anykms-recipes`, `anykms-conformance`,
`anykms`, CI). Per-backend designs live in their own documents; this one owns everything they
share. Inputs: `docs/PLAN.md` §0–§3, §8, §10–§12, Appendix A, §19–§22; the code at `dd3cc82`.

Effort: S ≈ half a day, M ≈ 1–3 days, L ≈ 4+ days.

## 0. Summary of decisions

- **No breaking change to `anykms-core` is required.** Every core change below is additive
  (`#[non_exhaustive]` enums, provided trait methods, new optional handle parts, new types);
  `cargo-semver-checks` must stay green against 0.1.0. Release as **0.2.0** anyway (§7).
- **One new optional part:** `WrappedDataKeys` on `AeadKey` (AWS
  `GenerateDataKeyWithoutPlaintext`, transit `datakey/wrapped`, local).
- **One new always-present slot:** layered **extension calls** (`Part::Extension`), so
  backend-specific per-call APIs (AWS encryption-context maps) run through retry and observe
  layers instead of a raw `downcast_ref`.
- **Native `KeyWrap` needs no core change.** `Provider::key_wrap` → `KeyWrapKey` with a native
  `KeyWrap` main part already exists (§20). Only the conformance suite must learn it.
- **RSA-OAEP is SHA-256 only**, fixed per backend; no portable wrap-algorithm parameter. SHA-1
  OAEP keys are `KeyMismatch`.
- ~~**No shared cloud crate.**~~ *Superseded:* all three backends ended up as in-house REST
  clients and share `anykms-http` (README §2.1, Q4). The backend checklist of §5 still applies.
- **Schemes follow Tink:** `aws-kms://`, `gcp-kms://`; Azure `azure-kv://<host>/keys/...`.
- **Conformance redesign (§22) grows** from 1–1.5 days to about 4 days: §22's seven steps plus
  the transit-shaped assumptions found in the case bodies (§1.3), a shared/fresh key split for
  cloud cost, and the new cases the cloud parts need.
- **Deferred:** `AsymmetricDecrypt` trait, native `KeyWrap` part on `AeadKey`, `MuSigner`,
  secp256k1 / HMAC-SHA224 (additive, with whichever backend first needs them), envelope v2.

## 1. Conformance capability redesign (PLAN §22)

### 1.1 What is transit-shaped today (from the code)

- `cases/mod.rs::all`: `aead::*`, `rewrap::with_aad`, `datakeys::*`, `describe::*`,
  `errors::missing_key`, `errors::local_checks_name_the_key`, `hygiene::*`, every
  `recipes::envelope::*`, `recipes::emulated_data_keys`, `mac::*` have `requires: &[]`.
- `fixture.rs::TypedHandles`: `aead`, `digest_key`, `message_key`, `mac_key` are required;
  `key_wrap` defaults to `self.aead(uri).map(KeyWrapKey::from_aead)`.
- `fixture.rs::bridge_aead` requires `Aead + Rewrap + DataKeys + Describe` (`AeadKey::full`).
- `ctx.rs::Ctx::describe` (typed path) goes through `typed.aead(uri)`; `describe_key` falls back
  to it for `TestKeyKind::Aead`.
- `FixtureCaps::support` returns `FixtureLacks("... not declared")` for undeclared features, so
  an undeclared feature is a `skip` (a failure only under `ANYKMS_FAIL_ON_SKIP=1`).
- `TestKeyKind` has `Aead`, `Hmac`, `Signing(alg)`; no `KeyWrap`.
- Not in §22, found in the case bodies:
  - `sign::input_validation` and `mac::failures` require a non-numeric version (`"abc"`,
    `"x1"`) and an unversioned signature/tag to be `InvalidArgument`. AWS versions are ARNs,
    Azure 32-hex; an unversioned signature is meaningful on AWS (one key, no versions).
  - `aead::describe`, `mac::describe`, `aead::ciphertext_version`, `sign::public_key` require
    `KeyInfo::primary_version()`. AWS symmetric keys and GCP signing/MAC keys have none
    (Appendix A).
  - `Feature::Rotate` gates AEAD, MAC and signing rotation together; AWS rotates symmetric keys
    only (asymmetric and HMAC keys cannot rotate).
  - Every case calls `c.key(kind)`, i.e. `Fixture::create_key` per case: hundreds of cloud keys
    per run. GCP keys can never be deleted; AWS keys cost until deleted (7-day minimum wait).
  - `envelope_roundtrip`, `envelope_format`, `envelope_rewrap_to_and_keyring` compare against
    `c.aead(..)`, so they cannot run on a KeyWrap-only fixture.

### 1.2 Changes per file

**`fixture.rs`**

- `Feature` (`#[non_exhaustive]`, additive): `Aead`, `Rewrap`, `DataKeys`, `WrappedDataKeys`,
  `Mac`, `Describe`, `KeyWrap` (native key-wrap keys, `TestKeyKind::KeyWrap`), `KeyWrapRewrap`
  (a native KEK rewraps server-side), `RotateMac`, `RotateSigning`, `MaxMessageLen`,
  `UsedPrimary`, `Extension`. `Rotate` keeps its name and now
  means AEAD/KeyWrap keys only; local and transit declare all three rotate features. (As
  implemented, §1.6: `Rotate` is AEAD-only and `RotateKeyWrap` covers key-wrapping keys.)
- `Support::Undeclared` (new variant). `FixtureCaps::support` returns it instead of
  `FixtureLacks` for a missing entry.
- `FixtureCaps::supports_all(&[Feature])`. `RewrapWithAad` and `datakey_aad` are read only when
  `Rewrap` / `DataKeys` are `Yes` (document on the fields; cases already gate).
- New declarations (builder style, like `with_hmac_versions_listed`):
  - `with_versions(VersionShape)`: `Numeric` (transit, local, GCP) or `Opaque` (AWS ARN, Azure
    hex). Replaces the hard-coded "non-numeric → `InvalidArgument`" expectation.
  - `with_unversioned_verify(Unversioned)`: `Rejected` (default; transit, local) or
    `UsesCurrent` (AWS).
  - `without_primary_version(TestKeyKind)`: per kind, for AWS symmetric and GCP signing/MAC.
  - `with_max_message_len(usize)` (declares `MaxMessageLen`; AWS 4096).
  - `with_used_primary(bool)` (declares `UsedPrimary`; GCP).
- `TestKeyKind::KeyWrap` (enum is `#[non_exhaustive]`): a native key-wrapping key (AWS RSA
  `ENCRYPT_DECRYPT`, GCP `ASYMMETRIC_DECRYPT` OAEP-SHA256, Azure RSA / oct-HSM).
- `KeyUse { Shared, Fresh }` and `Fixture::create_key(kind, KeyUse)`: breaking for the
  unpublished crate only. `Shared` may return a pooled key (pre-provisioned by IaC, §6.5);
  `Fresh` must be new. Cases that rotate, disable, set a minimum version or need two distinct
  keys use `Fresh` (or `Ctx::keys(kind, 2)` which may return two distinct pooled keys).
  Alternative considered: a separate `Fixture::shared_key`; rejected, one entry point keeps
  fixtures simple.
- `TypedHandles`: `aead`, `digest_key`, `message_key`, `mac_key` get defaults returning
  `Unsupported` ("not declared"); gating guarantees they are only called when supported.
  `key_wrap` keeps its `from_aead` default.
- Replace `bridge_aead` with `AeadBridge`, bounded per part (no `full`, so new parts never
  force stubs):

  ```rust
  pub struct AeadBridge<K> { key: Arc<K>, handle: AeadKey }
  impl<K: Aead + Send + Sync + 'static> AeadBridge<K> {
      pub fn new(key: K) -> Self;                 // AeadKey::new("typed", k).with_concrete(k)
      pub fn rewrap(self) -> Self where K: Rewrap;
      pub fn data_keys(self) -> Self where K: DataKeys;
      pub fn wrapped_data_keys(self) -> Self where K: WrappedDataKeys;
      pub fn describe(self) -> Self where K: Describe;
      pub fn build(self) -> AeadKey;
  }
  pub struct KeyWrapBridge<K>;                    // same shape: new(k).rewrap().describe().build()
  ```

- `DigestKeyHandles` / `MessageKeyHandles` / `MacKeyHandles`: `describe` becomes
  `Option<Arc<dyn DynDescribe>>`, the structs `#[non_exhaustive]`, with `bridge` (all parts, as
  today) and `bridge_without_describe`. No cloud key lacks describe today; this only stops the
  struct from forcing it.

**`lib.rs` (`run_or_skip`)**

- Gate: `Support::Undeclared` → the trial **fails** with "declare Feature::X in probe()",
  regardless of `ANYKMS_FAIL_ON_SKIP`. `NotApplicable` → ignored `n/a`; `FixtureLacks` → `skip`
  as today.
- One extra trial `conformance::declarations` (typed path only): fails listing every feature any
  case requires that the fixture left undeclared. Runs even when every case is filtered out.
- `Case` gains nothing else: OR-gating is avoided by splitting cases (below).

**`ctx.rs`**

- `Ctx::key(kind)` → `KeyUse::Shared`; `Ctx::fresh_key(kind)`; `Ctx::keys(kind, n)` (distinct).
- `Ctx::describe(uri)` is removed; `Ctx::describe_key(&TestKey)` dispatches on `key.kind` for
  every kind (`Aead` → `typed.aead`, `KeyWrap` → `typed.key_wrap`, ...), and
  `Ctx::describe_for(kind, uri)` serves the missing-key cases. Neither touches `typed.aead`
  for non-AEAD kinds.
- `Ctx::kek(kind)` opens a KEK: `KeyWrap` → `key_wrap(uri)`; `Aead` → `key_wrap(uri)` too
  (`from_aead` on both paths).

**`cases/*` (gating and splits; names are the trial names)**

| Case(s) | Requires |
|---|---|
| `aead::*` (all), `describe::preflight`† | `Aead` (+ existing features) |
| `aead::ciphertext_version`, `aead::disabled_key` | `Aead, Describe` |
| `aead::decrypt_with_info` (new) | `Aead`; `used_primary` checked with `UsedPrimary` (+`Rotate` half split into `aead::used_primary_after_rotation`) |
| `rewrap::*` | `Aead, Rewrap` |
| `datakeys::*` | `Aead, DataKeys` |
| `datakeys::wrapped_only`, `datakeys::wrapped_only_aad` (new) | `Aead, WrappedDataKeys` |
| `describe::aead_key` | `Aead, Describe` |
| `describe::key_wrap_key` (new) | `KeyWrap, Describe` |
| `describe::hmac_key` | `Mac, Describe` |
| `describe::preflight_disabled`, `describe::preflight_disabled_version` (release review) | `PreflightState` plus the key family |
| `describe::generic_preflight_disabled_primary` (release plan 2.8, R-49) | `DisableVersion, Describe, DescribeVersionState`; floating key kinds with a reported primary version |
| `keywrap::disabled_key` (release review) | `KeyWrap, PreflightState` |
| `mac::*` | `Mac`; `mac::<alg>::rotation` → `Mac, RotateMac` |
| `mac::<alg>::input_limit` (new) | `Mac, MaxMessageLen` |
| `mac::wrong_key_type` | split: `mac::aead_key_as_mac` (`Mac, Aead`), `mac::hmac_key_as_aead` (`Mac, Aead`); a signing-key variant `mac::signing_key_as_mac` (`Mac, Signing(EcdsaP256Sha256)`) covers GCP-like fixtures without AEAD |
| `sign::<alg>::rotation`, `recipes::cached_verifier::<alg>` | `Signing(alg), RotateSigning` |
| `sign::ed25519::input_limit` (new) | `Signing(Ed25519), MaxMessageLen` |
| `errors::missing_key` | split per family: `errors::missing_key::{aead,key_wrap,mac,signing}` |
| `errors::local_checks_name_the_key` | split: `::mac` (`Mac`), `::signing` (`Signing(EcdsaP256Sha256)`) |
| `errors::unauthorized` | split: `::aead`, `::key_wrap`, `::signing`, each `+ UnauthorizedProvider` |
| `hygiene::errors_do_not_leak_inputs` | split: `::aead` (`Aead`), `::data_keys` (`Aead, DataKeys`), `::key_wrap` (`KeyWrap`), `::mac` (`Mac`) |
| `recipes::envelope::{roundtrip,format,rewrap,rewrap_to_and_keyring}` | `Aead` (KEK from an AEAD key; the comparisons with the AEAD handle stay) |
| `recipes::envelope_native::{roundtrip,format,rewrap_local,rewrap_to_and_keyring}` (new) | `KeyWrap` (format check unwraps via `unwrap_key`, not `decrypt`); `::rewrap` additionally `Rewrap`-on-KEK declared via `KeyWrapRewrap`‡ |
| `recipes::envelope::rewrap_current`, `recipes::envelope_native::rewrap_current` (release plan 2.6, R-44) | `Aead, Rotate`; native `KeyWrap, RotateKeyWrap` (server-side rewrap where the KEK has it, otherwise local, so no `Rewrap`) |
| `recipes::emulated_data_keys` | `Aead` |
| `recipes::keywrap_data_keys` (new, §4) | `KeyWrap` |
| `layers::extension_calls_are_layered` (new) | `Extension` |
| `capabilities::handles_match_declaration` (new, §22 step 6) | none |

† `describe::preflight` additionally requires `Signing(EcdsaP256Sha256)` (it opens the AEAD key
as that signer). ‡ `Feature::KeyWrapRewrap`: whether a native KEK rewraps server-side (AWS
`ReEncrypt` on RSA keys is not assumed; the AWS plan decides).

Version-shape fixes (no new cases): `sign::<alg>::input_validation` and `mac::<alg>::failures`
use `KeyVersion::new("abc")` only for `VersionShape::Numeric`; for `Opaque` they use another
key's version and accept `NotFound | InvalidArgument`, and with `RequestCount` assert zero
requests. The unversioned check follows `Unversioned`. `aead::describe`, `mac::describe`,
`sign::public_key`, `aead::ciphertext_version` compare with `primary_version()` only where the
kind reports one, else require the version to appear in `versions()`.

Consistency case `capabilities::handles_match_declaration`: for every declared family, open the
handle on both paths and check `AeadKey::supports_{rewrap,data_keys,wrapped_data_keys,describe}`
and `KeyWrapKey::supports_{rewrap,describe}` equal the declaration; every undeclared or `n/a`
part returns `Unsupported` (and, with `RequestCount`, sends zero requests); `describe()`
capability bits agree (`Capabilities::REWRAP` iff `Rewrap`, ...).

### 1.3 Migration of existing fixtures (§22 step 7)

- `crates/anykms-local/tests/conformance.rs`: `supports_all(&[Aead, Rewrap, DataKeys,
  WrappedDataKeys, Mac, Describe, RotateMac, RotateSigning])`, `KeyWrap` and `Extension`
  `not_applicable`, `MaxMessageLen` / `UsedPrimary` `not_applicable`; `AeadBridge::new(k)
  .rewrap().data_keys().wrapped_data_keys().describe().build()`; `create_key` ignores `KeyUse`.
- `crates/anykms-transit/tests/common/*`: same declaration (`WrappedDataKeys` after task K2);
  `create_key(KeyWrap, _)` → `Unsupported`; `RotateMac`/`RotateSigning` yes.
- Exit: case counts per backend do not drop (n/a counts may grow only by the new cases); Vault
  and OpenBao matrices green with `ANYKMS_FAIL_ON_SKIP=1`.

### 1.4 Shape proof fixtures over the local backend (§22)

In `crates/anykms-local/tests/` (local already dev-depends on the suite; no new dependency
edge): `conformance_gcp_shaped.rs`, `conformance_azure_shaped.rs`, sharing
`tests/shaped/mod.rs`. A `ShapedProvider { inner: LocalProvider, shape: Shape }` implements
`Provider` by opening from `inner` and rebuilding handles with only the shape's parts
(`AeadKey::new(..).with_describe(..)`), and a `MaskedDescribe` wrapper that clears the
capability bits the shape lacks and drops `primary_version` where the shape has none.

| | GCP-shaped | Azure-standard-shaped |
|---|---|---|
| `Aead` | yes, `ciphertext_version` → `None` (wrapper), `decrypt_with_info` reports `used_primary` | no |
| `Rewrap` / `DataKeys` / `WrappedDataKeys` | no | no |
| `KeyWrap` (native) | no (AEAD via `from_aead` only) | yes: a local AES key exposed **only** through `key_wrap` with a native-style `KeyWrap` wrapper (`version ‖ ct` framing) |
| `Mac` | yes, no primary version | no |
| Signing | ECDSA/Ed25519, no primary version | ECDSA only, no primary version |
| Versions | `Numeric` | `Opaque` (32-hex mapping layer) |

Exit: both run green with `ANYKMS_FAIL_ON_SKIP=1` in the `check` CI job, with no `Unsupported`
stubs in either provider. This is the proof that GCP and Azure can pass without lying.

### 1.5 Publishing (§22 step 7, tail)

- `crates/anykms-conformance/Cargo.toml`: drop `publish = false`; root `Cargo.toml`
  `anykms-conformance = { path = ..., version = "0.2.0" }`.
- `crates/anykms-transit/Cargo.toml`: remove the `exclude` entries for `tests/common`,
  `conformance_*.rs`, `integration.rs` (they build from the package again; they still need
  servers and skip/fail per `ANYKMS_REQUIRE_FIXTURE`).
- `.github/workflows/ci.yaml` `semver` matrix: add `anykms-conformance` (skipped until it exists
  in the baseline). `docs/releasing.md`: publish order core → recipes → **conformance** → local →
  transit → cloud backends → anykms; drop the "not published" paragraph. `CHANGELOG.md`.
- Publish only after the GCP- and Azure-shaped fixtures pass, so the published fixture API has
  been exercised by three shapes.

### 1.6 As implemented (C1–C9)

Differences from the plan above, and the C8 additions (README §2.3):

- `MaxMessageLen` is split per family: `Feature::MacInputLimit` (`with_max_mac_input`) and
  `Feature::MessageInputLimit` (`with_max_signed_message`), since GCP's limits differ by key type.
  `with_max_plaintext` clamps `aead::roundtrip`; `EmptyPlaintext`/`EmptyMessage` gate the
  `aead::roundtrip_empty`, `mac::empty_input` and `sign::ed25519::empty_message` cases.
- `Fixture::rotate` returns the key to use for the new version (`TestKey::with_version` for
  version-pinned URIs); `Fixture::disable_version` (`DisableVersion`) with
  `{aead,mac,sign::<alg>}::disabled_version` and `aead::disabled_primary_version`;
  `Fixture::malformed_version()` and `with_foreign_version_error` (default `NotFound` or
  `InvalidArgument`); `with_key_state_per_version`; `with_used_primary`.
- Bounded waits: `FixtureCaps::with_settle_time`; cases retry expectations after a state change
  for up to that long (`Ctx::settled`).
- `Feature::ServerErrorMessages` (`with_emulated_errors`) gates the key- and version-state cases
  whose error kinds a backend derives from server messages.
- `Case::consults`: behavior declarations a case reads (`RewrapWithAad`, `UsedPrimary`, ...) must
  be declared too. A required feature declared not applicable or lacking ignores the case even
  when another one is undeclared, so a fixture without AEAD keys need not declare AEAD-only
  behaviors.
- `DataKeys` also covers `Provider::data_keys` (`DataKeysKey`, `TypedHandles::data_keys`), over
  AEAD keys or, without `Aead`, key-wrapping keys (`datakeys::source::*`);
  `recipes::keywrap_data_keys::{aead,key_wrap}` cover the `KeyWrapDataKeys` recipe.
- `layers::extension_calls_are_layered` uses `Fixture::extension_call(&AeadKey)`.
- Proof fixtures live in `crates/anykms-local/tests/shaped/` (`conformance_gcp_shaped`,
  `conformance_azure_shaped`); the Azure shape also serves data keys through `KeyWrapDataKeys`.
- HMAC test keys are asked for per algorithm: `TestKeyKind::Hmac(MacAlgorithm)`, like
  `Signing(alg)`. AWS, GCP and Azure Managed HSM bind the algorithm to the key (Appendix A), so
  their fixtures create one key per algorithm (AWS pools `ANYKMS_AWS_KEY_HMAC`, `_HMAC_384`,
  `_HMAC_512`); local and transit keys serve every algorithm and ignore it. Cases that need any
  MAC key ask for `Hmac(HmacSha256)`. `without_primary_version(Hmac(_))` ignores the algorithm,
  as for `Signing`. The GCP-shaped proof fixture binds each HMAC key to its algorithm (another
  algorithm is `KeyMismatch`), so a case asking for the wrong key fails there.
- Rotation is declared per family: `Rotate` covers AEAD keys only, `Feature::RotateKeyWrap`
  native key-wrapping keys (`recipes::envelope_native::{rewrap,rewrap_local,rewrap_current}`), next to
  `RotateMac` and `RotateSigning`. AWS RSA keys never rotate (n/a); GCP and Azure key-wrapping
  keys rotate; local and transit have no native key-wrapping keys (n/a); the Azure-shaped proof
  fixture declares it n/a (conservative; the Azure backend's fixture declares it). The new
  `recipes::envelope_native::rewrap_unrotated` (`KeyWrap, KeyWrapRewrap`) keeps server-side
  rewrap covered where KEKs never rotate.
- `Fixture::missing_key_uri(kind)` takes the key kind, so a backend whose signing, MAC or RSA KEK
  keys are opened with a version (GCP) names a version of the missing key.

## 2. New handle parts

### 2.1 Mechanics shared by every new part (`dynamic.rs`)

The `handle!` macro sets **every** optional part in `full` (`$( $opt: Some(k.clone()), )*`), so
today a new optional part would either break `full` or need `K` to implement it. Change the
macro (K1) to take a second group of *later* parts:

```
AeadKey / AeadKeyParts {
    aead: DynAead [aead];
    rewrap: ..., data_keys: ..., describe: ...;           // 0.1 parts: set by `full`
    later wrapped_data_keys: DynWrappedDataKeys [wrapped_data_keys]
        / with_wrapped_data_keys / supports_wrapped_data_keys;   // never set by `full`
}
full: Aead Rewrap DataKeys Describe
```

`full` initializes later parts to `None`; `apply`, `with_*`, `rebuild`, `Debug` treat both
groups alike. `full_bounds_are_frozen` stays unchanged (it is the guard). Per new part, the
checklist (PLAN §22 "each new part also needs a `Layer` method"):

1. trait in `traits.rs` (`#[trait_variant::make(Send)]`), re-export in `lib.rs` and `prelude`;
2. `dyn_layer!` invocation (or hand-written like `DynDataKeys` for by-value args) and a
   `sealed` marker;
3. `Part::X`, `PartKind::X` (+ `as_str`), `Layer::x` provided method calling `part`, the
   forward in `impl Layer for Arc<L>`;
4. `RetryLayer::part` and `ObserveLayer::part` arms (exhaustive inside core: does not compile
   until done), `impl X for Retry<T>`, `impl X for Observed<T>`;
5. `optional_part!` arm (Unsupported before I/O when missing);
6. `KeyWrapKey::from_aead` carries it where relevant; local implements it; conformance case.

### 2.2 `WrappedDataKeys` (K2) — in scope

Appendix A *planned* (AWS `GenerateDataKeyWithoutPlaintext`), §19 (transit `datakey/wrapped`).

```rust
pub trait WrappedDataKeys {
    /// A fresh data key, returned only wrapped (as `DataKeys` would return its ciphertext).
    /// Unwrap with `Aead::decrypt(ct, aad)` on the same key. AAD semantics as `DataKeys`.
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext>;
}
```

- Separate trait, not a flag on `DataKeys`: least privilege (AWS IAM action and Vault policy
  path differ; a writer that never sees plaintext keys).
- Hand-written `DynWrappedDataKeys` (by-value `spec`), `Operation::GenerateDataKey` reused (no
  new `Operation`), no capability bit (it is available exactly where `DATA_KEYS` is on every
  planned backend; `supports_wrapped_data_keys()` is the per-handle truth).
- Optional *later* part on `AeadKey` only. Implemented by transit (`datakey/wrapped`, same AAD
  rule as `datakey/plaintext`), local, AWS. GCP/Azure: absent (no emulation: a recipe would
  have to see the plaintext).

### 2.3 Native `KeyWrap` on non-AEAD keys — no core change

`KeyWrapKey::new(backend, Arc<dyn DynKeyWrap>).with_describe(..).with_concrete(..)` already
covers it. In scope for the cloud backends:

| Backend | Key | Wrap | Unwrap | Notes |
|---|---|---|---|---|
| AWS | RSA `ENCRYPT_DECRYPT` | `Encrypt` `RSAES_OAEP_SHA_256` (server) | `Decrypt` with `KeyId` = handle key | no `EncryptionContext` (AWS rejects it) |
| GCP | `ASYMMETRIC_DECRYPT` `RSA_DECRYPT_OAEP_*_SHA256` | **local** OAEP with the version's public key (R3) | `asymmetricDecrypt` (CRC32C) | URI must name a version; SHA-1 keys → `KeyMismatch` |
| Azure | RSA (vault, HSM) | `wrapKey` `RSA-OAEP-256` | `unwrapKey` | framing `version ‖ ct` (Appendix A) |
| Azure MHSM / oct-HSM | AES | `wrapKey` `A256KW` | `unwrapKey` | Premium oct-HSM preview: not promised |

Decision: **OAEP-SHA-256 only**, fixed by the backend, not a portable parameter. A per-call
algorithm (AWS, Azure) is pinned at open so a wrapped key never depends on caller input;
SHA-1 interop, if ever needed, is a backend `OpenOptions` extension. `wrapped_key_version`
returns the backend's version where the framing has it (Azure, GCP), `None` on AWS.

Declined for now: a native `KeyWrap` *optional part on `AeadKey`* (Azure MHSM AES keys can both
encrypt and `wrapKey`). `Provider::key_wrap` already opens the key as a `KeyWrapKey` with the
native wrap; nothing needs both on one handle. Revisit if an `AeadKey` → native-wrap
conversion is asked for.

`AsymmetricDecrypt` (decrypting foreign RSA-OAEP ciphertexts of arbitrary length/AAD-less
payloads) stays deferred: `KeyWrap` covers envelopes, which is the only portable use.

### 2.4 Other Appendix A *planned* rows

| Row | Shared work | Where |
|---|---|---|
| GCP newest-ENABLED version mode | none | GCP backend |
| Azure `KeyWrap`-based data keys | recipe R1 (§4) | recipes |
| GCP `used_primary` | none in core (`Decrypted::with_used_primary` exists); conformance `UsedPrimary` | suite |
| AWS native context maps, grant tokens | extension calls (§3); grant tokens via `OpenOptions::with_extension` (exists) | core |
| `BackendDetail::{code, request_id}`, `Unauthenticated`, `KeyVersionUnusable` | none (exist) | — |
| secp256k1, HMAC-SHA224 (§21 4.8) | `SignatureAlgorithm::EcdsaSecp256k1Sha256` (+ storage code, `FromStr`, JOSE `ES256K`), `AsymmetricKeyType::EcSecp256k1`, `MacAlgorithm::HmacSha224`, `LocalVerifier` via `k256` | core + recipes, K4, later |

## 3. Layered extension calls (K3)

Problem (review plan 4.3, Appendix A): a backend-specific operation reached through
`AeadKey::downcast_ref::<AwsAeadKey>()` bypasses every `Layer`: no retries, no metrics.

Split the two kinds of backend-specific input:

- **Per-open options** (grant tokens, a pinned algorithm): `OpenOptions::with_extension` —
  exists; the handle's normal parts are layered. No change.
- **Per-call native operations** (encrypt/decrypt/re-encrypt with a native context map): a new
  layered slot every opaque handle has.

```rust
// traits.rs
pub trait ExtensionCalls {
    async fn call(&self, call: ExtensionCall<'_>) -> Result<ExtensionOutput>;
}
// dynamic.rs
#[non_exhaustive]
pub struct ExtensionCall<'a> {
    pub op: Operation,              // Encrypt, Decrypt, Rewrap, ... (for retry/observe/labels)
    pub name: &'static str,         // "aws.encrypt_with_context"; stable, non-secret
    run: &'a (dyn Fn() -> BoxFuture<'a, Result<ExtensionOutput>> + Send + Sync),
}
impl<'a> ExtensionCall<'a> { pub fn run(&self) -> BoxFuture<'a, Result<ExtensionOutput>>; }
pub struct ExtensionOutput(Box<dyn Any + Send>);   // opaque; only the handle helper unerases
```

- `dyn_layer!` gives `DynExtensionCalls`; a private `Direct` impl (`call.run().await`) is the
  raw part of every handle (`new`, `full`, `from_aead`), so the slot is never `None`.
- `Part::Extension(&mut Arc<dyn DynExtensionCalls>)`, `PartKind::Extension`,
  `Layer::extension` provided method. `RetryLayer`: `Retry::run(|| call.run())` (the closure
  is `Fn`, so attempts re-invoke the backend). `ObserveLayer`: times it; `OpEvent` gains
  `extension_name() -> Option<&'static str>`. Third-party layers see it in their catch-all
  (§20 rule), so nothing silently bypasses them.
- Every opaque handle gets one generic helper (in `handle!`):

  ```rust
  pub async fn call_extension<'a, R: Send + 'static>(
      &'a self, op: Operation, name: &'static str,
      f: impl Fn() -> BoxFuture<'a, Result<R>> + Send + Sync + 'a,
  ) -> Result<R>;
  ```

  It erases `R` into `ExtensionOutput`, calls the layered slot, and unerases (a type mismatch is
  impossible by construction; map it to `Backend` defensively).
- Typed path: `Retry<T>::call(op, f)` and `Observed<T>::call(op, name, f)` (public), so
  `retry.wrap(aws_key)` users get the same.
- Backend pattern (AWS plan owns the trait):

  ```rust
  pub trait AwsAeadExt {
      async fn encrypt_with_context(&self, pt: &[u8], ctx: &EncryptionContext) -> Result<Ciphertext>;
  }
  impl AwsAeadExt for AeadKey {
      async fn encrypt_with_context(&self, pt: &[u8], ctx: &EncryptionContext) -> Result<Ciphertext> {
          let k = self.downcast_arc::<AwsAeadKey>().ok_or_else(not_an_aws_key)?;
          self.call_extension(Operation::Encrypt, "aws.encrypt_with_context",
              || Box::pin(k.encrypt_with_context(pt, ctx))).await
      }
  }
  impl AwsAeadExt for AwsAeadKey { /* direct */ }
  impl AwsAeadExt for Retry<AwsAeadKey> { /* self.call(..) */ }
  ```

- Rejected: `Part::Other(TypeId, &mut Arc<dyn Any>)` (layers cannot decorate unknown types);
  per-backend `Part` variants in core (core would name AWS); a `Layer::around` hook with a
  default (third-party layers would silently skip it, the exact failure §20 designed out).
- Spike first (S): the `'a` lifetimes through `Fn() -> BoxFuture<'a>` borrowed across retries.
- Conformance: `layers::extension_calls_are_layered` (`Extension`): fixture method
  `Fixture::extension_call(&self, key: &AeadKey) -> Result<()>` performs one native call; the
  case wraps the handle in a counting `Layer` and asserts one `PartKind::Extension` event, and
  that an injected retryable failure is retried by `RetryLayer`.

## 4. Recipes

- **R1 `KeyWrapDataKeys<K: KeyWrap>`** (`recipes/src/datakeys.rs`, ungated like
  `EmulatedDataKeys`). Implements `DataKeys`: non-empty `aad` → `Unsupported` *before* the RNG
  and any I/O ("KeyWrap has no AAD slot; bind context with EnvelopeAead"); else 32 random bytes
  (`getrandom`, `Backend` on failure, as `EmulatedDataKeys`), `wrap_key`, `DataKey::new`. The
  `DataKey`'s ciphertext unwraps with `KeyWrap::unwrap_key`, not `Aead::decrypt`: documented in
  the "Emulates / Enforced by" box. For Azure standard vaults (Appendix A, §21). Separate type
  rather than generalizing `EmulatedDataKeys` (whose AAD binding is its point).
  Conformance `recipes::keywrap_data_keys` (`KeyWrap`): round trip via `unwrap_key`, AAD →
  `Unsupported` with zero requests.
- **R2 `ClientRewrap<K: Aead>`**: implements `Rewrap` as decrypt + encrypt in the client, AAD
  supported. "Emulates: server-side rewrap. Enforced by: none; the plaintext passes through this
  process." For GCP (no `Rewrap`) and anyone else; never used implicitly (PLAN §3.2). Optional
  `EnvelopeAead::rewrap_or_local` (uses `Rewrap` when the KEK `supports_rewrap()`, else
  `rewrap_local`) is a convenience, S, nice-to-have.
- **R3 RSA-OAEP-SHA256 public-key wrap** (`recipes/src/rsa_backend.rs`, behind the existing
  `aws-lc-rs` / `rsa` features): `pub fn rsa_oaep_sha256_encrypt(spki_der: &[u8], msg: &[u8])
  -> Result<Vec<u8>>`. Needed by GCP's local wrap. aws-lc-rs: `OaepPublicEncryptingKey`;
  RustCrypto: `rsa::Oaep::new::<Sha256>()` (encryption with a public key; Marvin advisory is
  about private-key ops, so the `deny.toml` reason stays true). Neither feature → `Unsupported`.
- GCP `EmulatedDataKeys<AeadKey>` and `LocalVerifier` need no change; GCP depends on
  `anykms-recipes` with `default-features = false, features = ["aws-lc-rs"]` (§21).
- Azure ECDSA raw `r‖s` → DER: `recipes::ecdsa_der` exists.

## 5. Shared cloud infrastructure

*Superseded by README §2.1 / Q4:* the backends share `anykms-http` (HTTP client, TLS, retry
hints, zeroizing buffers). The decision below is kept for history; the backend checklist after the
table is current.

Original decision: **no shared crate** (`anykms-http` or similar) for 0.2. A crate the backends depend on
must be published and semver-checked; the shareable surface is small, and two of three backends
are likely SDK-based (their HTTP stack is the SDK's). Revisit if two in-house REST clients
appear.

| Candidate | Decision |
|---|---|
| Retry-After parsing (`transit/src/client.rs::retry_after_value`, 40 lines + `httpdate`) | copy into backends that see the header (Azure 429/503); AWS/GCP signal throttling by error code |
| rustls provider precedence (`client.rs::crypto_provider`: config → process default → aws-lc-rs → ring) | copy the function and its test; it is the rule, keep it identical (review plan 1.2) |
| `zbuf.rs` (zeroizing growable buffers) | copy where the backend builds request bodies itself; with an SDK it cannot control buffers: document the residual risk instead |
| Lazy credential/client init | pattern, not code: `tokio::sync::OnceCell::get_or_try_init`; a failed init is not cached by the `OnceCell` (separately, the shared credential cache remembers a failed credential fetch for 5 s, release plan 2.1); `Provider` construction stays sync and I/O-free (§19) |
| Error-mapping helpers | per backend; core already has `Error::new`, `BackendDetail::{code,request_id,http_status}`, `with_retry_after`, `with_retry_hint` |
| Tracing field allowlist | a written rule (below) plus a per-backend TRACE hygiene test, modelled on `transit/tests/hygiene.rs` |

Backend checklist (every HTTP backend, transit included; reviewers check it). Updated with the
Phase 1 rules of `architecture-plan.md` §2 (PLAN §25.1): where a rule names an `anykms-http`
helper, backends call it instead of keeping their own copy.

- **No retries below `Retry`.** AWS `RetryConfig::disabled()`; GCP retry policy "never" on every
  call; Azure `RetryOptions::none()`. Credential refresh inside the SDK is the one allowed
  retry. Surface `Retry-After` / retry info with `Error::with_retry_after`.
- **No redirects.** reqwest-based clients (Azure's default `azure_core` transport, any
  in-house client) use `redirect::Policy::none()`; a 3xx is `Configuration` (D6: a redirect
  means the endpoint is wrong, and retrying will not fix it) with no body or `Location` echoed. Verify for each SDK transport.
  `TowerTransport` cannot control the inner service's redirects: its docs make the caller
  configure the service not to follow them, and a 3xx that comes through is still the
  backend's `Configuration` error.
- **Timeouts**: connect and per-attempt timeouts in the client (transit defaults: 2 s / 10 s);
  overall deadline stays in `Retry`. `TowerTransport` adds none of its own (a layer's job; it
  forwards `RequestTimeout` to the service in the request's extensions).
- **Responses** are read through `anykms_http::client::send` (bounded, zeroizing);
  `max_response_bytes` is at least `client::MIN_RESPONSE_BYTES` (64 KiB), refused at `build()`
  otherwise (P1-11).
- **TLS**: rustls 0.23 with the provider precedence above; no `native-tls`/OpenSSL in the
  default build; no option to skip verification.
- **Opening does no I/O**; credentials lazy; errors map to `Unauthenticated` (401/expired),
  `PermissionDenied` (403), `Configuration` (no credentials found), `Unavailable` (metadata
  endpoint unreachable). The data-plane HTTP client is built in `build()` (TLS roots and the
  crypto provider fail there, with no network I/O); credential-endpoint clients stay lazy (P1-12).
  P1-12 is superseded for the facade defaults only (release plan 2.3, R-33): when the system
  trust store has no usable root, `with_default_providers()` skips that cloud provider with
  `SkipCause::TlsRoots` instead of failing the registry. A provider built explicitly still fails
  at `build()`.
- **Configuration** that would refuse everything is an error at `build()`: an empty allowlist or
  an allowlist variable set to an empty value is `Configuration` (P1-10).
- **Credentials**: every source, custom ones included, goes through the credential cache and the
  token span (P1-7). Token **files** (projected or rotated) are classified by
  `zbuf::token_file_error_kind`: a missing file is `Unavailable`, every other failure
  `Configuration`, and the error names the file; files that select a credential source (ADC JSON,
  AWS profiles) are always `Configuration` (P1-2). The cache is single-flight (release plan 2.1,
  R-30): one fetch runs at a time and every caller waiting for it gets its result, a failure
  included; with no usable credential a failure is returned without a fetch for 5 s (as
  transit's `Login` does); a refresh ahead of expiry runs in the one caller that found it due
  while the others keep the valid credential; a cancelled fetch hands over to a waiting caller.
- **Debug** of any type holding a URL prints `redact::url_origin` (`scheme://host:port`) only;
  signed requests never print a signature. The hygiene test checks it with
  `anykms_testkit::assert_debug_redacts` (P1-1).
- **Metadata caches** (type check, describe, key bundle) are dropped only when a request that
  addressed the handle's own key or version fails with `NotFound`, `KeyMismatch`, `Unsupported`
  or `KeyStateInvalid`; a version taken from input never drops them. A per-backend test sends 100
  forged versions and counts no extra metadata request (P1-4). Concurrent misses for one key
  share one read and its result, a failure included (`cache::SingleFlight`; release plan 2.1,
  R-34): a per-backend test sends 20 concurrent first operations and counts one metadata
  request. A failed read is not cached beyond that.
- **Local verification** trusts a version's public key for at most the metadata TTL, jittered
  with `cache::jittered_ttl` and counted from the fetch; a failed re-read fails closed; unknown
  input versions are negative-cached (64 entries, same TTL) (P1-13).
- **Errors** carry the key as `resource` (`KeyUri::without_query`), including open-time checks
  after the URI is parsed (P1-6), `BackendDetail::code` = exception name / gRPC status / Azure
  code, `request_id` (filtered by `redact::request_id`: 1–128 ASCII graphic characters, P1-9);
  `Retry-After` and similar hints are attached whatever the kind (P1-3); never a message that can
  contain input (redact via `ServerMessage::redacted`).
- **Tracing allowlist** (`tracing` feature; D3, one schema for all four HTTP backends).
  Request spans are `anykms.<backend>` with exactly these fields: `backend`, `op`, `resource`,
  `key_version`, `attempt`, `http_status`, `code`, `request_id`, `latency_ms`, `error_kind`,
  `outcome`. `outcome` is `ok`, `error`, or `cancelled` when the call was dropped before it
  finished (recorded by the `span::start_request` guard, R-32). `resource` is `KeyUri::without_query` and carries the location (region and
  account, project/location/key ring, vault host); there are no separate location fields.
  `code` is `BackendDetail::code` (AWS exception name, GCP `google.rpc.Status` name, Azure
  innermost error code), not a backend-specific name such as `aws_error_code`. `request_id` is
  recorded only after the backend's request-id filter. Token spans are `anykms.<backend>.token`
  with `backend`, `credential`, `outcome`, `error_kind`, `latency_ms`, `expires_in_s`. Spans
  are created with `anykms_http::request_span!`/`token_span!` and closed with
  `span::start_request`'s guard/`finish_token`; the hygiene test asserts the schema with
  `anykms_testkit::assert_request_schema`/`assert_token_schema`. A token refresh is a `debug!`
  event, a failed one a `warn!` with `credential`, `error_kind` and the error (P1-8).
  Never: plaintext, AAD or encryption-context values (AAD is context on AWS), grant tokens,
  credentials, request or response bodies, URLs with query strings. Library-internal spans
  (`hyper`, `reqwest`, `rustls`) are outside the allowlist: each backend's operator doc
  (`docs/operations-<backend>.md`) tells operators to cap them at INFO, and each backend's
  hygiene test runs with every target at TRACE to find leaks.
- **Fuzz** the URI parser (add to `fuzz/` and the nightly matrix).
- **Backend name** (D1): `Error::backend()`, `Provider::name()` and `SkippedProvider::backend`
  use the crate suffix, not the scheme: `transit`, `aws`, `gcp`, `azure` (schemes stay
  `hashivault`/`openbao`, `aws-kms`, `gcp-kms`, `azure-kv`).
- **Unversioned verify input** differs on purpose: GCP and Azure refuse a signature or tag
  without a version (`InvalidArgument`), AWS verifies it with the handle's key (one key per ARN,
  so absence cannot select a key).

## 6. URIs, providers, facade, supply chain, CI

### 6.1 KeyUri schemes

Core `KeyUri { scheme, rest }` needs no change (`uri.rs`: lowercase scheme, opaque rest, no
whitespace/control/non-ASCII, 2048-byte cap). Schemes (Tink convention where one exists):

| Scheme | Rest grammar (each backend's strict parser) | Address policy |
|---|---|---|
| `aws-kms` | `//arn:aws[-cn\|-us-gov]:kms:<region>:<account>:key/<id>` or `…:alias/<name>`; bare IDs only with a configured default region | region from the ARN picks the regional endpoint; optional account and region allowlists; custom endpoint (LocalStack) only from config, never the URI |
| `gcp-kms` | `//projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>[/cryptoKeyVersions/<n>]` | fixed endpoint; optional project allowlist; version required for signing, MAC and `KeyWrap` keys |
| `azure-kv` | `//<host>/keys/<name>[/<32-hex version>]` | host allowlist (default: `*.vault.azure.net`, `*.managedhsm.azure.net` and sovereign suffixes, §21); bearer tokens never reach other hosts |

`Registry::build` already rejects duplicate schemes; each provider claims exactly one scheme.

Implemented as: AWS URIs are ARN-only (no bare IDs, no default region), and the region must have
the AWS region shape and belong to the ARN's partition, so a derived host is always a KMS
endpoint (security review L3); endpoint overrides come from the builder or `AWS_ENDPOINT_URL*`.
GCP also has an optional location allowlist, and its regional endpoint is derived from the URI's
location when configured. Azure versions are accepted as 32 hex characters today.

### 6.2 Facade (`crates/anykms`)

- Features `aws`, `gcp`, `azure` (`dep:anykms-aws` etc.; crate names per backend plans), all
  off by default. `tracing` forwards (`anykms-aws?/tracing`); `rustls-ring` / `rustls-aws-lc-rs`
  forward where the backend exposes them.
  Implemented with `rsa-aws-lc-rs` / `rsa-rustcrypto` and `http2` forwarded to all three cloud
  backends as well; `gcp` also turns on `anykms-gcp/service-account-key`.
- `with_default_providers()` (D2): a cloud provider with its feature on is **always
  registered**: construction is I/O-free, credentials lazy, URIs fully addressed. A missing
  credential is a `Configuration` error on the first operation, naming the variables to set.
  - A **malformed** environment variable (e.g. `AWS_USE_FIPS_ENDPOINT=maybe`, an unparsable
    `ANYKMS_GCP_ENDPOINT`, `ANYKMS_AZURE_CREDENTIAL=bogus`) is an **error** returned from
    `with_default_providers()`, never a skip (the transit rule: "a broken configuration is an
    error, never a silent skip").
  - The one explicit skip is `ANYKMS_AZURE_CREDENTIAL=none`.
  - Feature off → `SkippedProvider` "the anykms `aws` feature is not enabled", exactly like
    transit; opening such a key fails with `Configuration` naming the feature.
  - Transit stays the exception: without `VAULT_ADDR`/`BAO_ADDR` it has no address and is skipped.
- README feature table and quick start. Operator docs are one file per backend (D5):
  `docs/operations-aws.md`, `docs/operations-gcp.md`, `docs/operations-azure.md`, with transit in
  `docs/operations.md`. This replaces the earlier "one section per cloud in
  `docs/operations.md`": separate files keep each runbook readable.

### 6.3 `deny.toml`, MSRV

- Licenses: run `cargo deny check licenses` on a spike branch per SDK before committing to it.
  Expected additions: `Zlib` (e.g. `foldhash`), `BSL-1.0`, `MIT-0` only if a crate requires it
  outright (aws-lc-sys 0.45 offers it as an alternative and passes today), possibly `MPL-2.0`
  (weak copyleft; maintainer decision, §9).
  Add each with the crate that needs it in a comment.
- Advisories/bans: SDKs must resolve to rustls 0.23 / hyper 1 / http 1 (AWS
  `behavior-version-latest`, default HTTPS client without the legacy rustls 0.21 connector).
  `multiple-versions = "warn"` stays; review `cargo tree -d` per backend.
- MSRV: workspace stays 1.85 for core, recipes, local, transit, conformance and the facade
  without cloud features. A backend whose SDK needs newer Rust sets its own `rust-version`;
  the facade documents "feature `aws` needs Rust ≥ X". **Risk:** `resolver = "3"` prefers
  dependency versions compatible with the workspace members' `rust-version`; verify the SDKs do
  not get pinned to stale versions, else set `incompatible-rust-versions = "allow"` in
  `.cargo/config.toml` (CI MSRV job keeps checking the 1.85 crates from the lockfile).

### 6.4 CI (`.github/workflows/ci.yaml`)

- `check`: add the shaped fixtures (`cargo test -p anykms-local --test conformance_gcp_shaped
  --test conformance_azure_shaped`), clippy/`--no-default-features` per backend crate (the
  existing loop covers new crates), facade `--features aws,gcp,azure` docs.
- `msrv`: `cargo check --workspace --exclude anykms-aws --exclude anykms-gcp --exclude
  anykms-azure ...` at 1.85; one job per backend at its own MSRV if higher.
- `semver` matrix: add `anykms-conformance` and each backend (skipped until baselined).
- `cloud-emulated` (every PR, no secrets): `docker compose --profile aws --profile azure up`
  and run AWS conformance against the emulator, Azure against Lowkey Vault; GCP mock tests only.
- `cloud-live` (push to `main`, nightly schedule, `workflow_dispatch`; **never** on
  `pull_request`): `permissions: id-token: write`, GitHub OIDC federation, no long-lived keys:
  AWS `aws-actions/configure-aws-credentials` (`role-to-assume`, trust policy pinned to
  `repo:sagikazarmark/anykms:ref:refs/heads/main` and the environment), GCP
  `google-github-actions/auth` (workload identity pool, attribute condition on repository and
  ref), Azure `azure/login` with a federated credential (subject = environment). A protected
  GitHub environment `cloud` per provider; actions pinned by SHA like the existing ones;
  `ANYKMS_REQUIRE_FIXTURE=1`, `ANYKMS_FAIL_ON_SKIP=1`.
- Implemented as per-backend jobs rather than two shared ones: `aws-emulator` (Floci, every PR),
  `aws-localstack` (only with `LOCALSTACK_AUTH_TOKEN`), `aws-live`; `azure` (Lowkey Vault, every
  PR) and `azure-live`; GCP's mock and fake-server conformance tests run inside `check`, plus
  `gcp-live`. Every crate, cloud backends included, has MSRV 1.85 (no SDKs; PLAN §23 Q5), so the
  `msrv` job needs no per-backend exclusions beyond the wiremock-based tests.

### 6.5 Live test resources

*Implemented as `scripts/{aws,gcp,azure}-test-setup.sh` (see the architecture plan, C6).*

- Pre-provision keys with IaC in `ci/cloud/{aws,gcp,azure}/` (Terraform/OpenTofu): a shared
  pool per `TestKeyKind`, plus a dedicated, tightly scoped account/project/subscription; the
  CI identity can use the pool and create keys only under a test prefix/key ring.
- `KeyUse::Shared` → pool; `KeyUse::Fresh` → created, tagged with the run ID, scheduled for
  deletion (AWS 7 days, Azure soft-delete + purge, GCP version destroy) at the end of the run
  and by a nightly sweeper for crashed runs. GCP keys and key rings cannot be deleted: Fresh
  keys there reuse a per-run ring and destroy all versions; cost is per version.
- Rotation-heavy cases are the cost driver (AWS on-demand rotation is limited per key):
  backend plans size them; `RotateMac` / `RotateSigning` are n/a on AWS by design.

### 6.6 Emulators (`compose.yaml`, `scripts/dev-up.sh`)

- Compose **profiles** so the default `dev-up.sh` (Vault, OpenBao) is unchanged:
  `--profile aws`: LocalStack KMS (fallback: moto server; see §9; implemented as Floci, with
  LocalStack opt-in, cloud README §2.2); `--profile azure`: Lowkey
  Vault (needs its self-signed TLS cert in the test trust store and its host in the test
  allowlist, config only). Images pinned by tag **and** digest, overridable as whole references
  (`LOCALSTACK_IMAGE`, `LOWKEY_VAULT_IMAGE`), as §20 requires.
- GCP: no emulator. Mock tests (wiremock over REST, or a fake gRPC server, per the GCP plan) and
  live runs; the GCP-shaped proof fixture covers the suite's gating.
- Emulator fidelity is never the exit criterion: cases that differ on the emulator are declared
  `lacks` there, `Yes` on live.

## 7. Semver and release

- Baseline: 0.1.0 as on crates.io (if it is not yet published when this work starts, publish
  0.1.0 first; nothing here belongs in it).
- Core changes are additive: new trait (`WrappedDataKeys`, `ExtensionCalls`), new
  `Part`/`PartKind`/`Feature` variants (all `#[non_exhaustive]`), new provided `Layer` methods,
  new handle methods (`with_wrapped_data_keys`, `call_extension`), new `OpEvent` accessor, new
  types. `full` bounds unchanged (guard test). Recipes: new items only. Transit/local: new impls.
  So `cargo-semver-checks` stays green.
- Breaking only in the unpublished `anykms-conformance` (`create_key` signature, `bridge_aead`
  → `AeadBridge`, undeclared = failure). No constraint, by design of §22.
- **Release as 0.2.0** with AWS: lockstep versioning puts new crates (conformance, aws) at the
  workspace version; a minor bump marks the dependency-tree and MSRV jump of the cloud
  features; and 0.x leaves room to bundle a deliberate break if the AWS work finds one. If the
  maintainer prefers, the shared parts alone can ship as 0.1.x (they are compatible).
- Ordering relative to M5 (PLAN §10): Kubernetes/JWT login, the decrypt-side DEK cache
  (`CachingKeyWrap`) and the metrics layer (`ObserveLayer`) are done (review plan 4.1–4.3);
  AppRole login is not and does not block cloud work (independent crate). Layered extension
  handles are K3 here. Envelope v2 (multi-slot + streaming) is independent and must not gate
  any cloud backend; `KeyLifecycle`, `Random`, `AsymmetricDecrypt` stay after.
- Order: 0.2.0 = suite redesign + K1–K3 + R1–R3 + AWS. GCP and Azure follow as 0.2.x (additive)
  or 0.3.0 if they need a core break.

## 8. Ordered tasks

| # | Task | Size | Depends on | Unblocks |
|---|---|---|---|---|
| D0 | PLAN §23 records this document's decisions; Appendix A *planned* rows point here | S | — | all |
| K1 | `handle!` "later parts" group; tests that `full` leaves them `None` and `with_*` + layers work | S | — | K2, K3 |
| C1 | `Feature` variants, `Support::Undeclared`, `supports_all`, gate fails on undeclared, `conformance::declarations` trial (§22 steps 1–2) | S | — | C2–C6 |
| C2 | `TypedHandles` defaults, `TestKeyKind::KeyWrap`, `KeyUse` + `Ctx::{fresh_key,keys,describe_key,describe_for,kek}`, `AeadBridge`/`KeyWrapBridge`, optional describe on `*KeyHandles` (steps 3–4) | M | C1 | C3, C5 |
| C3 | Gating table §1.2; case splits; version-shape, primary-version and per-kind rotate fixes; `recipes::envelope_native::*` | M–L | C2 | C4–C6, all backends |
| C4 | `capabilities::handles_match_declaration` (step 6) | S | C3 | C6 |
| C5 | Migrate local and transit fixtures (step 7, first half); counts unchanged | S | C3 | C6, C9 |
| K2 | `WrappedDataKeys` (core checklist §2.1), transit + local impls, `datakeys::wrapped_only*` cases | M | K1, C3 | AWS |
| K3 | Extension calls: spike, core, `Retry::call`, `Observed::call`, `layers::extension_calls_are_layered` | M | K1, C3 | AWS (context maps) |
| C6 | GCP-shaped and Azure-shaped proof fixtures, in CI | M | C4, C5 | GCP, Azure |
| C7 | New cases: `aead::decrypt_with_info`/`used_primary_after_rotation`, `mac::<alg>::input_limit`, `sign::ed25519::input_limit` | S | C3 | AWS, GCP |
| R1 | `KeyWrapDataKeys` + `recipes::keywrap_data_keys` | S | C3 | Azure |
| R2 | `ClientRewrap` (+ optional `rewrap_or_local`) | S | — | GCP |
| R3 | `rsa_oaep_sha256_encrypt` in recipes, both RSA backends, vectors | S–M | — | GCP `KeyWrap` |
| I1 | CI skeleton: `cloud-emulated`/`cloud-live` jobs (OIDC, environments), MSRV split, semver matrix entries; compose profiles; `dev-up.sh` profile flags | M | — | per backend fill-in |
| I2 | Facade features + `with_default_providers` behavior + README/operations sections | S per backend | backend crate | release |
| I3 | `deny.toml` license/advisory review per SDK spike | S per backend | SDK choice | backend merge |
| C9 | Publish conformance (§1.5): manifests, transit excludes, semver matrix, releasing.md, CHANGELOG | S | C6 | third-party backends, 0.2.0 |
| K4 | secp256k1 + HMAC-SHA224 (core, recipes `k256`, JOSE `ES256K`, conformance algs) | M | — | AWS/GCP/Azure extra algs (optional) |
| D1 | `docs/operations.md`: SDK log targets, OIDC setup notes, live-test IaC | S | I1 | release |

Critical paths: **AWS** K1 → C1 → C2 → C3 → (K2, K3, C5) → AWS crate → C9 → 0.2.0.
**GCP** C3 → C6 + R2 + R3 → GCP crate. **Azure** C3 → C6 + R1 → Azure crate. Shared work
before the first backend can merge: about 8–10 days (C1–C5, K1–K3, C7), of which the suite is
about 4; C6, R1–R3 add 3–4 days and can run in parallel with the AWS crate.

## 9. Risks and open questions

Risks:

- **Extension-call lifetimes.** `Fn() -> BoxFuture<'a>` borrowing caller inputs across retry
  attempts may fight the borrow checker through `trait_variant`; spike before committing (K3).
  Fallback: owned inputs (`Arc`/clone) in the closure.
- **SDK MSRV vs 1.85 and resolver 3** (§6.3): the SDKs may need a newer compiler, and the
  MSRV-aware resolver may hold them back silently. Check `Cargo.lock` after adding each SDK.
- **LocalStack availability.** LocalStack's distribution and licensing terms have changed over
  time (auth tokens for some images); if the KMS emulator needs an account, use moto server
  (Apache-2.0) for the AWS emulated job.
- **Cloud cost and quotas.** Per-case key creation is not viable on GCP (undeletable keys) or
  at AWS scale; `KeyUse` plus pools mitigate. Live runs must stay off fork PRs.
- **SDK logging.** SDK TRACE output may contain bodies or headers outside our allowlist; the
  per-backend hygiene test is the guard, and the operator guidance caps those targets.
- **`util::tamper` assumptions.** It flips a byte at `len/2 + 2`; on framed ciphertexts (Azure
  `version ‖ ct`, AWS blobs with a key header) a hit in the header must still map to
  `DecryptFailed`, not `NotFound`/`KeyVersionUnusable`. Backend plans must check their mapping.
- **Undeclared = failure** breaks third-party fixtures loudly on every new `Feature`; intended
  (§22 step 2), but it makes adding a feature a coordinated change once the crate is published.
- **Default TLS provider.** Cloud SDKs bring aws-lc-rs; with the facade's default
  `rustls-ring`, a build with `transit,aws` compiles both. §22 left switching open.

Open questions for the maintainer:

1. 0.2.0 for the AWS release (recommended) or 0.1.x for the additive shared parts?
2. Is `MPL-2.0` (weak copyleft) acceptable in `deny.toml` if an SDK's credential chain needs it?
3. Crate names: `anykms-aws` / `anykms-gcp` / `anykms-azure` (short) vs `anykms-aws-kms` /
   `anykms-gcp-kms` / `anykms-azure-keyvault` (explicit)? Facade features follow.
4. Should the facade's default TLS provider move to aws-lc-rs when a cloud feature is on, or
   globally?
5. OAEP-SHA-256 only (recommended), or SHA-1 interop for existing AWS/Azure RSA-wrapped data?
6. Who owns the cloud accounts/projects/subscriptions for CI, and the monthly budget cap for the
   live jobs?
7. Is `ClientRewrap` (plaintext through the client) acceptable as a public recipe, or should GCP
   users get only `EnvelopeAead::rewrap_local` (which exposes only data keys)?
8. Should the conformance suite also own a TRACE hygiene case (capturing subscriber in the
   harness), or stay per backend as transit does today?
