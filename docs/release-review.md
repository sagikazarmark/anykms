# anykms 0.1.0 pre-release review

Source: a multi-agent review run on 2026-10-12 against HEAD `ee91665` (`main`), following
`docs/release-review-prompt.md`. The phases were:

- **Phase 0:** a shared brief.
- **Phase 1:** six review lenses: API, SEMVER, SEC, OPS, DOCS and SCOPE.
- **Phase 2:** four black-box personas, P1 to P4.
- **Phase 3:** two comparison studies, CMP-RS (Rust) and CMP-X (other languages).
- **Phase 4:** consolidation of 77 raw findings into 55.
- **Phase 5:** a judge panel.

Findings rated Blocker or Should-fix went to three independent judges: the **Verifier (V)**, the
**Maintainer's advocate (M)** and the **User and release advocate (U)**. Lower-rated findings went
to the Verifier alone. A chair aggregated the verdicts and wrote this file.

**Reviewers that failed: none.** Every lens, persona, comparison and judge batch returned results.
The host disk filled up (ENOSPC) partway through the run. That cut short a few live experiments,
which are noted where they apply: P2's JWKS request count, P4's live Vault-to-AWS migration, and
SEC's floci forgery run. No reviewer was lost.

Effort: XS < 1h, S ≈ half a day, M ≈ 1–3 days, L more.

Reversibility:

| Class | Meaning |
|---|---|
| `ONE-WAY` | Data or contracts that outlive the code |
| `BREAKING` | Public Rust API or feature changes |
| `ADDITIVE` | Can ship in 0.1.x |
| `DOCS` | Documentation only |

`CHALLENGE` marks a finding that argues against a settled decision. "Settled #n" refers to the
94-entry settled-decisions list of the Phase 0 brief. Its sources are PLAN.md,
docs/review-plan.md, docs/cloud/*-plan.md and the CHANGELOG.

All experiments ran in a scratch directory that has since been deleted. Where a verdict rests on
one, the command and its output are quoted inline.

### Baseline at review time (Phase 0)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| clippy `-D warnings`, all features and no default features | pass, 0 warnings |
| rustdoc `-D warnings`, workspace all features and facade defaults | pass |
| `cargo test --workspace --all-features --locked` | **3188 passed, 0 failed**, 3613 ignored (1724 `n/a`, 1883 `skip`), in 370 s |
| `cargo package --workspace --exclude anykms-testkit --locked` | all 10 crates verify. The 41 warnings are all the expected "test not included" kind. |
| `cargo +1.91 check --workspace --all-features --all-targets` | pass (MSRV 1.91) |

Services used by the test run:

| Service | Result |
|---|---|
| Vault conformance | 381 passed |
| OpenBao conformance | 405 passed |
| AWS on Floci | 335 passed, 3 `skip`. The skipped cases are `errors::unauthorized`, because the emulator does not enforce IAM. |
| Lowkey Vault (Azure) | 253 passed |
| GCP fake | 312 passed |

The live cloud and Managed HSM suites skip by design.

Not run: cargo deny, cargo-semver-checks, fuzzing, cargo-hack.

---

## 1. Verdict

**Ship after the blockers.** The project is in unusually good shape for a first release:
- Every check is green.
- The persona trials compiled on the first try in almost every task, and every task scored 3 or
  better.
- The error model, retry design, testing story and conformance suite lead every Rust and
  other-language comparator the review looked at.
- The panel found no defect in the frozen envelope v1 format.

Two items must be settled before `cargo publish`, because they cannot be corrected afterwards:

1. **The AWS AAD encoding (R-1, ONE-WAY).** It must be decided explicitly against Tink's
   convention. See Decision D1.
2. **The envelope trust boundary for RSA (public-key) KEKs (R-2).** The docs currently state the
   wrong writer set. Anyone holding the public key can forge envelopes, and the panel reproduced
   this.

The eleven Should-fix items are almost all XS:
- docs.rs metadata, frozen README and rustdoc statements, and the release-day publish procedure;
- three cheap API corrections that would be BREAKING later: R-3, R-6 and R-11 (Decision D2).

The panel downgraded or rejected a large share of what the consolidator proposed:
- Of the 21 findings the consolidator proposed as Blockers or Should-fixes, 12 survived. Four went
  down to 0.1.x, one to Later, and four were rejected.
- Six findings were rejected in total, three of them because the Verifier refuted them.
- Of the 6 items the consolidator suggested as decisions, 5 were resolved by agreement between
  the advocates.

Total time for the blockers and Should-fixes is about 2–3 days of work.

## 2. Scorecards

### Lenses

| Lens | Score | Summary |
|---|---|---|
| API design | 4 | The core design is careful: sealed `Dyn*` mirrors and handles, consistent `#[non_exhaustive]`, diagnostics that name the fix, one error type classified by kind alone, and redacted `Debug`. The problems are at the edges: per-backend credential naming and casing, one C-STRUCT-PRIVATE gap, feature names that differ between crates. All are cheap to fix before 0.1.0. |
| SemVer and release engineering | 4 | Mature for a first release: lockstep versioning is documented, CI runs a package dry run and an MSRV job, the semver job switches to blocking automatically, and every crate ships license files. The gaps are policy and process: no disclosure or yank procedure, a publish step that hits crates.io's new-crate rate limit, one wrong lower bound, and public-dependency bumps that the semver job cannot see. |
| Security | 4 | Secret hygiene, transport and fail-closed behaviour are strong and held up in experiments. The main gap is that RSA-KEK envelopes can be forged by any holder of the public key, and nothing says so. Smaller gaps: JWTs without `exp` by default, and no consolidated security model. |
| Operations | 3 | The runtime design is careful, but it has gaps under concurrency and failure. Credential fetches serialize, and early refreshes block callers that hold a valid token. The retry deadline and the `interactive()` latency promise are not enforced. One budget is shared across all backends. Cancelled calls are invisible to metrics. All of these are ADDITIVE fixes of size S or smaller. |
| Docs | 4 | Thorough and accurate: every README snippet compiles, the examples run, each operator guide stands alone, and rustdoc coverage is effectively complete. But README and guide code is not tested in CI (one snippet fails at run time), docs.rs leaves `SdkCredentials` out of anykms-aws, and a handful of statements went stale after the credentials change. |
| Scope and sustainability | 3 | The in-house/SDK split is drawn well. But one person owns about 83k lines of Rust plus a 6.8k-line API listing, and CI history shows failures going unseen: a nightly red for 8 days, and a LocalStack job that never ran but is listed as a release gate. |

### Usability tasks (Phase 2 personas)

| Persona | Overall | Task | Score | Note |
|---|---|---|---|---|
| P1: application developer, intermediate | 4 | Encrypt a column: local in dev, Vault in prod | 4 | Zero compiler errors; Vault worked first run (about 10 min). Local keys vanish on restart, so a persistent dev DB returns `decrypt_failed` (400). |
| | | Rotate the KEK and rewrap the rows | 3 | One call for a version rewrap. "Every row on the newest version of the newest KEK" needs a keyring plus a second `EnvelopeAead`, manual routing and an undocumented version comparison (about 45 lines). |
| | | Share the `Registry` across axum handlers | 5 | `Clone + Send + Sync`, as documented; compiled first time. |
| | | Map errors to HTTP | 3 | `Error::class()` is excellent. Caller→400 is wrong for ciphertexts read from your own DB. The README prose contradicts `class()`. The README's default retry policy held a request 7.9 s against an unreachable Vault. |
| P2: platform or identity engineer | 4 | JWT issuer signing with a KMS key (Vault, AWS on floci) | 5 | Compiled first try. About 12 anykms lines. |
| | | Publish a JWKS and verify with jsonwebtoken | 5 | README snippet worked verbatim on both backends. |
| | | Rotate the signing key with overlap | 3 | Needs a hand-merged JWKS. An AWS alias-backed signer drops the old key at the repoint. Transit cannot pre-publish. |
| | | Issue and check HMAC API tokens | 4 | Easy. On AWS the canonical tag embeds the key ARN, giving 177-character tokens. |
| P3: library or backend author | 4 | Toy third-party backend plus conformance | 4 | Green after 3 suite runs (85 passed, 385 n/a). Three rules were discoverable only by failing the suite. No backend-author guide. |
| | | Metrics decorator layer | 5 | Compiled and passed on the first build, from the `Layer` rustdoc example. |
| P4: test author and ops engineer | 4 | Unit tests with no network | 5 | 5/5 passed on the first run. |
| | | Fault injection on retry and error paths | 4 | 7/7 passed on the first run. Hinted, Retry-After, caller-class and `Unauthenticated` faults need a hand-written fake. Exhausted retries look like first-attempt errors. |
| | | Synchronous CLI | 3 | Works with a hand-built `current_thread` runtime, but no doc shows it. A non-tokio executor panics. |
| | | Migrate a Vault KEK to an AWS KEK with `EnvelopeKeyring` | 4 | Excellent rustdoc, idempotent, survives faults. No ring accessors and no completion check. The live run was blocked by the disk incident; verified offline. |

### Comparison verdict per axis (Phase 3)

| Axis | vs Rust crates (CMP-RS) | vs other languages (CMP-X) |
|---|---|---|
| Capability coverage | 4: broadest multi-backend crate; the SDKs are broader by design; missing secp256k1, PQC and asymmetric decrypt (all additive) | 5: the only library with AEAD, rewrap, data keys, sign, MAC and public keys behind one interface |
| Key addressing | 4: same AWS/GCP spellings as Tink, plus allowlists; the AWS AAD mapping breaks Tink interop (R-1) | 3: Tink-compatible on AWS/GCP and safer (address-free); shares the `hashivault`/`openbao` names with sigstore under a different grammar (R-54) |
| Envelope format | 4: committing, versioned, with vectors; better than kms-aead and Tink; no multi-KEK or streaming yet (v2) | 4: commitment equal to ESDK 2.x; better than Tink, Go CDK and go-kms-wrapping; behind ESDK and SOPS on multiple KEKs and streaming |
| Credentials | 3: lazy, controlled workload sources; bridges close most of the gap to SDK chains | 3: parity through the bridges; I/O-free open is better; narrower without them |
| Reliability | 5: one retry layer with deadline, Retry-After, jitter and a budget; no hidden SDK retries | 4: beats opaque SDK retries; ESDK's encrypt-side DEK caching absent by design |
| Errors | 5: 16 kinds, 4 classes and `BackendDetail`, uniform across vendors | 5: only Go CDK's `gcerrors` comes close, and it has no retry classes |
| Testing | 5: local backend with fault injection, plus a published conformance suite | 4: Go CDK's `localsecrets` plus `drivertest` is the closest equal |
| Extensibility | 5: object-safe `Provider`, `Layer`/`Around`, third-party conformance | 4: no out-of-process plugins (not needed in a library) |
| Runtime model | 4: async with `Send` futures and injectable sleep/clock; no sync API (settled) | 3: every comparator offers synchronous calls, which suit CLI use |
| Cost to adopt | 5: 149 deps for four backends vs 135–178 for a single vendor SDK; MSRV below the AWS SDK's | 3: the module-split lesson is applied up front; the default aws-lc-sys C build even with no backend is a cost |
| Hygiene | 3: zeroization and redaction beat the SDKs; no FIPS path, and the README implies one (R-18) | 3: leads on secret handling and fail-closed AAD; FIPS scope undocumented |
| Docs | 4: well ahead of kms-aead and tink-rust; narrower than the SDK guides | 4: on par with ESDK and .NET; no cross-ecosystem URI table |
| Project health | 2: new, solo, unpublished | 2: pre-release, one maintainer, against comparators backed by large organizations |

---

## 3. Decisions needed

Two decisions are the maintainer's to make. Both must be made before publish.

### D1. AWS AAD encoding: adopt Tink's, or record the divergence (R-1, ONE-WAY, Blocker)

**Facts (Verifier CONFIRMED):**
- For non-empty AAD, anykms sends the encryption context
  `{"anykms-aad": base64url_nopad(aad)}`. See `crates/anykms-aws/src/context.rs:27,59`.
- The maintained Tink implementations send `{"associatedData": hex(aad)}`:
  - Tink Java: `AwsKmsAead.java:63,82`, using AWS SDK v2 `BinaryUtils.toHex`.
  - Tink Python.
  - Tink Go's `NewClientWithOptions` default. Only Go's deprecated constructors and tink-rust use
    the legacy `additionalData`.
- So an anykms AWS ciphertext with AAD and a Tink ciphertext under the same `aws-kms://` URI cannot
  decrypt each other. The only symptom is `DecryptFailed`.
- GCP and transit already match Tink by construction.
- The project adopted Tink's URIs (settled #62, "Tink key URIs open unchanged", `uri.rs:1`) and
  Tink's empty KEK AAD (PLAN §15 #9) for portability.
- The recorded reasons for `anykms-aad` (settled #57: ASCII, no `aws` prefix, valid in condition
  keys, UTF-8 values) are met equally by `associatedData`. Tink interop was never weighed.

**Options:**

| Option | What | Cost | Loses |
|---|---|---|---|
| (a) Adopt Tink | `{"associatedData": lowercase_hex(aad)}`, omitted when empty. Reserve that key in `EncryptionContextAead`. Update vectors, `operations-aws.md:56,74,88` and the CHANGELOG. Add a cross-check vector produced by real Tink output, because KMS compares context values exactly. | S | The namespaced policy pin `kms:EncryptionContextKeys ["anykms-aad"]`, which marks anykms traffic. Headroom under the measured 8140-character context limit drops from about 2× to about 1.3×: hex(3072 B) is 6144 characters plus the key. |
| (b) Keep and record | Record the divergence as an explicit decision. Qualify "Tink key URIs open unchanged" in `uri.rs:1` and `lib.rs:20`. Document an `EncryptionContextAead` recipe for reading and writing Tink ciphertexts. Later, add an `AadEncoding::Tink` option (additive). | XS | AWS remains the one backend that cannot interoperate with Tink, permanently, by default. |

**Advocates:**
- M recommends **change now**: "defensible, but not better on any axis users would notice". If
  the change is declined, M considers (b) mandatory.
- U recommends **Blocker, DECISION NEEDED**: "S now, impossible later". U accepts (b) only if it
  is recorded explicitly.

**Recommendation:** (a). Settle R-50 in the same change by making the 3072-byte cap a limit on
producing operations only, so that "may only rise" is safe across mixed fleets.

Before freezing, confirm the hex case against a real Tink Java output. AWS SDK v2 `BinaryUtils`
lowercase is UNVERIFIED. Go's `hex.EncodeToString` is lowercase.

### D2. JWTs without `exp` by default (R-11, BREAKING-behaviour, Should-fix)

**Facts (Verifier CONFIRMED):**
- `JwtOptions::new()` sets neither `exp` nor `iat`. `exp` is added only by `with_ttl`
  (`crates/anykms-recipes/src/jose.rs:352-376,443-448`).
- jwt-simple 0.15 checks `exp` only when the token has one (`claims.rs:624-629`). The project's
  own example works around that by hand (`examples/jwt_signing_jwt_simple.rs:56-57`).
- jsonwebtoken, the verifier the README recommends, requires `exp` by default.

**Options:**

| Option | What | Cost |
|---|---|---|
| (a) Docs only | Warn on `JwtOptions::new`, `JwtSigner::sign` and `sign_jwt` that without `with_ttl` (or an `exp` claim) the token never expires, and that lenient verifiers accept it forever. A later opt-in `require_exp()` is additive. | XS |
| (b) Refuse by default | `sign` returns `InvalidArgument` naming `with_ttl` unless the claims carry `exp` or the caller chose `JwtOptions::without_expiry()`. | S; breaks the project's own exp-less release-token test (`tests/verify_jose.rs:909`), which then uses `without_expiry()` |
| (c) Required-TTL constructor | `JwtOptions::new(ttl)` plus `JwtOptions::no_expiry()` | S; same break, more churn in examples |

**Advocates:**
- M recommends **docs only**. Settled #86 keeps claim policy out of jose. Exp-less JWTs are
  legitimate (release statements, software statements). The recommended verifier rejects them
  anyway.
- U recommends **refusal with an escape hatch, Should-fix**. It is a silent security default in a
  crypto library, and changing it after release breaks callers silently.

**Recommendation:** (b). Settled #86 limits jose to signing and publishing; it does not address
safe signing defaults, and an explicit `without_expiry()` keeps every legitimate use one call away.
This is the only release where the safe default costs nobody anything.

If the maintainer prefers (a), it is still a Should-fix (DOCS), because docs.rs is frozen per
version.

### Resolved by the panel (no maintainer decision needed)

The consolidator suggested these as decisions. Both advocates agreed, so the panel settled them:

| Item | Panel outcome |
|---|---|
| R-2: refuse public-key KEKs by default in `EnvelopeAead`/`EnvelopeKeyring` | **No.** Public-key wrap is inherent hybrid-encryption behaviour, and refusal would break the only Azure standard-vault path. The docs fix is a Blocker. An opt-in (`require_private_wrap()` or a `KeySemantics` wrap-authority field) is additive later. |
| R-8: `Sync` supertrait on capability traits | **No.** Document `+ Sync` next to the README's generic example. Adding it later breaks only non-`Sync` implementors, and those are essentially nonexistent. |
| R-12: change the AWS JWT kid shape | **No.** `<name>.<key ARN>` follows settled #63, whose reason (distinct kids across alias repoints) holds. Fix the false rustdoc sentence. `with_kid_fn` is additive. |
| R-13 (CHALLENGE): opt-in gate for Managed HSM | **No.** The paths fail closed (`handles.rs:1477`, `framing.rs:207-210`), the uncertain semantics are already gated (`mhsm-hmac`), and settled #2 and #94 stand. |
| R-20 (CHALLENGE): hard retry deadline | **Not for 0.1.0.** The challenge is partly right: `Retry` does own a `SleepFn`, so the recorded "no timer" reason is overstated. But the soft deadline and a single owner of attempt timeouts remain defensible. Fix the false `interactive()` promise now; an `attempt_timeout` is additive. |
| R-4: seal `EncryptionContextAead` | **No.** Provided methods that default to `Unsupported` make future additions non-breaking. Sealing would remove test fakes. |
| R-5: unify credential vocabulary | **Not before 0.1.0.** Vendor-native names are a coherent policy. Renames can ship with deprecated aliases. |

---

## 4. Findings by severity

| Severity | Count |
|---|---|
| Blocker | 2 |
| Should-fix before 0.1.0 | 11 |
| 0.1.x | 30 |
| Later | 6 |
| Rejected | 6 |

Each entry lists its raw sources. The full mapping is in Appendix D.

### 4.1 Blocker

#### R-1. CHALLENGE: the AWS AAD mapping matches no Tink implementation → Decision D1

- **Sources:** CMP-RS-1, CMP-X-1, reported independently by both comparison lenses.
- **Evidence:**
  - anykms: `crates/anykms-aws/src/context.rs:27` (`AAD_CONTEXT_KEY = "anykms-aad"`) and `:59`
    (`URL_SAFE_NO_PAD`).
  - Tink Java: `AwsKmsAead.java:62-63,81-82`,
    `encryptionContext.put("associatedData", BinaryUtils.toHex(associatedData))`.
  - Tink Go: `tink-go-awskms aws_kms_client.go:114-122,141,183-184` (default `AssociatedData`) and
    `:217,242,264` (legacy constructors), plus `aws_kms_aead.go:59,76` (`hex.EncodeToString`).
  - tink-rust 0.3: `aws_kms_aead.rs:62,67` (`"additionalData"`).
- **Challenges:** settled #57 (PLAN App. A, §21 0.3, §23 Q7). Its reasons are naming constraints
  that `associatedData` meets equally.
- **Reversibility:** ONE-WAY. **Effort:** S.
- **Fix:** see D1, and settle R-50 alongside.
- **Judges:**
  - V CONFIRMED: no maintained Tink default matches. The finding's wording on Go's default was
    slightly garbled; Go actually defaults to `associatedData`.
  - M **change-now**: the recorded reasons never weighed interop, and this is the last moment the
    change costs S.
  - U **Blocker**: few users in six months, but the cost asymmetry is extreme.

#### R-2. Envelopes under an RSA (public-key) KEK can be forged by any holder of the public key; the docs describe the writer set as "anyone with encrypt on the KEK"

- **Sources:** SEC-1.
- **Evidence:**
  - V re-ran the forge experiment (a local RSA mock of the cloud wrap path):
    `FORGED envelope accepted: "999-99-9999 (attacker)"` and
    `FORGED envelope accepted by keyring (primary is symmetric): "attacker row"`.
  - Wrap paths: `crates/anykms-aws/src/handles.rs:1164-1176` and
    `crates/anykms-gcp/src/handles.rs:1769` call `rsa_oaep_sha256_encrypt` with the fetched SPKI.
  - Docs: `docs/envelope-format.md:118-120` and `crates/anykms-recipes/src/envelope.rs:18-21`
    ("anyone with `encrypt` on the KEK"); `docs/operations.md:341-346` (retirement advice built on
    revoking `encrypt`); `docs/operations-aws.md:43` ("RSA KEK | writers kms:GetPublicKey").
  - Azure standard vaults offer only RSA KEKs (`docs/operations-azure.md:14,21-22`).
- **Reversibility:** DOCS. U reclassified it from BREAKING, because the minimum fix fully restores
  correctness. **Effort:** XS–S.
- **Fix:**
  - Wherever the writer set is described, state that with a public-key KEK every holder of the
    public key is a writer, so the envelope gives confidentiality only, and AAD does not
    authenticate the writer. Places: envelope-format.md, the envelope module rustdoc, the recipes
    crate table, operations.md "Retiring envelope KEKs", operations-aws.md:43, and the
    operations-azure.md and operations-gcp.md:40 envelope notes.
  - Add to the retirement advice that a symmetric primary does not protect a keyring that keeps an
    RSA secondary.
  - Refuse-by-default was rejected (see "Resolved by the panel").
- **Judges:**
  - V CONFIRMED: reproduced. The cloud handles use the same wrap function.
  - M **docs-only, and the docs fix is a Blocker**: the forgery is real and the wording frames the
    boundary as an IAM permission.
  - U **Blocker (DOCS)**: a security-relevant misstatement that costs XS to fix.

### 4.2 Should-fix before 0.1.0

#### R-3. Recipe adapters expose the wrapped key as a public tuple field on exhaustive structs (C-STRUCT-PRIVATE)

- **Sources:** API-1.
- **Evidence:**
  - `crates/anykms-recipes/src/datakeys.rs:44-45`: `pub struct EmulatedDataKeys<K>(pub K);` with
    no constructor.
  - `:85` `KeyWrapDataKeys(pub K)` and `rewrap.rs:28` `ClientRewrap(pub K)`.
  - Core's `AeadKeyWrap<T>(T)` keeps its field private and offers `new`/`inner`/`into_inner`
    (`traits.rs:470`).
  - Tuple-constructor call sites: `anykms-azure/src/provider.rs:683`, `handles.rs:1567`,
    `conformance cases/recipes.rs:357`, and `docs/cloud/gcp.md:523`.
- **Reversibility:** BREAKING. **Effort:** XS.
- **Fix:** make the fields private and add `new`/`inner`/`into_inner` to all three. Update the
  azure, conformance and gcp.md call sites.
- **Judges:**
  - V CONFIRMED.
  - M **change-now**: settled #33 and core's own adapter set the pattern. The `std::num::Wrapping`
    precedent fits field-free semantics, but these adapters are likely to gain options.
  - U **Should-fix**: privatizing a field cannot be done additively, and it costs XS now.

#### R-6. Tracing contract: credential `kind()` values mix snake_case and kebab-case (scoped down)

- **Sources:** API-4, OPS-7. Brief lead 2.
- **Evidence:**
  - snake_case: `aws sts.rs:345` `"web_identity"`, `chain.rs:95` `"default_chain"`,
    `gcp service_account.rs:89`, `transit token.rs:322`.
  - kebab-case: azure `entra.rs:226` `"workload-identity"`, `:320` `"client-secret"`,
    `managed_identity.rs:233`, `cred/sdk.rs:81` `"azure-identity"`, and gcp `auth/gca.rs:12`
    `"google-cloud-auth"`. These are pinned by tests at `anykms-azure provider.rs:754-760`.
  - Every other stable label (`ErrorKind`/`Operation`/`PartKind::as_str`) is snake_case.
  - Secondary: the request span's `attempt` (credential refresh, 1 or 2; `anykms-http span.rs:149`)
    and the retry event's `attempt` mean different things. The `anykms retry` event carries no
    `resource` (`anykms-core retry.rs:560-569`).
- **Reversibility:** BREAKING, for an observable contract. **Effort:** XS.
- **Fix (pre-release scope):**
  - Change the five literals to `workload_identity`, `client_secret`, `managed_identity`,
    `azure_identity` and `google_cloud_auth`, and update the pinned tests and the docs tables.
  - Document `kind()` as a stable snake_case label.
  - Leave the `ANYKMS_AZURE_CREDENTIAL` env values unchanged. M checked that `kind()` does not
    mirror them.
  - Document the two meanings of `attempt` rather than renaming.
  - Adding `resource` to the retry event is additive and belongs in 0.1.x.
- **Judges:**
  - V CONFIRMED.
  - M **change-now (casing only)**: no recorded decision chose kebab-case. Dashboards break
    silently on a later change.
  - U **Should-fix (casing only)**: string label values cannot be aliased.

#### R-11. `JwtOptions::new()` issues JWTs with no `exp` → Decision D2

- **Sources:** SEC-2.
- **Evidence:** see D2. Pointers: `jose.rs:352-376,443-448`, jwt-simple `claims.rs:624-629`,
  `examples/jwt_signing_jwt_simple.rs:56-57`.
- **Reversibility:** BREAKING (behaviour). **Effort:** S, or XS for docs only.
- **Fix:** D2 option (b). The minimum is option (a).
- **Judges:**
  - V CONFIRMED: jsonwebtoken requires `exp` by default, so the exposure is limited to lenient
    relying parties.
  - M **docs-only**: legitimate exp-less tokens exist, and #86 keeps claim policy out of jose.
  - U **Should-fix (refuse, with an opt-out)**: a silent security default, cheap now.

#### R-12. The jose rustdoc says AWS keys use the bare key name; AWS kids and tags actually carry the full key ARN (scoped to DOCS)

- **Sources:** SEC-6, P2-1. Brief lead 6.
- **Evidence:**
  - `crates/anykms-recipes/src/jose.rs:9-11` says "(e.g. AWS KMS) use the bare key name". That is
    wrong for AWS asymmetric and HMAC keys, whose `KeyVersion` is the ARN (settled #63,
    `operations-aws.md:116-118`).
  - Live floci JWKS:
    `"kid":"jwt.arn:aws:kms:us-east-1:000000000000:key/d726a41d-66fe-4204-82c1-6cc92d20af67"`.
  - HMAC API token on AWS: 177 characters, against 78 on transit.
  - `JwsHeader::with_field` refuses `kid` (`jose.rs:275`).
- **Reversibility:** DOCS. The kid derivation stays, per "Resolved by the panel". **Effort:** XS.
- **Fix:**
  - Correct jose.rs:9-11.
  - Add a sentence in operations-aws.md that AWS kids and `AKT` tags embed the key ARN (account,
    region, key UUID), with the compact `as_bytes()` + `Tag::from_parts(alg, None, ..)` pattern
    for tags.
  - `JwtSigner::with_kid_fn` is 0.1.x.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only**: the kid follows settled #63 and its recorded reason. The doc error must be
    fixed, because docs.rs is frozen per version.
  - U **Should-fix (DOCS)**: keep the kid shape; the remedy for anyone who dislikes it is additive.

#### R-14. No disclosure route in the repo, no yank procedure for a lockstep release, no supported-versions statement (scoped down)

- **Sources:** SEMVER-1, SEC-3.
- **Evidence:**
  - No `SECURITY*` file in the repo. `.github` holds only `dependabot.yaml` and the workflows.
  - `docs/releasing.md` has no yank, advisory or RustSec step.
  - The README carries a Scorecard badge (`README.md:4`).
- **Mitigation the chair checked:** the account-level `sagikazarmark/.github` repository has a
  `SECURITY.md` (809 bytes, `gh api repos/sagikazarmark/.github/contents/SECURITY.md`). It routes
  reports to GitHub's private "Report a vulnerability" button and applies to every public repo of
  the account that lacks its own. Private vulnerability reporting still has to be enabled on
  `sagikazarmark/anykms`, which does not exist yet.
- **Reversibility:** DOCS. **Effort:** XS.
- **Fix:**
  - Add a releasing.md step: enable private vulnerability reporting when the repository goes
    public.
  - Add a "Broken or vulnerable release" section: yank the whole lockstep `0.1.N` set, publish
    `N+1`, file a RustSec advisory.
  - Optionally add a repo-local `SECURITY.md` that says "latest 0.1.x only".
  - The consolidated `docs/security-model.md` is 0.1.x.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only, downgrade**: the disclosure channel exists at account level; what remains is XS.
  - U **Should-fix (SECURITY.md plus yank section only)**: the first day researchers look is right
    after publish.

#### R-15. A one-command publish of 10 new crates hits crates.io's new-crate rate limit

- **Sources:** SEMVER-2.
- **Evidence:**
  - crates.io `src/rate_limiter.rs` (fetched by V): `LimitedAction::PublishNew => 10 * 60` with
    `default_burst ... PublishNew => 5`. A `publish_rate_overrides` table exists.
  - `docs/releasing.md:57-61` runs a single `cargo publish --workspace --exclude anykms-testkit
    --locked`.
  - None of the 10 names is on crates.io.
- **Reversibility:** DOCS. **Effort:** XS.
- **Fix:** either ask help@crates.io for a temporary override before release day, or document
  dependency-order batches (5, then one every 10 minutes, facade last) and how to resume with
  `--exclude` or `-p`.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only, must land before release day**.
  - U **Should-fix**: certain to bite on the first publish.

#### R-16. docs.rs metadata: anykms-aws leaves out `sdk-credentials`, so docs.rs has no `SdkCredentials`

- **Sources:** SEMVER-8, DOCS-2.
- **Evidence:**
  - `crates/anykms-aws/Cargo.toml:117` lists `[tracing, http2, rsa-aws-lc-rs, rsa-rustcrypto,
    rustls-aws-lc-rs, rustls-ring]`. `sdk-credentials` is declared at `:48` but not listed.
  - `SdkCredentials` sits behind `cfg(feature = "sdk-credentials")` (`credentials/mod.rs:37,46`).
  - README.md:363, operations-aws.md:166-170 and CHANGELOG.md:95-96 send users to it.
  - Only `anykms` and `anykms-recipes` enable `doc_cfg`.
  - The facade's inlined items show foreign feature names, for example `anykms::azure::rustls`
    items read "crate feature std".
- **Reversibility:** DOCS, frozen per published version. **Effort:** XS.
- **Fix:**
  - Pre-release: add `sdk-credentials` to the list. In the same pass, add
    `#![cfg_attr(docsrs, feature(doc_cfg))]` to every published `lib.rs`.
  - Add a release step that builds each crate's docs with its docs.rs metadata.
  - Facade badge naming and `#[doc(no_inline)] pub use rustls` are 0.1.x polish.
  - The hand-written list exists because `__test-fixtures` is a `compile_error!` in release builds,
    so `all-features` cannot be used.
- **Judges:**
  - V CONFIRMED.
  - M **change-now**: a one-word edit now, or a 0.1.1 release later.
  - U **Should-fix**: it hides the headline feature of the last merge.

#### R-17. The pending external review of envelope v1 is invisible where users adopt `EnvelopeAead`

- **Sources:** SEC-4.
- **Evidence:**
  - `grep -i 'review|pending|long-lived'` finds no hits in `crates/anykms-recipes/src/envelope.rs`,
    `lib.rs`, `crates/anykms/src/lib.rs` or the recipes README.
  - `envelope.rs:9` promises only "every future release decrypts v1".
  - The caveat appears only at README.md:537-545, envelope-format.md:3-8 and CHANGELOG.md:230.
  - The quick start (README.md:59-79) encrypts an SSN with `EnvelopeAead`.
- **Challenges:** none. This accepts settled #55 and makes its gate visible to users.
- **Reversibility:** DOCS. **Effort:** XS.
- **Fix:**
  - Add a one-line Status note to the envelope module rustdoc, the `EnvelopeAead`/`EnvelopeKeyring`
    docs, the recipes README and the facade's recipes section: "v1 is frozen and always decrypts;
    external review pending; not yet recommended for long-lived data."
  - Say how promotion will be announced.
  - The quick start can link to it; its keys are ephemeral.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only, before 0.1.0**: a gate adopters cannot see does not gate anything.
  - U **Should-fix**: rows stored before the note reaches docs.rs were written without informed
    consent.

#### R-19. The README's error-to-HTTP prose contradicts `Error::class()`; caller-class errors on stored ciphertexts are mapped to 400

- **Sources:** P1-1, P4-1, found independently by two personas.
- **Evidence:**
  - README.md:496-501 lists the `retry_hint()` check first, gives a `CachedVerifier` rejection as
    the 503 example, and says `class()` returns the cases "in that order".
  - `crates/anykms-core/src/error.rs:571-581` checks `is_caller_error()` first, and
    `docs/operations.md:463-468` agrees with the code.
  - P4 test: `invalid_argument(..).with_retry_hint(500ms)` gives `class Caller`.
  - P1 repro: a stored row below `min_decryption_version`, a corrupt row and a swapped row all
    returned 400.
- **Challenges:** none. Kind-only classification (settled #46/#47) is unchanged.
- **Reversibility:** DOCS. The README is the facade's crates.io page. **Effort:** XS.
- **Fix:**
  - Reorder the sentence (caller, hinted, retryable, config) and move the `CachedVerifier` example
    out of the 503 clause.
  - Add one sentence: 400 applies when the input came from the request. A caller-class error on
    the application's own stored ciphertext is a data-integrity 500 and should alert.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only, before publish**: the prose steers readers into what settled #48 forbids.
  - U **Should-fix**.

#### R-20. CHALLENGE (partly upheld): `RetryPolicy::interactive()` promises "about 2 s" but takes 10 s against a hanging server (scoped to DOCS)

- **Sources:** OPS-2.
- **Evidence:**
  - V re-ran the experiment against a TCP listener that accepts and never answers:
    `interactive() (deadline 2s): Err("... timeout: request timed out") after 10.002864875s` and
    `default (deadline 15s): Err(...) after 20.225210084s`.
  - `crates/anykms-core/src/retry.rs:191-193` ("A struggling backend then costs a request about
    2 s") and `docs/operations.md:470-474` repeat the promise.
  - The module-level "Deadline scope" section (`retry.rs:58-65`) documents the soft semantics
    correctly.
- **Challenges:** settled #29 ("Retry has no timer to cancel an attempt"). Retry does own a
  `SleepFn` (`retry.rs:85,323`), so that reason is overstated. The cancellation-safety and
  single-owner reasons hold.
- **Reversibility:** ADDITIVE for code; the pre-release part is DOCS. **Effort:** XS for the docs.
- **Fix:**
  - Pre-release: state the worst case in the `interactive()` rustdoc and operations.md: the
    deadline plus one in-flight attempt, up to the provider's `request_timeout` (10 s by default),
    plus any credential wait. Tell request-path users to lower `request_timeout` or wrap the call
    in `tokio::time::timeout`.
  - 0.1.x: an optional `attempt_timeout` on the non-exhaustive `RetryPolicy`. V's caveat:
    `instant_sleep()` returns immediately, so racing the `SleepFn` naively would cancel every
    attempt in tests.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only**: keep the soft semantics; the false promise is indefensible.
  - U **Should-fix (docs), code 0.1.x**.

#### R-47. `rewrap_local` docs say it "vouches for the envelope", but it detects neither swapped rows nor corrupted payloads (upgraded from 0.1.x)

- **Sources:** P1-6.
- **Evidence:**
  - `envelope.rs:31` and `:586-590`: "Use `rewrap_local` when a successful rewrap must also vouch
    for the envelope (e.g. a migration that reports corrupted rows)".
  - The commitment check covers the DEK only (`envelope.rs:412-421`).
  - V's test: `rewrap_local of row-1 envelope stored in row 6: ok=true` and
    `rewrap_local of payload-corrupted envelope: ok=true`. Decrypting either then gives
    `DecryptFailed`.
- **Reversibility:** DOCS. **Effort:** XS.
- **Fix:** say that `rewrap_local` checks the key commitment and that the DEK unwraps; it never
  sees the AAD or the payload. To verify rows, decrypt each one with its own AAD.
- **Judges:** V CONFIRMED. V also found it broader than claimed: payload corruption is not caught
  either.
- **Chair:** upgraded because the rustdoc's own example is false in the integrity-relevant
  direction, docs.rs is frozen per version, and the fix belongs in the same pass as R-2.

### 4.3 0.1.x

These need the Verifier alone, unless noted. Where marked **pre-tag**, the item is XS and the
chair recommends folding it into the release commit, but it does not gate the release.

#### R-7. anykms-recipes names its RSA-backend features `aws-lc-rs`/`rsa`; backends and facade use `rsa-aws-lc-rs`/`rsa-rustcrypto` (downgraded from Should-fix)

- **Sources:** API-5. **Class:** ADDITIVE, via feature aliases. **Effort:** XS.
- **Evidence:**
  - `crates/anykms-recipes/Cargo.toml` (`aws-lc-rs = ["dep:aws-lc-rs"]`, `rsa = ["dep:rsa",
    "dep:sha2"]`) against the forwards at `anykms-aws/Cargo.toml:37-38`,
    `anykms-gcp/Cargo.toml:28-29` and `anykms-azure/Cargo.toml:30-31`.
  - The bridge feature names also differ: `sdk-credentials` on aws, `google-cloud-auth` and
    `azure-identity` on gcp and azure.
- **Fix:** add `rsa-aws-lc-rs`/`rsa-rustcrypto` on recipes, keep the old names as aliases, and
  remove them in 0.2.
- **Judges:**
  - V CONFIRMED.
  - M **change-later**: features can be aliased.
  - U **0.1.x**: only direct recipes users see the mismatch.

#### R-8. Capability traits require `Send` but not `Sync` (downgraded from Should-fix to DOCS)

- **Sources:** API-6. **Class:** DOCS. **Effort:** XS.
- **Evidence:** V reproduced it with `spawn_arc<K: Aead + 'static>(k: Arc<K>)`, which fails with
  `error[E0277]: K cannot be shared between threads safely` and
  `help: consider further restricting type parameter K with trait Sync`. The README shows the
  generic `seal<A: Aead + ?Sized>` without `Sync` (README.md:629-631).
- **Fix:** add `+ Sync` and one sentence next to the README's generic example, and record the
  choice.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only**.
  - U **0.1.x (DOCS)**: rustc names the fix, and the shared-state path the README teaches is
    already `Sync`.

#### R-18. FIPS scope is undocumented and narrower than README.md:380 suggests (downgraded from Should-fix)

- **Sources:** CMP-RS-2, CMP-X-3, SEMVER-6. **Class:** DOCS, with additive code later.
  **Effort:** XS.
- **Evidence:**
  - README.md:378-383 contains "(e.g. a FIPS build)" in the TLS-provider bullet.
  - No `fips` feature exists (`grep -rni fips crates/*/Cargo.toml` finds nothing).
  - The envelope uses `aes-gcm`, `hkdf` and `sha2`. SigV4 uses `sha2` and `hmac`
    (`anykms-aws/Cargo.toml:65-66`). aws-lc-rs is built without `fips`.
  - The process-default lookup sees only providers installed through rustls 0.23
    (`anykms-http/src/tls.rs:35-48`), and `rustls 0.24.0-dev.1` is on crates.io.
- **Fix:**
  - Add a "FIPS scope" paragraph: KMS operations run in the KMS. TLS follows a FIPS provider only
    when it is configured or installed through the re-exported rustls 0.23. Envelope, SigV4 and
    local verification are not FIPS-validated.
  - Qualify the "(e.g. a FIPS build)" phrase **pre-tag**.
  - Later: a `fips` feature and a strict no-fallback opt-in.
- **Judges:**
  - V CONFIRMED, with a nuance: the README sentence is scoped to TLS.
  - M **docs-only, do now**.
  - U **0.1.x**: not most users. Its audience is regulated adopters, who audit primitives directly.

#### R-21. README and guide snippets are not compiled in CI; the GCP placeholder `projects/p` is refused (downgraded from Should-fix)

- **Sources:** DOCS-1. **Class:** DOCS. **Effort:** XS for the placeholder, S for the CI gate.
- **Evidence:**
  - README.md:226 and `crates/anykms-gcp/README.md:17` use `gcp-kms://projects/p/...`.
  - `anykms-gcp/src/uri.rs:78-79,157-158` requires 6–30 characters and returns
    `invalid GCP project ID`.
  - No `include_str!` of a README appears in any `lib.rs`. The bridge snippets are ```` ```ignore ````.
- **Fix:** use `projects/my-project` **pre-tag**. Add a test target holding the README snippets
  verbatim, and a compile-only check for the bridge snippets.
- **Judges:**
  - V CONFIRMED.
  - M **docs-only**: the snippet needs real cloud resources anyway.
  - U **0.1.x**: this is not the quick start, which is local and works.

#### R-22. README "Public dependencies" omits the SDK bridge crates and anykms-http's public deps; semver-checks cannot catch public-dep majors

- **Sources:** SEMVER-5, DOCS-3. Brief lead 1. **Class:** ADDITIVE/DOCS. **Effort:** S.
- **Evidence:**
  - README.md:662-676.
  - Signatures: `SdkCredentials::new(impl aws_credential_types::...::ProvideCredentials)`,
    `Credentials::google_cloud_auth(google_cloud_auth::credentials::AccessTokenCredentials)`, and
    `AzureIdentity::new(Arc<dyn azure_core::credentials::TokenCredential>)`.
  - anykms-http exposes `http`, `rustls-pki-types` and `tracing::Span`.
- **Fix:**
  - Add the rows **pre-tag** (XS).
  - Configure Dependabot to ignore majors of public dependencies.
  - Record that rustls 0.24 means anykms 0.2.
- **Judge:** V CONFIRMED. V notes that Dependabot does not offer pre-releases, so the rustls risk
  arrives with 0.24 stable.

#### R-23. `google-cloud-auth = "1"` is too low; the bridge needs ≥ 1.3.0

- **Sources:** SEMVER-3. **Class:** ADDITIVE. **Effort:** XS, **pre-tag**.
- **Evidence:** `crates/anykms-gcp/Cargo.toml:62`. V's scratch crate with `=1.2.0` gave
  `error[E0432]: unresolved import google_cloud_auth::credentials::AccessTokenCredentials`;
  `=1.3.0` builds.
- **Fix:** `version = "1.3"`.
- **Judge:** V CONFIRMED.

#### R-24. CHALLENGE: lockstep plus a blocking semver job make anykms-http's "may change in minor releases" unenforceable

- **Sources:** SEMVER-4, SCOPE-1. **Class:** DOCS/policy. **Effort:** S.
- **Evidence:**
  - `grep -c anykms_http` over the other crates' API listings gives 0.
  - `anykms-http/src/lib.rs:3-5`; `Cargo.toml:24` (caret); `ci.yaml:665-738`.
- **Challenges:** settled #4, #10 and #11. The lockstep reason ("core breaks are backend breaks")
  does not hold for a crate whose types never cross a backend's API.
- **Fix:**
  - Version anykms-http on its own track after publish, which caret requirements allow.
  - Make its semver entry non-blocking, and add a CI guard that no `anykms_http` path appears in
    another crate's public API.
  - Do **not** apply this to anykms-conformance. V counted 71 `anykms_core` references in its
    public API, so it is coupled to core.
- **Judge:** V CONFIRMED. The chair keeps it low: the remedy is still available after publish.

#### R-25. No policy on whether a 0.1.x patch may add a conformance `Feature`

- **Sources:** SEMVER-7, P3-6. **Class:** DOCS. **Effort:** XS.
- **Evidence:** `anykms-conformance/src/fixture.rs:22-32` (an undeclared feature "fails that
  case"; `#[non_exhaustive] pub enum Feature`) and README.md:23-24.
- **Fix:** state that new `Feature`s and cases land only in `0.(x+1)`, and put the stability
  caveat into the rustdoc.
- **Judge:** V CONFIRMED.

#### R-26. Stability policy gaps: no MSRV-bump rule, an over-broad resolver claim, no rule on changing defaults

- **Sources:** SEMVER-9, CMP-RS-3. **Class:** DOCS. **Effort:** XS.
- **Evidence:** V reproduced on Rust 1.91. An edition-2021 package locks `aws-credential-types
  1.3.0`, which needs 1.94.1. An edition-2024 package locks 1.2.13. Compare README.md:546-548.
- **Fix:** "MSRV and default values change only in a 0.x minor release, listed in the CHANGELOG".
  Qualify the resolver note and give the `cargo update --precise` workaround.
- **Judge:** V CONFIRMED.

#### R-27. Library authors are not told to depend on anykms with `default-features = false`

- **Sources:** SEMVER-10. Brief lead 4. **Class:** DOCS. **Effort:** XS.
- **Evidence:** `crates/anykms/Cargo.toml:15` defaults. `rsa-aws-lc-rs`, `recipes` and `tokio`
  are unconditional; the `rustls-*` and `gcp-service-account-key` defaults are weak (`?`)
  features. README.md:384-403 is written for applications only.
- **Fix:** a "For library authors" note.
- **Judge:** V CONFIRMED, with that weak-feature nuance.

#### R-29. The workspace accepts zeroize 1.8–1.9.0, whose `Zeroizing` `Debug` prints decrypted plaintext

- **Sources:** SEC-5. **Class:** ADDITIVE. **Effort:** XS, **pre-tag**.
- **Evidence:**
  - `Cargo.toml:29` (`"1.8"`) and `Cargo.lock:4385-4386` (1.9.0).
  - V's test: `{:?}` of `Zeroizing::new(b"SECRET".to_vec())` prints
    `Zeroizing([83, 69, 67, 82, 69, 84])` on 1.9.0 and `Zeroizing { .. }` on 1.9.1.
  - `decrypt`, `decrypt_utf8` and `unwrap_key` return `Zeroizing`.
- **Fix:** require `"1.9.1"`, update the lockfile, and add a canary test.
- **Judge:** V CONFIRMED. It needs a user mistake, but the fix costs minutes.

#### R-30. The shared credential cache holds its lock across the token fetch: failures serialize and refresh-ahead blocks valid-token holders

- **Sources:** OPS-1. **Class:** ADDITIVE. **Effort:** S.
- **Evidence:**
  - `crates/anykms-http/src/credentials.rs:230,249,274`. The module doc (`:6-8`) promises callers
    "share its result", which is false for failures.
  - V re-ran the experiments. 8 callers on a source that fails after 1 s took 1.0, 2.0 … 8.0 s.
    The real AWS provider with no credentials took 1.08–5.09 s. Every caller waited about 2 s
    behind a refresh-ahead fetch.
  - Transit shares failures for 5 s (`anykms-transit/src/auth.rs:60-61,533-540`).
- **Fix:** true single-flight, short failure caching, and non-blocking refresh-ahead.
- **Judge:** V CONFIRMED. V notes that the cited `shared.md` lines do not state the decision; the
  contradicted doc is `credentials.rs`. The chair puts this first among the 0.1.x items: it has
  the highest operational impact on the default path.

#### R-31. A registry `RetryLayer` shares one budget across all backends; refused or exhausted retries are invisible

- **Sources:** OPS-3, P4-3. **Class:** ADDITIVE, with docs now. **Effort:** S.
- **Evidence:**
  - `retry.rs:311-327` (one budget per layer) and `:556-557` (a refused withdraw returns with no
    event).
  - README.md:558-561 and operations.md:122-127 say "per-backend bound".
  - V's run: a healthy key with one transient fault per call failed 20/20 once another key drained
    the budget.
- **Fix:** correct the docs wording **pre-tag**. Later, a budget per `LayerCx::backend()`, an
  `anykms retry suppressed` event, and an attempts or stop-reason accessor on `Error`.
- **Judge:** V CONFIRMED. The sharing itself is documented at `retry.rs:317`; the defect is the
  "per-backend" wording.

#### R-32. `ObserveLayer` and request spans record nothing for cancelled calls

- **Sources:** OPS-4. **Class:** ADDITIVE. **Effort:** S.
- **Evidence:** `observe.rs:165-179` reports only after `call.run().await`. `span.rs:160-184`. V's
  run: 3 cancelled calls produced 0 events.
- **Fix:** a drop guard that reports a cancelled outcome with `is_ok() == false`, and
  `outcome=cancelled` on spans.
- **Judge:** V CONFIRMED.

#### R-33. CHALLENGE: `with_default_providers()` fails the whole registry when the system trust store is empty, even for a Vault-only deployment

- **Sources:** OPS-5. **Class:** ADDITIVE. **Effort:** S.
- **Evidence:**
  - V's run with `SSL_CERT_FILE=/dev/null`: `ERR: aws configure: configuration: no trusted CA
    certificates (system roots unavailable and no ca_pem)`. The normal run gave
    `ok; skipped=["azure"]`.
  - `anykms-aws/src/client.rs:70-78` and `anykms-http/src/tls.rs:243-250`.
  - The facade rustdoc says "does no I/O" (`crates/anykms/src/lib.rs:126`).
- **Challenges:** settled #72 (D2). The roots failure in `build()` was deliberate
  (`docs/cloud/shared.md` P1-12), but the "no I/O" wording is false, and an unused backend should
  not block the registry.
- **Fix:** in the facade defaults, turn a cloud TLS-root failure into a `SkippedProvider`, and fix
  the wording.
- **Judge:** V CONFIRMED.

#### R-35. HTTP backends panic outside a tokio runtime; no doc shows a synchronous caller

- **Sources:** OPS-8, P4-2. **Class:** ADDITIVE. **Effort:** XS.
- **Evidence:**
  - V's run: `panicked ... there is no reactor running, must be called from the context of a
    Tokio 1.x runtime`, raised inside `anykms_http::client::send`.
  - `grep try_current` finds nothing.
  - A `current_thread` runtime does 20 round trips in 0.20 s.
- **Fix:** check `Handle::try_current()` in `anykms-http` `send` and return `Configuration`. Add a
  "From synchronous code" README snippet.
- **Judge:** V CONFIRMED.

#### R-36. Rustdoc landing pages don't say when to use each crate; the conformance caveat and the facade features table exist only in READMEs

- **Sources:** DOCS-6. **Class:** DOCS. **Effort:** XS.
- **Evidence:**
  - "facade" appears 0 times in the lib.rs of azure, conformance, core, gcp, http, local and
    recipes.
  - The facade's lib.rs table covers 7 of about 20 features.
- **Fix:** one "When to use this crate" paragraph per lib.rs, plus the conformance caveat and the
  facade features table.
- **Judge:** V CONFIRMED.

#### R-37. Stale statements after the credentials change

- **Sources:** DOCS-5. Brief lead 7. **Class:** DOCS. **Effort:** XS. The Cargo.toml comment is
  **pre-tag**, because it ships in the package.
- **Evidence (four confirmed):**
  - `operations-azure.md:239` still mentions `az` output, but the CLI credential was deleted in
    e816d86.
  - `operations-azure.md:202` says versionless support is "to verify with T3", but
    `research/azure-kv.md:21` records it as accepted.
  - `anykms-aws/Cargo.toml:43-47` says the SDK needs a higher MSRV, contradicting
    README.md:546-548.
  - `PLAN.md:18-20` says cloud backends follow "in 0.2", but §25 R1 ships them in 0.1.0.
- **Correction from V:** the fifth claim (GCP T1 / `publicKeyViewer`) is mischaracterized. It is
  still unverified (CHANGELOG.md:253-254), so operations-gcp.md:44 should say so rather than imply
  the probe checks it.
- **Judge:** V CONFIRMED (4 of 5).

#### R-39. Error-message gaps on typed URI parsing, GCP project rules, pasted Azure ids and local mismatches

- **Sources:** DOCS-7. **Class:** ADDITIVE. **Effort:** S.
- **Evidence:**
  - Typed openers return errors with `resource=None`, because `TransitKeyRef::parse(&uri)?` runs
    before `with_resource` (`transit provider.rs:144,148`; `aws provider.rs:176`).
  - `azure-kv://https://...` gives `invalid port`.
  - A pasted `https://contoso.vault.azure.net/keys/...` gives `no provider registered for scheme
    "https"`.
  - Local mismatch errors name no key kind (`anykms-local handles.rs:135,327`).
- **Fix:** attach the URI on typed paths, state the rules in the messages, add the two Azure
  hints, and name `LocalKeyKind`.
- **Judge:** V CONFIRMED.

#### R-40. CI signals that cannot fail or go unseen

- **Sources:** SCOPE-2. Brief lead 9. **Class:** DOCS/process. **Effort:** S. The gate-list fix
  is XS and **pre-tag**.
- **Evidence:**
  - The LocalStack job reports success with every step skipped (runs 38308533656 and 38276318857),
    yet `releasing.md:49-52` lists it as a gate, and `credentials-plan.md:199-201` records it as
    passed.
  - The Floci job lacks `ANYKMS_FAIL_ON_SKIP` (3 IAM skips).
  - Scheduled CI was red from 2026-10-05 to 10-12; the fuzz fix landed in b5248df.
  - Scorecard fails with `Resource not accessible by integration`.
- **Fix:**
  - Drop LocalStack from the gate list, or make it fail without a token.
  - Set `FAIL_ON_SKIP` on Floci and declare the IAM cases n/a.
  - Add a failure notifier for scheduled runs.
  - Fix or remove Scorecard.
- **Judge:** V CONFIRMED. "Unnoticed" should read "noticed late".

#### R-41. CHALLENGE: the release commit has never run against a real cloud; gate the tag on one dispatched live run

- **Sources:** SCOPE-3. **Class:** DOCS/process. **Effort:** S.
- **Evidence:**
  - The live jobs require `github.repository == 'sagikazarmark/anykms'` (`ci.yaml:479-481,603-605,
    826-829`), and that repository does not exist yet.
  - The last live GCP and Azure probes (2026-10-12 15:20) predate e816d86 (22:34).
  - The ci.yaml diff touches no live job.
- **Challenges:** settled #2 and the CP §9 acceptance. The reviewer conceded that the live-path
  code changes are mechanical. The residual risk is the OIDC/variables wiring.
- **Fix:** after creating the public repo, `workflow_dispatch` the release commit and require the
  three live jobs green before tagging.
- **Judge:** V CONFIRMED (facts).

#### R-43. README quick start puts the 15 s background retry policy on a registry that request handlers then use

- **Sources:** P1-2. **Class:** DOCS. **Effort:** XS, **pre-tag**.
- **Evidence:**
  - README.md:99-101, 130 and 218 all use `.layer(anykms::retry_layer())`.
  - `grep interactive README.md` finds nothing.
  - V's run against `VAULT_ADDR=http://127.0.0.1:1`: `default: 6.75s` against `interactive: 130ms`.
- **Fix:** one line showing `retry_layer().with_policy(RetryPolicy::interactive())` for
  request-serving registries. Pair it with R-20.
- **Judge:** V CONFIRMED.

#### R-44. KEK rotation and retirement tooling gaps

- **Sources:** P1-3, P4-4, P3-5. **Class:** ADDITIVE. **Effort:** S.
- **Evidence:**
  - `envelope.rs:820-824`: `rewrap_to_primary` leaves older primary versions alone.
  - The `EnvelopeKeyring` API listing has no `primary`/`kek_ids` accessors.
  - `dynamic.rs:1596-1600` returns `unsupported: key does not support rewrap` without mentioning
    `rewrap_local`.
  - `operations.md:340-346` gives no completion check. Leftover rows fail as caller-class
    `DecryptFailed` (`envelope.rs:792-806`, `error.rs:185`).
- **Fix:**
  - `rewrap_current` on `EnvelopeAead` and `EnvelopeKeyring` (server rewrap, else local).
  - `EnvelopeKeyring::primary_id()`/`kek_ids()`.
  - A documented completion scan via `Envelope::parse().kek_id()`.
  - An `Unsupported` message that names `rewrap_local`.
- **Judge:** V CONFIRMED.

#### R-46. `DefaultProviders::skipped()` lists features the application never enabled, with no structured reason

- **Sources:** P1-5. **Class:** ADDITIVE. **Effort:** XS.
- **Evidence:** `crates/anykms/src/lib.rs:222-291,298-320`; README.md:126-129. A transit-only app
  prints three "feature is not enabled" lines.
- **Fix:** a `#[non_exhaustive]` `SkipCause` accessor (`FeatureDisabled`/`NotConfigured`/
  `OptedOut`), and filter on it in the README snippet.
- **Judge:** V CONFIRMED.

#### R-48. JWKS publishing guidance for rotation

- **Sources:** P2-2, P2-3. **Class:** ADDITIVE, with docs. **Effort:** S. The docs part is XS and
  worth doing **pre-tag**.
- **Evidence:**
  - P2's rotate log, after an alias repoint:
    `active.jwks() now: [<new ARN>]` and
    `RP(active.jwks only) verifies t1: Err("unknown kid jwt.arn:...2bac54c0...")`.
  - Transit: `RP(cached j1) verifies t2: Err("unknown kid jwt.2")`.
  - `jose.rs:201-221` publishes one key. Only operations-gcp.md:178-182 has a rotation recipe.
- **Fix:**
  - A per-backend rotation section and a "cache the JWKS" sentence.
  - Additive: `jose::jwks_union` / `JwtSigner::also_publish`, and optionally `cached_jwks(ttl)`.
- **Judge:** V CONFIRMED. The per-fetch request count comes from the docs, not a measurement.

#### R-49. Core's generic `preflight()` passes a key whose primary (write) version is disabled

- **Sources:** P3-1. **Class:** ADDITIVE. **Effort:** S.
- **Evidence:**
  - `anykms-core/src/dynamic.rs:1658-1686`: `check_preflight` reads only `info.state()`.
  - V's run: `generic preflight with primary version 2 Disabled: Ok(Some(KeyVersion("2")))`.
  - The requirement is stated at `conformance fixture.rs:84-93` and `traits.rs:183-185`.
- **Fix:** refuse a non-Enabled primary version in the fallback when `KeyInfo` lists one.
- **Judge:** V CONFIRMED. The opaque `AeadKey::preflight` doc promises only key-level state, so
  "fails conformance" applies only when a backend declares `PreflightState`.

#### R-50. The AWS AAD cap is enforced on Decrypt too, so "may only rise" needs a reader-first rollout

- **Sources:** CMP-X-2. **Class:** ADDITIVE. **Effort:** XS.
- **Evidence:** `context.rs:29-34` (the promise), `:43-58` (no operation exemption) and `:226-230`
  (a test asserts that Decrypt over the cap errors). `handles.rs:974-983,990-997`.
- **Fix:** apply the cap only to producing operations, decided together with D1.
- **Judge:** V CONFIRMED.

#### R-51. The backend-author contract is undocumented

- **Sources:** P3-2, P3-4. **Class:** DOCS. **Effort:** S.
- **Evidence:**
  - `traits.rs:353-356` (`verify_mac`: "Failure is `Err(VerificationFailed)`") against
    `conformance cases/mac.rs:101-112`, which expects `InvalidArgument` for a tag of another
    algorithm.
  - The `Provider` docs have no Errors section (`provider.rs:311-355`).
  - The conformance README is 36 lines, and there is no example.
- **Fix:** "Errors" sections for implementers, plus a `minimal_backend` example of about 250 LOC.
- **Judge:** V PLAUSIBLE. The ParseUri rule *is* in the `Operation::ParseUri` rustdoc
  (`error.rs:222-226`), not only in the CHANGELOG; it is missing from the `Provider` docs.

#### R-53. local `Fault` cannot inject caller-class kinds, `Unauthenticated`, Retry-After or hints, or target one operation

- **Sources:** P4-5. **Class:** ADDITIVE. **Effort:** S.
- **Evidence:** `anykms-local/src/keyset.rs:50-84`: 8 struct variants with `pub times` and no
  variant-level `#[non_exhaustive]`. `inject_for_key` has no `Operation` parameter.
- **Fix:** `Fault::Kind{kind,times}`, `inject_error(Error, times)` and `inject_on(Operation, ..)`.
  The variant-level `#[non_exhaustive]` is the only piece that is cheaper before the tag.
- **Judge:** V CONFIRMED.

#### R-54. No translation from sigstore, Go CDK, Tink-hcvault or SOPS key URIs

- **Sources:** CMP-X-4. Brief lead 10. **Class:** DOCS. **Effort:** XS.
- **Evidence:**
  - V's run: `hashivault://mykey` and `openbao://mykey` both give `transit parse_uri:
    configuration: expected <scheme>://[alias]/<mount>/keys/<name>`.
  - The sigstore regex is `^(?:hashivault|openbao)://(?P<path>\w(([\w-.]+)?\w)?)$`.
  - The grammars are disjoint, so nothing is misrouted, and aliases or a translator can be added
    later.
- **Fix:** a "Key URIs from other tools" table, and a hint in the path-less `hashivault` error.
- **Judge:** V CONFIRMED.

### 4.4 Cheap items worth folding into the release commit

None of these gates the release. Each is XS and touches text or manifests that are frozen per
published version:

| Item | Change |
|---|---|
| R-23 | `google-cloud-auth = "1.3"` |
| R-29 | `zeroize = "1.9.1"` |
| R-37 | Fix the `anykms-aws/Cargo.toml:43-47` comment |
| R-21 | `projects/my-project` placeholders |
| R-43 | Show `RetryPolicy::interactive()` in the README for request-serving registries |
| R-18 | Qualify "(e.g. a FIPS build)" |
| R-22 | Add the public-deps rows |
| R-31 | Fix the "per-backend bound" wording |
| R-40 | Fix the release gate list |
| R-48 | Add a "cache the JWKS" sentence |

### 4.5 Later

| id | Title | Sources | Class | Reason for Later |
|---|---|---|---|---|
| R-5 | Credential vocabulary differs per backend; Azure's `TokenCredential` shadows `azure_core`'s | API-3 | BREAKING → ADDITIVE via aliases | V CONFIRMED. M **keep**: vendor-native naming is coherent, and bridge users never name both traits. U **0.1.x**: renames can ship with deprecated aliases. Unification is 0.2 material; add a short Azure docs note on the name clash in 0.1.x. |
| R-34 | Key-metadata caches are not single-flight | OPS-6 | ADDITIVE | V CONFIRMED (20 concurrent encrypts gave 20 metadata GETs), but the finding re-raises docs/review-plan.md 3.10 ("single-flight not added") without a CHALLENGE label. The new angle, the AWS DescribeKey quota, is UNVERIFIED. Revisit alongside R-30. |
| R-38 | No glossary; KEK expanded two ways; six names for handles | DOCS-4 | DOCS | V CONFIRMED. Polish. |
| R-45 | The local backend cannot back a persistent dev database | P1-4 | ADDITIVE | V PLAUSIBLE. The docs already say "vanish with the process ... unrecoverable" (README.md:67, `anykms-local/src/lib.rs:1-6`), and settled #91 covers the opt-in. What remains is a seeded-keys feature request. |
| R-52 | anykms-conformance offers two bridging styles | P3-3 | ADDITIVE | V CONFIRMED. Low impact: the suite fails loudly if parts are missed. Add builder-style bridges and deprecate the struct style in 0.2. |
| R-55 | The envelope v2 plan lacks a decrypt-side slot cap and a reader-first rollout rule | CMP-X-5 | DOCS | V CONFIRMED. The k-of-n point is already answered ("any one of which can decrypt"). This is v2 design material. |

---

## 5. Rejected

Kept here so they are not raised again.

| id | Title | Sources | Reason |
|---|---|---|---|
| R-4 | `EncryptionContextAead` is unsealed with only required methods (C-SEALED) | API-2 | The facts were CONFIRMED, but the premise ("every future addition is breaking") is false. A provided method that defaults to `Unsupported` is additive, which is the project's own pattern (PLAN §23 Q3, `Provider::data_keys`). Sealing would take away test fakes. M **keep**, U **0.1.x at most**. |
| R-9 | Cross-crate helpers (`rsa_oaep_sha256_encrypt`, `ecdsa_der`, `spki_key_type`, `pem_to_der`, Azure `env_credential_kind*`, `credential_from_env*`) published as user API | API-7 | **V REFUTED**: they are documented user API. `rsa_oaep_sha256_encrypt` is in the recipes table and CHANGELOG.md:72-74 for offline wrapping to GCP asymmetric-decrypt keys. It checks `MIN_RSA_BITS` and pins SHA-256, so it is not "misuse-prone". `env_credential_kind` replaced the removed `env_configured` (CHANGELOG.md:216), and `credential_from_env_with` is a documented entry point (operations-azure.md:115-117). M **keep**, U **Rejected**. `#[doc(hidden)]` remains available in any 0.1.x without a break. |
| R-10 | `AsymmetricKeyType::Rsa { bits }` lacks variant-level `#[non_exhaustive]` | API-8 | The facts were CONFIRMED, but no realistic future field exists: every KMS fixes e = 65537, and PSS-only is an algorithm or usage property. The enum is already `#[non_exhaustive]`, so a new variant is the additive escape hatch, and settled #33 is satisfied at the enum level. The attribute would forbid direct construction in the backend crates (31 sites) and in third-party backends. M **keep**, U **Later at most**. |
| R-13 | CHALLENGE: gate Managed HSM paths behind an opt-in | SCOPE-4 | The facts were CONFIRMED. Both advocates rejected the gate. Settled #2 records "no not-live-verified gating or banners", and #94 discloses the limitation (CHANGELOG.md:267-268). The uncertain semantics are already gated (`mhsm-hmac`, settled #81). The remaining paths use standard primitives and fail closed (`handles.rs:1477`, `framing.rs:207-210`). A gate would add a temporary API and a permanent env-var contract. Optional docs: tell MHSM adopters to run `anykms-conformance` against their pool before production. |
| R-28 | CI never checks a fresh dependency resolution | SEMVER-11 | **V REFUTED**: `.github/dependabot.yaml` runs a daily grouped cargo update, and its PRs run the full CI. Too-low lower bounds, as in R-23, are a minimal-versions problem that a fresh resolution would not catch either. |
| R-42 | "No GCP emulator" is out of date (floci-gcp, floci-az) | SCOPE-5 | **V REFUTED**: floci-gcp was evaluated and recorded in docs/cloud/gcp.md:570-576 (unverified fidelity, kept out of CI). That makes this a settled item re-reported without a CHALLENGE. floci-gcp also lists no MAC, Ed25519 or PSS support. Residual: floci-az advertises Managed HSM, while azure.md:753 says no emulator exists. That is worth a note when T13 is revisited. |

---

## Appendix A. Friction logs (condensed)

The personas worked black-box: READMEs, CHANGELOG, `docs/operations*.md`, the examples, the brief's
API listings and rendered rustdoc, with no crate sources. A shared-disk ENOSPC incident stalled
every persona for several minutes and took Docker down late in the run, which affected P2 Task 3
and P4 Task 4.

### A.1 P1: application developer (axum + SQLite, SSN column; local in dev, Vault in prod)

The app was `features = ["local", "transit"]`, axum 0.8 and rusqlite 0.37. About 40 of its ~310
lines touch anykms. Vault setup followed operations.md "Envelope KEKs need their own mount":

```sh
vault secrets enable -path=p1-envelope transit
vault write p1-envelope/config/keys disable_upsert=true
vault write -f p1-envelope/keys/app-kek type=aes256-gcm96
```

**Task 1, encrypt a column (4).**
- The README quick start plus `examples/field_encryption.rs` gave the whole design:
  `registry.key_wrap(uri)` → `EnvelopeAead::new("app-kek", kek)` → `encrypt(pt, aad)` →
  `to_base64()`.
- The first build had **zero errors**. Vault worked first run, including across a restart. That
  took 4 steps and about 10 minutes.
- Deliberate-mistake diagnostics, verbatim:

```
error[E0277]: `anykms::AeadKey` is not a key-wrapping key (`KeyWrap`)
   --> src/bin/mistakes.rs:8:45
    |
  8 |     let _env = EnvelopeAead::new("app-kek", kek)?;
    |                -----------------            ^^^ not a `KeyWrap`
    |                |
    |                required by a bound introduced by this call
    |
    = help: the trait `anykms::KeyWrap` is not implemented for `anykms::AeadKey`
    = note: open the KEK with `registry.key_wrap(uri)`, or adapt an AEAD key explicitly with `.into_key_wrap()` (wraps with empty AAD)
```

```
error[E0599]: no method named `encrypt` found for struct `EnvelopeAead<K>` in the current scope
   = help: items from traits can only be used if the trait is in scope
help: trait `Aead` which provides `encrypt` is implemented but not in scope; perhaps you want to import it
 2 + use anykms::Aead;
help: there is a method `dyn_encrypt` with a similar name
```

- Runtime misconfiguration messages all pointed at the fix:
  - `transit parse_uri [hashivault://p1-envelope/keys/app-kek-2]: configuration: expected <mount>/keys/<name>; the authority is a server alias, so use hashivault:///transit/keys/<name> (three slashes) for the default server`
  - `registry open [...]: configuration: no provider registered for scheme "hashivault" (transit: VAULT_ADDR/BAO_ADDR not set)`
  - `transit describe [...]: unauthenticated: token not accepted (http 403) (server: "permission denied")`
  - `configuration: no such mount or path (http 404) (server: <redacted 67 bytes, fp 1f981fcee5d0>)`
- Surprises:
  - After a dev restart, local keys are gone, giving
    `{"error":"decrypt_failed"} 400 ... local decrypt: decrypt_failed: envelope data key does not unwrap`.
    That is R-45.
  - `skipped()` printed three "feature is not enabled" lines. That is R-46.

**Task 2, rotate and rewrap (3).**
- A version rotation plus `if kek.supports_rewrap() { rewrap } else { rewrap_local }` worked
  first time: `rewrapped 3 rows, 0 already current`.
- Skipping current rows required the undocumented comparison
  `kek.describe().await?.primary_version()` == `envelope.ciphertext_version(&ct)?`.
- Moving to a second KEK needed `EnvelopeKeyring` **and** a separate `EnvelopeAead` over the
  primary, routed on `Envelope::parse(..).kek_id()`. Result:
  `RewrapReport { moved_kek: 4, moved_version: 1, current: 0, bad: [(5, "core decrypt: decrypt_failed: invalid base64 ciphertext")] }`.
  This is R-44.
- `rewrap_local` accepted a ciphertext copied from row 1 into row 6, despite "vouch for the
  envelope". That is R-47.

**Task 3, share the Registry (5).** `Registry` is `Clone + Send + Sync`; `State<AppState>`
compiled first time.

**Task 4, HTTP mapping (3).**

| Condition | README mapping | Note |
|---|---|---|
| `Fault::Throttled{times:1}` | 200 (retried) | correct |
| `Fault::Throttled{times:10}` | 503, no Retry-After | correct; 3 attempts in 0.13 s with `interactive()` |
| `Fault::PermissionDenied` | 500 | correct |
| stored row below `min_decryption_version` | **400** `key_version_unusable` | wrong: the client did nothing |
| stored row not base64 | **400** `decrypt_failed` | wrong: corrupt row |
| ciphertext copied to another row | **400** `decrypt_failed` | wrong: integrity incident |
| dev restart with local keys | **400** `decrypt_failed` | wrong |

With Vault unreachable, the default policy took **7.9 s** per request and `interactive()` took
**0.12 s** (R-43). The README order contradicts `class()` (R-19).

**Comparison: Tink Go.**
- Tink needs about 15 lines against anykms's about 40.
- Tink has a persistent dev keyset (`insecurecleartextkeyset`), no rewrap API, no KEK migration,
  no envelope key commitment and no error classification.
- Verdict: anykms is clearly better for production; Tink is better only for dev persistence.

### A.2 P2: platform or identity engineer (JWT issuer, JWKS, rotation, HMAC tokens; Vault + AWS on floci)

The app used the facade with `features = ["transit", "aws"]`, jsonwebtoken 11 (`rust_crypto`) and
axum 0.8. All four tasks were working 6 minutes after the first README read. **No compiler errors
in any task.**

**Task 1, issuer (5).**
- 73 lines, about 12 of them anykms.
- Vault header: `{"alg":"ES256","kid":"jwt.1","typ":"JWT"}`.
- AWS header: `{"alg":"ES256","kid":"jwt.arn:aws:kms:us-east-1:000000000000:key/d726a41d-66fe-4204-82c1-6cc92d20af67","typ":"JWT"}`.
  That kid is 79 characters, and the jose rustdoc says AWS uses the bare name (R-12).
- Preflight with the KMS down:
  `aws describe [aws-kms://arn:aws:kms:us-east-1:000000000000:alias/p2-jwt]: unavailable: connection refused`.

**Task 2, JWKS + jsonwebtoken (5).** README.md:286-296 worked verbatim:
`OK kid=jwt.1 claims=Claims { sub: "alice", ..., exp: 1791843993 }`.

**Task 3, rotation with overlap (3).**

```
Vault:
t1 kid=jwt.1 ; JWKS before rotation: ["jwt.1"]
t2 kid=jwt.2 ; JWKS after rotation: ["jwt.1", "jwt.2"]
  RP(cached j1) verifies t2: Err("unknown kid jwt.2")
  RP(j2) verifies t1 (overlap): Ok(())
JWKS after min_decryption_version=2: ["jwt.2"]
AWS (alias repoint, JwtSigner on the alias URI):
  active.jwks() now: [..45c2f1d6..]                          <- old key gone at the repoint
  RP(active.jwks only) verifies t1: Err("unknown kid jwt.arn:...2bac54c0...")
```

Rotation needed a hand-written 14-line JWKS union. Ending the overlap via `min_decryption_version`
was a guess (R-48).

**Task 4, HMAC tokens (4).**
- The token form was `p2_<16 random bytes>.<Tag::to_base64_url()>`.
- Vault: 78 characters. AWS: **177 characters**, embedding
  `arn:aws:kms:us-east-1:000000000000:key/...`.
- A forged token gives `verification_failed`, mapped to 401. Old tokens survive a transit rotation.

**Not completed:** counting KMS requests per JWKS fetch (services down during ENOSPC).

**Comparison: aws-sdk-kms directly.**
- About 90–120 lines and four more crates. You implement DER→P1363 yourself and get no error
  classes.
- You choose the kid. A Vault issuer would be a separate code path.
- Tink JWT keysets model "primary plus published non-primaries", which anykms's JOSE recipe lacks
  (UNVERIFIED).

### A.3 P3: library or backend author (toy third-party backend plus metrics layer)

The code was `toykms`: 424 LOC lib with AEAD and HMAC, a 136-LOC conformance test (about 45 lines
of feature declarations), a 90-LOC metrics layer test and a 48-LOC facade example.

**Task 1, provider plus conformance (4).** Compiler errors, verbatim; none came from anykms types
or bounds:

```
error: Cargo.toml: can't find `conformance` test at `tests/conformance.rs` or `tests/conformance/main.rs`. Please specify test.path if you want to use a non-default path.
```
```
error[E0405]: cannot find trait `Semantics` in this scope
   --> src/lib.rs:201:6
    |
201 | impl Semantics for ToyAeadKey {
    |      ^^^^^^^^^ not found in this scope
```

`Semantics` is not in the prelude. The third error was `E0034` (`aes_gcm::KeyInit` and
`hmac::Mac` both in scope), which was not anykms's fault.

| Run | Result | Next change |
|---|---|---|
| 1 | `24 passed; 446 failed`. The declarations trial: `undeclared feature: declare Feature::EmptyPlaintext, Feature::MinDecryptionVersion, ... in probe(); needed by 223 case(s)` | declared about 37 features |
| 2 | `45 passed; 4 failed`. `expected configuration from parse_uri, got configuration from open` and `preflight of a Aead key whose write version 1 was disabled: expected key_state_invalid, got success` | URI errors → `Operation::ParseUri`; wrote `impl Preflight` (R-49, R-51) |
| 3 | `49 passed; 0 failed; 421 ignored` | first success, AEAD only, about 60–75 min |
| 4 (HMAC added) | `77 passed; 8 failed`. `tag of another algorithm: expected invalid_argument, got verification_failed` | algorithm mismatch → `InvalidArgument` (R-51) |
| 5 | `85 passed; 0 failed; 385 ignored`, also with `ANYKMS_FAIL_ON_SKIP=1` | done |
| lie experiment | `the Aead handle declares no KeySemantics` and `capabilities Capabilities(AEAD) disagree with key_wrap (wraps: true)` | the messages point straight at the fix |

Other surprises:
- `Fixture` renders as `Send + Sync + 'static + Send` (cosmetic, from trait-variant).
- A third-party provider may claim a built-in scheme whose feature is off. That is undocumented.
- `EnvelopeAead::rewrap` on a KEK with no server-side rewrap fails with
  `toykms rewrap: unsupported: key does not support rewrap` (R-44).
- Two bridging styles exist (R-52).

**Task 2, metrics layer (5).**
- 40 LOC, which compiled and passed on the first build:
  `{ ("toykms","decrypt","decrypt_failed"): (1, 15.25µs), ("toykms","encrypt","ok"): (1, 40.333µs), ... }`.
- The ready-made `ObserveLayer` is documented in operations.md "Metrics" but not named in the
  README.

**Comparison: Go CDK `gocloud.dev/secrets`.**
- A toy Go CDK driver is well under 100 LOC; anykms's AEAD-only toy is 268 LOC.
- anykms's 470-case suite pins behaviour far more precisely and gives better feedback.
- The gap is documentation: the rules should be in the trait docs and a backend guide (Go API from
  memory, UNVERIFIED).

### A.4 P4: test author and ops engineer (unit tests, fault drills, sync CLI, KEK migration)

**Task 1, network-free unit tests (5).** 5/5 passed on the first run. Verbatim:

```
no opt-in: local open [local://default/kek]: configuration: local:// keys are ephemeral; enable them with LocalProvider::allow_ephemeral_local_keys()
bad base64: core decrypt: decrypt_failed: invalid base64 ciphertext
missing key: local wrap_key [local://default/nope]: not_found: key not found (kind NotFound)
moved row error: envelope decrypt: decrypt_failed: wrong key or AAD, or a malformed or tampered envelope
below min version: local unwrap_key [local://default/kek]: key_version_unusable: key version is below the minimum decryption version (kind KeyVersionUnusable)
```

A local key cannot be imported, so golden-ciphertext fixtures are impossible. That is by design
(settled #91).

**Task 2, fault injection (4).** 7/7 passed on the first run:

```
attempts: ["wrap_key throttled", "wrap_key throttled", "wrap_key ok"]
calls:    ["wrap_key ok"]
exhausted: local wrap_key [local://default/kek]: unavailable: injected fault class=Retryable(None) retry_after=None source=None
default policy: local wrap_key [local://default/kek]: timeout: injected fault, 6 attempts, virtual elapsed 6.627s   (start_paused)
budget: call 0: 6 attempts; call 1: 6 attempts; call 2..4: 1 attempt each (default budget cap 10 exhausted)
```

- Hinted, Retry-After, `DecryptFailed` and `Unauthenticated` faults need a hand-written fake
  (R-53).
- Exhausted, refused and first-attempt errors are indistinguishable (R-31).

**Task 3, synchronous CLI (3).**

| Mode | Result |
|---|---|
| one `current_thread` runtime, `rt.block_on` per op | works; 20 encrypt+decrypt in 0.20 s |
| a fresh runtime per call | works; 0.23 s |
| `futures_lite::future::block_on` | **panic** |

```
thread 'main' panicked at .../core/src/ops/function.rs:250:5:
there is no reactor running, must be called from the context of a Tokio 1.x runtime
backtrace:  5: tokio::time::sleep::sleep  10: anykms_http::client::send::{closure#0}  11: anykms_transit::client::send::{closure#0}  43: cli::main
```

That is R-35. `build()` outside a runtime works, but that is undocumented.

**Task 4, Vault→AWS migration (4, offline).**
- A cross-backend `EnvelopeKeyring` compiled first try. The live run reached only a dead Vault
  after the disk incident: `Unavailable ... op: Describe ... connection refused`, real 6.86 s.
- The offline run used local keys:

```
unmigrated row under new-only envelope: envelope decrypt: decrypt_failed: kek_id mismatch: the envelope names kek_id "vault-kek", this envelope is configured with "aws-kek" | class Caller
revoked old kek during backfill: Err("local unwrap_key [local://default/old-kek]: permission_denied: injected fault")
unknown kek_id in rewrap_to_primary: envelope rewrap: decrypt_failed: unknown kek_id: the envelope names kek_id "other-kek", the keyring has "vault-kek", "aws-kek" | class Caller
```

- `rewrap_to_primary` is idempotent and retries Throttled transparently.
- Leftover rows after retirement are caller-class, so they do not page anyone (R-44).
- The hinted caller error check (R-19):
  `hinted caller error: class Caller retry_hint Some(500ms)` and
  `hinted config error: class Hinted(500ms)`.

**Comparison.**
- Failure drills: anykms is better than aws-smithy-mocks and Tink. Tink's `fake-kms://` keysets
  allow committed fixtures (UNVERIFIED).
- Sync use: equal to the Rust SDKs, worse than Tink and go-kms-wrapping.
- KEK migration: clearly better than ESDK and Tink. anykms moves only the DEK, can mix backends in
  one ring, and is idempotent; the others re-encrypt the payload.

---

## Appendix B. Comparison matrices (Phase 3)

### B.1 Rust ecosystem (CMP-RS)

Compared, with versions and dates as of 2026-10-13:

| Crate | What it is |
|---|---|
| `aws-sdk-kms` 1.123.0 + `aws-config` 1.12.0 | official SDK |
| `google-cloud-kms-v1` 1.15.0 | official, GA since 2025-09 |
| `azure_security_keyvault_keys` 1.0.1 + `azure_identity` | official, GA since 2026-05 |
| `vaultrs` 0.8.0 | community |
| `kms-aead` 0.29.0 | **the closest analogue**: envelope AEAD over GCP, AWS, Azure, Vault and ring; one maintainer |
| `tink-*` 0.3.0 | unofficial Tink port, dormant, on rusoto |
| `aws-esdk` 1.2.4 | Dafny-generated |
| `asherah` 1.0.0 | synchronous |
| `rops` 0.1.7 | |
| `alloy-signer-aws`/`-gcp` 2.5.0 | |
| deprecated `rusoto_kms` and yoshidan `google-cloud-kms` | |

No other Rust crate offers capability-typed sign, MAC, key wrap and AEAD across several KMSs.

| Axis | Verdict | Evidence |
|---|---|---|
| Capability coverage | **better** than every multi-backend crate; **worse** than the SDKs on breadth (by design) | anykms: AEAD, data keys, rewrap, digest/message sign/verify, MAC, public keys, KeyWrap, describe on 4 backends plus local. `kms-aead`: envelope AEAD only. tink-rust: KMS AEAD on AWS/GCP. `aws-esdk`: envelope only. The SDKs expose admin, `AsymmetricDecrypt`, `RawEncrypt`, `GenerateRandom`, ECDH and secp256k1. Gaps users will ask for: secp256k1 (alloy-signer-aws, 3.9 M downloads; settled #44), PQC (#43), asymmetric decrypt (#37). All additive. |
| Key addressing | **better** than the Rust field, **equal** to Tink | Only tink-rust uses URIs: `aws-kms://arn:...`, `gcp-kms://`. anykms uses the same spellings. `kms-aead` uses typed refs; the SDKs use ids. anykms adds allowlists and an alias-not-address authority for Vault. Tink's `hcvault://<host>` carries an address. sigstore `hashivault://<keyname>` fails closed in anykms. `awskms`/`gcpkms`/`azurekms` aliases are additive (`Provider::schemes()` is a slice). **Gap: the AWS AAD mapping is not Tink's (R-1).** |
| Envelope format | **better** than kms-aead and Tink on safety and versioning; **worse** than ESDK on multi-KEK, interop and streaming | anykms v1: magic+version, HKDF key commitment, `kek_id` routing, strict parsing, a 4096-byte encrypted-DEK cap (the same as Tink Go), vectors. `kms-aead`: no commitment, no KEK id, no version tag until 0.29.0. Tink `KmsEnvelopeAead`: no version, no commitment, empty KEK AAD. ESDK: committing suite since 2.0 (DEK-only scope, matching anykms), multi-keyring, interop, framing. |
| Credentials | **worse** than the SDKs and kms-aead (full chains); **equal or better** on laziness and control | Built-in workload sources plus the bridges (`SdkCredentials`, `Credentials::google_cloud_auth`, `AzureIdentity`). `azure_identity` dropped `DefaultAzureCredential`. tink-rust is stuck on rusoto 0.48 and yup-oauth2 5. With the bridges, anykms reaches SDK parity. |
| Reliability | **better** than kms-aead and tink-rust; **equal or better** than the SDKs | One `RetryLayer`: equal jitter, deadline, Retry-After floor, a shareable token-bucket budget, nothing below it. AWS SDK: standard mode, 3 attempts. Azure SDK: 8 retries in clients *and* credentials. kms-aead inherits SDK retries. Describe and public-key caches, plus `CachingKeyWrap`. ESDK's encrypt-side caching CMM is absent (additive). |
| Errors | **better** for cross-backend decisions | 16 kinds, `ErrorClass`, `BackendDetail`, documented HTTP mapping. AWS `SdkError<OpError>`, GCP `gax::error::Error`, `azure_core::Error`, and kms-aead `{SystemError, NetworkError, EncryptionError}`. None classifies across vendors. |
| Testing | **better** | The local backend with rotation and per-key fault injection, a published conformance suite, and hand-written fakes via `AeadKey::new`. AWS `aws-smithy-mocks`; GCP `from_stub`; kms-aead a ring stand-in only. |
| Extensibility | **better** | Object-safe `Provider`, `Layer`/`Around`, a `part` catch-all, third-party conformance. kms-aead is generic, with no decorators or conformance. Tink has a `KMSClient` registry; ESDK keyrings and CMMs; SDK interceptors per vendor. |
| Runtime model | **equal** to the SDKs; **better** than tink-rust and asherah in async apps; **worse** for sync CLIs | Async, `Send` futures, injectable sleep and clock, no blocking API (#41). tink-awskms holds `Rc<RefCell<Runtime>>` plus `block_on` (not `Send`, panics in async). asherah has an internal runtime. |
| Cost to adopt | **better** | Unique normal deps: aws-sdk-kms+aws-config 164, google-cloud-kms-v1 178, azure keys+identity 135, vaultrs 117, aws-esdk 195, kms-aead (all KMS) 243. **anykms: 149 for all four backends**, 135 per cloud backend, 109 for transit. MSRV: anykms 1.91, AWS SDK 1.94.1, GCP 1.91, Azure 1.88. |
| Hygiene | zeroization **better**; FIPS **worse** | `zbuf` zeroizing bodies plus Debug/trace hygiene tests, where the SDKs use `Blob`/`Bytes`. `aws-esdk` has a `fips` feature. The AWS SDK has `rustls-aws-lc-fips`, and smithy-rs PR #4874 moves SigV4 to FIPS AWS-LC (UNVERIFIED by consolidator). anykms has no FIPS feature (R-18). |
| Docs | **better** than kms-aead and tink-rust; **different** from the SDKs | A 721-line README, per-cloud guides with IAM policies, an envelope spec with vectors, "Emulates / Enforced by" boxes. |
| Project health | **worse** (inherent) | Unpublished, one maintainer, 3188 tests and emulator CI. kms-aead has had 29 breaking minors in 4 years. tink-rust and rusoto are dormant. |

Ciphertext interoperability with Tink (AEAD with AAD):

| Backend | Tink convention | anykms | Interoperable? |
|---|---|---|---|
| GCP | AAD in `additionalAuthenticatedData` | same (`anykms-gcp/src/handles.rs:705`) | yes, by construction (untested) |
| Vault transit | `associated_data`, standard base64 | same (`anykms-transit/src/handles.rs:471-480`) | yes, by construction (untested) |
| AWS | `{"associatedData": lowercase_hex(aad)}` | `{"anykms-aad": base64url_nopad(aad)}` | **no (R-1)** |
| Envelope | `KmsEnvelopeAead` (len ‖ eDEK ‖ payload) | `AKE` v1 | no, by design (a reader would be additive) |

Lessons from history:

| What happened | Is anykms exposed? |
|---|---|
| Tink Go changed its AWS context key from `additionalData` to `associatedData` and keeps `LegacyAdditionalData` forever. tink-rust still uses the legacy key. | **Yes**: anykms picked a third convention (R-1). |
| Tink Go Vault sent AAD as `context`, which Vault ignores for non-derived keys (fail-open), then moved to `associated_data`. | No. |
| ESDK 1.7→2.0: key commitment and explicit KeyIds were breaking, with a readers-first rollout. | No: v1 commits from day one, `kek_id` is checked first, and AWS Decrypt passes the KeyId (#63). |
| kms-aead retrofitted its layout (32-bit length prefix; tag added in 0.29.0, "upgrade every reader before the first write"). | No: fixed-width lengths, magic and version. |
| Tink Go's envelope constructor went through three generations. | No (#89). |
| Rusoto was deprecated, stranding tink-awskms. | Partly: the bridges couple to GA 1.x crates behind features (R-22). |
| Azure SDK for Rust broke almost monthly in 0.x. | Low: the bridge takes `azure_core` 1.x. |
| The AWS SDK made `BehaviorVersion` mandatory so it can change defaults. | Mildly: anykms has no defaults-change policy (R-26). |
| FIPS is being retrofitted into smithy-rs. | Yes (R-18). |
| tink-rust's sync-over-async design. | No (#41). |

### B.2 Other languages (CMP-X)

Compared, from shallow clones taken 2026-10-13:
- Google Tink: tink-java v1.23.0, tink-go v2.8.0, tink-go-awskms, tink-go-hcvault v2.5.0.
- The AWS Encryption SDK specification.
- Go CDK `gocloud.dev/secrets` v0.46.0.
- `go-kms-wrapping/v2` v2.0.26.
- sigstore `pkg/signature/kms` v1.11.0.
- SOPS v3.13.3.
- ASP.NET Core Data Protection with Azure Key Vault.

All had commits within the last 3 months.

| Axis | anykms | Comparators | Verdict |
|---|---|---|---|
| Capability coverage | AEAD, rewrap, data keys, sign, verify, MAC, public keys, describe and KeyWrap on 4 backends | Go CDK: Encrypt/Decrypt only. sigstore: sign/verify/public key. Tink KMS: a remote Aead only. go-kms-wrapping: encrypt/decrypt plus a separate signer. ESDK, SOPS and .NET: encryption only. | **Better** |
| Key addressing | Tink spellings for AWS/GCP; `hashivault`/`openbao://[alias]/<mount>/keys/<name>`, `azure-kv://<host>/keys/<n>[/<v>]`; never a network address | Tink: same AWS/GCP; `hcvault://<host>/...` with an address. sigstore: `awskms://[endpoint]/...`, `gcpkms://`, `azurekms://<vault>/<key>`, `hashivault://<name>` (mount from env). Go CDK: `awskms://<id>?region=`, `azurekeyvault://<host>/keys/<k>[/<v>]` (the same shape as azure-kv), `hashivault://<key>?engine=`. SOPS: a full Vault URL. | **Equal, mixed**: stricter and safer; scheme names shared with sigstore and Go CDK under a disjoint grammar (R-54) |
| Envelope format | AKE v1: HKDF commitment over the DEK, unauthenticated `kek_id`+wrapped-DEK slot (rewrap, migration), one slot, no streaming, flags reserved, vectors, external review pending | Tink: `u32 len ‖ encDEK ‖ ct`, no commitment, no KEK id. ESDK: committing suites since 2.0 (DEK only), N wrapped keys with `max_encrypted_data_keys`, framed streaming, stored context, optional signatures. go-kms-wrapping: protobuf `BlobInfo`, no commitment. SOPS: key groups with Shamir. .NET: proprietary header plus key id. | **Better** than Tink, Go CDK and go-kms-wrapping; **equal** to ESDK on commitment; **worse** than ESDK and SOPS on multiple KEKs and streaming (v2) |
| Credentials | Built-in lazy workload chains plus SDK bridges | Full vendor SDK chains everywhere; .NET takes any `TokenCredential` | **Equal** on reach via the bridges; **better** on I/O-free open; **worse** without the bridges |
| Reliability | One `Retry` layer with deadline, jitter, Retry-After floor and hint; decrypt-side `CachingKeyWrap`; `CachedVerifier` | Opaque, stacking SDK retries. ESDK caching CMM (encrypt side too). .NET 24 h key-ring cache. | **Better** on retries; **equal** on caching |
| Errors | 16 kinds, 4 classes, HTTP mapping, `BackendDetail` | Tink: `GeneralSecurityException`. Go CDK: `gcerrors` (no retry classes). sigstore and SOPS: raw errors. ESDK: per-failure exceptions. | **Better**; only Go CDK comes close |
| Testing | `anykms-local` with fault injection, plus conformance | Go CDK `localsecrets` + `drivertest`; Tink fake KMS (UNVERIFIED); sigstore `kms/fake`; go-kms-wrapping test wrapper; ESDK raw keyrings | **Better** (faults); **equal** to Go CDK otherwise |
| Extensibility | `Provider`, layers, extension calls, third-party conformance | Go CDK `URLMux`; sigstore `AddProvider` plus CLI plugins; go-kms-wrapping gRPC plugins; Tink `KmsClient` (ServiceLoader discovery deprecated as unsafe); ESDK keyrings and CMMs | **Equal or better** in-process; no out-of-process plugins |
| Runtime model | Async only (#41) | All comparators are synchronous (Go `context`, Java, Python; .NET also async) | **Worse** for sync callers; aligned with Rust |
| Cost to adopt | Per-backend features; 149 deps; aws-lc-sys by default even with no backend | sigstore split per-provider Go modules; Tink split KMS integrations into separate artifacts | **Equal** in structure; **lighter** than the SDK-based ones |
| Hygiene | `Zeroizing`, Debug redaction, TRACE tests, TLS honours a process FIPS provider; envelope primitives are RustCrypto; FIPS scope undocumented | Tink FIPS mode (UNVERIFIED); go-kms-wrapping transit **drops AAD** (`transit.go:83,106`); Tink hcvault once sent AAD as ignored `context` | **Better** on secrets and fail-closed AAD; **worse or undocumented** on FIPS |
| Docs | Envelope spec with positive and negative vectors, per-backend guides | ESDK spec; Tink site; Go CDK concepts; go-kms-wrapping and sigstore thin; .NET extensive | **Equal** to the best; no cross-ecosystem URI table |
| Project health | Pre-release, one maintainer, no users | Backed by Google, AWS, HashiCorp, LF, CNCF, Microsoft | **Much worse** (inherent) |

Lessons from history:

| Project | What happened | Is anykms exposed? |
|---|---|---|
| Tink Go vs Java, AWS | Java used `associatedData` = hex; Go hard-coded `additionalData`; Go now carries both forever | **Yes, ONE-WAY (R-1)** |
| Tink hcvault | AAD sent as Vault `context` (fail-open), later fixed | No: `associated_data`, and AAD refused where transit would ignore it (`handles.rs:634-703`) |
| Tink `KmsClients` | ServiceLoader auto-registration deprecated as an attack vector | No: explicit `Registry` |
| Tink `KmsEnvelopeAead` | DEK restricted to an allowlist | No: v1 fixes AES-256-GCM |
| ESDK 1.7→2.0 | Commitment breaking; two-step rollout | Commitment: no. Rollout: yes, for v2 and the AWS AAD cap (R-50, R-55) |
| ESDK strict vs discovery keyrings | Split | No: `kek_id` is never a URI; Decrypt passes the KeyId |
| ESDK `max_encrypted_data_keys` | Client-side cap | Not in v1; v2 must include it (R-55) |
| ESDK required encryption context | Added on decrypt | No: the caller supplies AAD on decrypt |
| Go CDK Azure | Versionless decrypt breaks after rotation | No: the AZK frame carries the version |
| Go CDK AWS SDK v1→v2 | Entry-point churn | Low: in-house REST |
| sigstore | Per-provider modules; added `openbao://`; CLI plugins | Done via features; `openbao` from day one; plugins not needed |
| .NET Data Protection | 2-day activation lead; package replaced for security reasons | Partly: "publish before use" applies to JWKS rotation (R-48) |
| SOPS | Full Vault URLs in files; Shamir key groups | No: address-free; k-of-n is a v2 note |

---

## Appendix C. Public API surface statistics (Phase 0)

The listings came from `cargo-public-api` 0.52.0 with `-s` (blanket impls omitted, auto-trait
impls kept), on nightly rustc 1.101.0 (2026-10-06), with all public features per crate. For AWS
that means everything except the hidden `__test-fixtures`.

Counting rules:
- There is one line per item per path. Core lists many items twice, for example
  `anykms_core::dynamic::AeadKey` and `anykms_core::AeadKey`, and traits also under `prelude`.
- Every capability trait has forwarding impls for `&T`, `Box<T>`, `Arc<T>`, `dyn DynX`, `Retry<T>`
  and `Observed<T>`.
- The last column deduplicates by last path segment.

| Crate | Lines | pub mod | struct | enum | trait | fn/method | async | const | type alias | macro | impl blocks | pub use | `#[non_exhaustive]` | distinct type+trait names |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| anykms-core | 3216 | 5 | 47 | 22 | 49 | 1599 | 484 | 11 | 10 | 1 | 631 | 1 | 62 | 69 |
| anykms-recipes | 389 | 4 | 15 | 0 | 2 | 169 | 41 | 4 | 0 | 0 | 62 | 2 | 0 | 13 |
| anykms-local | 258 | 1 | 7 | 2 | 0 | 102 | 19 | 2 | 0 | 0 | 59 | 0 | 2 | 9 |
| anykms-http | 211 | 8 | 7 | 3 | 0 | 76 | 4 | 4 | 1 | 2 | 26 | 2 | 1 | 10 |
| anykms-transit | 500 | 1 | 16 | 4 | 1 | 187 | 23 | 2 | 0 | 0 | 118 | 1 | 5 | 21 |
| anykms-aws | 665 | 2 | 22 | 2 | 3 | 279 | 42 | 5 | 0 | 0 | 162 | 1 | 3 | 25 |
| anykms-gcp | 448 | 1 | 14 | 3 | 1 | 188 | 28 | 2 | 0 | 0 | 112 | 1 | 6 | 18 |
| anykms-azure | 730 | 2 | 18 | 9 | 1 | 268 | 20 | 9 | 0 | 0 | 176 | 1 | 12 | 28 |
| anykms-conformance | 369 | 1 | 11 | 4 | 2 | 119 | 0 | 0 | 0 | 1 | 56 | 0 | 9 | 17 |
| anykms (facade) | 46 | 1 | 2 | 0 | 0 | 17 | 0 | 0 | 0 | 0 | 5 | 7 | 0 | 2 |

**Modules.**

| Crate | Modules |
|---|---|
| core | root, `encoding`, `observe`, `prelude`, `retry` |
| recipes | root, `ecdsa_der`, `envelope`, `jose` |
| http | `cache`, `client`, `credentials`, `redact`, `span`, `tls`, `zbuf` |
| aws | root, `credentials` |
| azure | root, `framing` |
| other backends | root only |
| facade | root (`pub use anykms_core::*`); modules `recipes`, `transit`, `aws`, `gcp`, `azure`, `local`; own items `DefaultProviders`, `SkippedProvider`, `with_default_providers[_from]`, `retry_layer`, `tokio_sleep`, `tokio_clock` |

**Public traits.**
- Core has 33 distinct traits:
  - Capability traits: `Aead`, `Rewrap`, `DataKeys`, `WrappedDataKeys`, `KeyWrap`,
    `DigestSigner`, `MessageSigner`, `DigestVerifier`, `MessageVerifier`, `PinnedVerifier`, `Mac`,
    `PublicKeys`, `Describe`, `Preflight`.
  - Others: `ExtensionCalls`, `Semantics`, `Provider`, `Layer`, `Around`, `OpaqueHandle` (sealed),
    `IntoKeyUri`.
  - Sealed `Dyn*` twins: `DynAead`, `DynRewrap`, `DynDataKeys`, `DynWrappedDataKeys`,
    `DynKeyWrap`, `DynDigestSigner`, `DynMessageSigner`, `DynDigestVerifier`,
    `DynMessageVerifier`, `DynMac`, `DynPublicKeys`, `DynDescribe`, `DynPreflight`,
    `DynExtensionCalls`.
- Other crates:

  | Crate | Traits |
  |---|---|
  | recipes | `IntoKek` |
  | transit | `TokenSource` |
  | aws | `CredentialSource`, `EncryptionContextAead` |
  | gcp | `CredentialSource` |
  | azure | `TokenCredential` |
  | conformance | `Fixture`, `TypedHandles` |

- Macros: `anykms_core::forward_provider!`, `anykms_http::request_span!`/`token_span!` and
  `anykms_conformance::typed_handles!`.

**Types that are not `#[non_exhaustive]`.**

| Crate | Types |
|---|---|
| core | `AeadKeyWrap<T>(_)`, `Call<'a>`, `CallOutput(_)`, `ObserveLayer`, `Observed<T>`, `RetryBudget`, `RetryLayer` (all private fields) |
| recipes | `EmulatedDataKeys<K>(pub K)`, `KeyWrapDataKeys<K>(pub K)`, `ClientRewrap<K>(pub K)`, which have **public tuple fields** (R-3); `Envelope<'a>`, `EnvelopeAead<K>`, `EnvelopeKeyring<K>`, `CachingKeyWrap<K>`, `CachedVerifier<P>`, `LocalVerifier`, `jose::{JwsHeader, JwtOptions, JwtSigner<S>}` |
| http | `zbuf::Writer(pub Zeroizing<Vec<u8>>)`; `client::{BodyError, SendError}`, which are exhaustive enums wrapping `reqwest::Error`; `ClientOptions`; `Response` (public `status`, `headers`, `body`); `credentials::{Credential, CredentialCache, Expiring}`; `TlsOptions` |
| backends | handles, providers, builders and credential sources; `Token(_)`, `StaticToken(_)`, `StaticCredentials(_)`, `EncryptionContext(_)`, `GrantTokens(_)`, `azure::framing::Frame<'a>`, `AccessToken`, `TestHost` |
| conformance | `AeadBridge`, `KeyWrapBridge`, `FixtureCaps`, `FreshKeys`, `KeySpecTable`, `RunId` |
| facade | `DefaultProviders`, `SkippedProvider` |

These structs have public named fields: `AwsKeyInfo` (17), `AzureKeyInfo` (about 19),
`AzureVersionInfo`, `RetryPolicy` and `anykms_http::client::Response`. All except `Response` are
`#[non_exhaustive]`.

**Scale (SCOPE lens).**
- 59.1k lines in `crates/*/src`, of which about 11.6k are `#[cfg(test)]`.
- 23.5k lines of integration tests and 7.1k of conformance.
- 23 fuzz targets.
- 12.6k lines of Markdown docs.
- 375 commits between 2026-10-03 and 2026-10-12, all by one author.

The public contract covers 6.8k listing lines, 5 URI schemes, about 30 env vars, 3 persisted
formats and 2 tracing schemas.

---

## Appendix D. Consolidation map (raw finding → consolidated id)

| Consolidated | Raw sources | Final |
|---|---|---|
| R-1 | CMP-RS-1, CMP-X-1 | Blocker (D1) |
| R-2 | SEC-1 | Blocker |
| R-3 | API-1 | Should-fix |
| R-4 | API-2 | Rejected |
| R-5 | API-3 | Later |
| R-6 | API-4, OPS-7 | Should-fix |
| R-7 | API-5 | 0.1.x |
| R-8 | API-6 | 0.1.x |
| R-9 | API-7 | Rejected |
| R-10 | API-8 | Rejected |
| R-11 | SEC-2 | Should-fix (D2) |
| R-12 | SEC-6, P2-1 | Should-fix |
| R-13 | SCOPE-4 | Rejected |
| R-14 | SEMVER-1, SEC-3 | Should-fix |
| R-15 | SEMVER-2 | Should-fix |
| R-16 | SEMVER-8, DOCS-2 | Should-fix |
| R-17 | SEC-4 | Should-fix |
| R-18 | CMP-RS-2, CMP-X-3, SEMVER-6 | 0.1.x |
| R-19 | P1-1, P4-1 | Should-fix |
| R-20 | OPS-2 | Should-fix |
| R-21 | DOCS-1 | 0.1.x |
| R-22 | SEMVER-5, DOCS-3 | 0.1.x |
| R-23 | SEMVER-3 | 0.1.x |
| R-24 | SEMVER-4, SCOPE-1 | 0.1.x |
| R-25 | SEMVER-7, P3-6 | 0.1.x |
| R-26 | SEMVER-9, CMP-RS-3 | 0.1.x |
| R-27 | SEMVER-10 | 0.1.x |
| R-28 | SEMVER-11 | Rejected |
| R-29 | SEC-5 | 0.1.x |
| R-30 | OPS-1 | 0.1.x |
| R-31 | OPS-3, P4-3 | 0.1.x |
| R-32 | OPS-4 | 0.1.x |
| R-33 | OPS-5 | 0.1.x |
| R-34 | OPS-6 | Later |
| R-35 | OPS-8, P4-2 | 0.1.x |
| R-36 | DOCS-6 | 0.1.x |
| R-37 | DOCS-5 | 0.1.x |
| R-38 | DOCS-4 | Later |
| R-39 | DOCS-7 | 0.1.x |
| R-40 | SCOPE-2 | 0.1.x |
| R-41 | SCOPE-3 | 0.1.x |
| R-42 | SCOPE-5 | Rejected |
| R-43 | P1-2 | 0.1.x |
| R-44 | P1-3, P4-4, P3-5 | 0.1.x |
| R-45 | P1-4 | Later |
| R-46 | P1-5 | 0.1.x |
| R-47 | P1-6 | Should-fix |
| R-48 | P2-2, P2-3 | 0.1.x |
| R-49 | P3-1 | 0.1.x |
| R-50 | CMP-X-2 | 0.1.x |
| R-51 | P3-2, P3-4 | 0.1.x |
| R-52 | P3-3 | Later |
| R-53 | P4-5 | 0.1.x |
| R-54 | CMP-X-4 | 0.1.x |
| R-55 | CMP-X-5 | Later |

Reclassifications:

| Finding | Change | Reason |
|---|---|---|
| R-12 (P2-1) | ONE-WAY → BREAKING (consolidator) → DOCS (judges) | The kid is kept |
| R-52 (P3-3) | BREAKING → ADDITIVE | New builders can sit alongside the old style |
| R-24 (SCOPE-1) | BREAKING → DOCS | An independent version track stays available |
| R-2 | BREAKING → DOCS | The minimum fix restores correctness |
| R-5, R-7 | BREAKING → ADDITIVE | Aliases |
| R-8 | BREAKING → DOCS | |
