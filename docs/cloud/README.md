# Cloud backends: combined plan

Status: **implemented** (2026-10-06). `anykms-http`, `anykms-aws`, `anykms-gcp` and `anykms-azure`
exist on the `cloud-backends` branch. What was built, the deviations from these plans, the
agreed conventions (D1–D6) and the open release gates are in
[PLAN §24](../PLAN.md#24-cloud-backends-implementation-status-2026-10-06). The plans below are
kept as written; each now opens with "Implementation notes", and places where the code departs
from the plan are marked "Implemented as: …".

**After the backends (2026-10-07):** [`architecture-plan.md`](architecture-plan.md) is the signed-off
plan for the consistency fixes, the core API changes (`KeySemantics`, `pin`, the error model,
`Around`/`Call` layers, `Preflight`, KEK public keys) and packaging; it is implemented, see
[PLAN §25](../PLAN.md#25-architecture-plan-after-the-cloud-backends-2026-10-07).

Index and reconciliation of four plans written in parallel on 2026-10-05 against `dd3cc82`:

| Document | Scope | Size of work |
|---|---|---|
| [`shared.md`](shared.md) | conformance capability redesign (PLAN §22), new handle parts, layered extension calls, recipes, URIs/facade/CI/semver | ~8–10 days before the first backend can merge, +3–4 days in parallel |
| [`aws.md`](aws.md) | `anykms-aws`: AWS KMS | ~3 weeks (critical path A2→A3→A6→A8→A9→A12→A13) |
| [`gcp.md`](gcp.md) | `anykms-gcp`: GCP Cloud KMS | ~3–4 weeks (credentials are the largest item) |
| [`azure.md`](azure.md) | `anykms-azure`: Key Vault (release A) and Managed HSM (release B) | A ≈ 8–10 days, B ≈ 4–5 days + MHSM time |
| [`architecture-plan.md`](architecture-plan.md) | after the backends: Phase 1 consistency fixes (implemented), Phase 2 core API, Phase 3 packaging (2026-10-07, not one of the four original plans) | tasks X0–X23 |

Each document honors PLAN Appendix A and §19–§22. Where two documents disagree, this file decides
(§2). PLAN.md gets a §23 that points here once the maintainer has answered §5 (task D0).

## 1. Decisions common to all three

- **In-house REST clients on reqwest + rustls, no official SDKs.** All three SDKs now need a
  newer compiler than the workspace MSRV 1.85 (AWS SDK 1.94.1, google-cloud-rust 1.91,
  Azure SDK 1.88), retry internally, and choose their own TLS provider. The in-house clients are
  modelled on `anykms-transit`. This keeps retries in `Retry`, zeroization of request bodies, TLS
  provider precedence and no-redirects under our control. Each backend computes its own
  credentials (SigV4 + AWS chain; ADC; Entra ID token sources) lazily, with no I/O on open.
- **URIs:** `aws-kms://arn:…` (ARN only; host derived from partition/region or configured
  endpoints), `gcp-kms://projects/…` (both Tink spellings), `azure-kv://<host>/keys/<name>[/<ver>]`
  checked against a host allowlist. Optional account / project allowlists on AWS and GCP (Q8).
- **No retries below `Retry`, no redirects, timeouts in the client, TRACE hygiene test per
  backend, fuzzed URI parser and response classifier** (shared.md §5 backend checklist).
- **Testing tiers:** wiremock mocks on every PR; an emulator job where one is faithful enough
  (AWS: LocalStack with a project token, or Floci; Azure: Lowkey Vault; GCP: none); nightly live
  jobs per cloud with GitHub OIDC federation, never on fork PRs, with pooled long-lived keys
  (GCP keys cannot be deleted).
- **Each backend starts with a live probe task** (AWS A0, GCP T1, Azure T3/T13). Facts the
  vendor docs do not state are pinned from real responses into `docs/research/<cloud>-kms.md`,
  as transit's were.
- **Release:** 0.2.0 = conformance redesign + K1–K3 + R1–R3 + AWS, with `anykms-conformance`
  published. GCP and Azure follow as 0.2.x (additive) unless one needs a core break. All core
  changes are additive; `cargo-semver-checks` stays green against 0.1.0. *Superseded by PLAN §25
  R1: 0.1.0 had not been published, so every backend ships in 0.1.0; the publish waits for probes
  T1 and T3 and one green GitHub CI run (PLAN §24.4).*

## 2. Reconciliation (where this file overrides a sub-plan)

1. **Shared HTTP/credential code: extract a crate (overrides shared.md §5).** shared.md decided
   "no shared crate" on the assumption that two of three backends would use SDKs, and said to
   revisit if two in-house REST clients appeared. All three are in-house, so the copied surface
   is now large: the rustls provider precedence, no-redirect client builder, zeroizing bodies
   (`zbuf.rs`), `Retry-After` parsing, and above all the **credential cache with single-flight
   refresh and refresh-once-on-401**, which AWS (A4), GCP (T5) and Azure (T5) each size as L.
   Recommendation: a published `anykms-http` (internal-use, `#[doc(hidden)]`-style API, semver
   checked but documented as unstable for third parties) extracted from transit as task **S1**
   before A3. The cloud-specific credential sources stay in each backend. Maintainer decision Q4.
2. **AWS emulator fallback is Floci, not moto (overrides shared.md §6.6/§9).** aws.md found that
   moto cannot verify digest signatures, and LocalStack has required an auth token since
   2026-03-23. Use LocalStack with a project token if the maintainer provides one (Q6), otherwise
   Floci after A0 checks its fidelity; the emulator job does not run on fork PRs either way.
3. **The conformance work needs one more task, C8, beyond shared.md §8.** The backend plans ask
   for suite features that shared.md's C1–C7 do not list:
   - AWS: `FixtureCaps::max_plaintext` clamping `aead::roundtrip`'s 64 KiB case (AWS: 4096);
     `Feature::EmptyPlaintext` / `EmptyMessage` (AWS rejects empty `Encrypt`/`Sign`/`GenerateMac`
     input); `Fixture::malformed_version()` and a foreign-version expectation; per-family rotation.
   - GCP (gcp.md §13 P2–P9): `Feature::DisableVersion` + `Fixture::disable_version` with
     version-scoped cases; rotation per family returning a versioned URI; versioned signing/MAC
     test URIs left untouched by cases; `key_state_per_version`; `reports_used_primary`; bounded
     waits after state changes; `VERIFY` meaning "the handle verifies, locally or not".
   - Azure: a flag saying a fixture's error messages come from an emulator, so message-level
     cases skip under Lowkey Vault; KeyWrap-gated envelope cases that do not require `Aead`.

   C8 (M, depends on C3) adds these; C7's input-limit and `used_primary` cases stay as planned.
   The suite grows from ~4 to ~5–6 days. The GCP-shaped and Azure-shaped proof fixtures (C6)
   must exercise the C8 additions.
4. **Registry path for Azure data keys (gap in shared.md R1).** R1 plans the `KeyWrapDataKeys`
   recipe but not how `Registry` reaches it for a standard-vault key. Options: an optional
   `DataKeys` part on `KeyWrapKey` (a later part via K1's `with_*`), or a new
   `Provider::data_keys` → `DataKeysKey` handle (Azure's preference). Recommendation: the new
   handle, because a dedicated KEK should not also hand out data keys under the same name.
   Decide before R1 (Q3); it is additive either way.
5. **RSA-OAEP wrap direction.** shared.md R3 adds a local RSA-OAEP-SHA-256 encrypt helper (GCP
   `asymmetricDecrypt` keys have no server-side encrypt). Use it for AWS RSA `KeyWrap` too
   (wrap locally with the cached, pinned public key, unwrap with `Decrypt`), which answers
   aws.md Q12. Azure keeps server-side `wrapKey`/`unwrapKey` (a native operation that respects
   `key_ops` and logs in Azure Monitor). SHA-256 OAEP only on all three (Q10).
6. **PLAN.md corrections to apply in D0:**
   - §19 / §18 "Azure MAC: no HMAC data-plane op": wrong. Managed HSM has HS256/384/512 (GA
     since API 7.6; preview on Premium vaults). Azure release B ships `Mac` only if the live
     probe shows HS* signs the message, not a digest (azure.md Q4).
   - Appendix A GCP "Verifier: — native": correct for signatures; but `macVerify` exists and GCP
     `Mac` uses it.
   - Appendix A AWS: plaintext limit 4096 **and a minimum of 1 byte**; the encryption-context
     size limit is not documented by AWS (the 8192 that circulates is the grant-token limit) and
     is pinned by A0.
   - The handle macro's "later parts" group (K1) is needed before §22's "`full` is frozen" can
     hold: today `handle!` sets every optional part inside `full`.

## 3. Sequence

```
           ┌─ S1 anykms-http extract ─────────────────────────────┐
K1 ─┬─ K2 ─┤                                                      │
    └─ K3 ─┤                                                      ▼
C1→C2→C3 ─┬┴─ C4, C5, C7, C8 ── C6 (proof fixtures) ── C9 publish suite
          │                                                    │
          ├─ R1, R2, R3 (recipes, parallel)                    │
          │                                                    ▼
          ├─ AWS  A0…A13 (A14 needs K3, A15 needs K2, A16 needs R3) ── 0.2.0
          ├─ GCP  T1…T12 (T11 needs C6+C8, R2, R3) ─────────────────── 0.2.x
          └─ Azure T1…T12 = release A (T9 needs R1 + Q3, T10 needs C6+C8) ── 0.2.x
                   T13…T16 = release B (Managed HSM; needs MHSM budget)
```

- Backend-local work that does not touch the suite (URI parsers, signers, clients, credentials,
  error tables, handles, mocks) starts **in parallel with the conformance redesign**; only each
  backend's fixture task (A12, GCP T11, Azure T10) waits for C3/C6/C8.
- The three live probes (A0, GCP T1, Azure T3) run first; they need accounts (Q6).
- One engineer: shared ~2.5 weeks, then AWS ~3 weeks, GCP ~3–4 weeks, Azure A ~2 weeks,
  Azure B ~1 week, i.e. roughly 3 months serially. With three backend engineers after the
  shared core, about 6–7 weeks to all three on 0.2.x.
- Order stays AWS → GCP → Azure (PLAN §10, §22: AWS drives the redesign and the new parts).
  Azure release A is the smallest and could move ahead of GCP if user demand says so (azure.md).

## 4. Deferred (recorded, not planned here)

`AsymmetricDecrypt` trait; native `KeyWrap` part on `AeadKey` (Azure MHSM A256KW via
`into_key_wrap`); `MuSigner` for ML-DSA; secp256k1 / HMAC-SHA224 (task K4, with whichever
backend needs them first); GCP newest-enabled-version mode (gcp.md T13, the release after the
first); envelope v2; `KeyWrap::unwrap_with_info`; optional adapters to official SDK credential
chains (AWS SSO / role chaining, `google-cloud-auth`), behind features, if users ask.

## 5. Questions for the maintainer (deduplicated)

Blocking the start:

- **Q1 Version:** 0.2.0 with AWS (recommended), or ship the additive shared parts as 0.1.x?
- **Q2 Crate names:** `anykms-aws` / `anykms-gcp` / `anykms-azure` (assumed by all plans) or
  `anykms-aws-kms` / `anykms-gcp-kms` / `anykms-azure-keyvault`?
- **Q3 Azure data-keys handle:** new `DataKeysKey` via `Provider::data_keys` (recommended) or a
  part on `KeyWrapKey`?
- **Q4 Shared `anykms-http` crate** (recommended, §2.1) or copy the helpers per backend?
- **Q5 MSRV:** confirm in-house clients to stay on 1.85, or let cloud crates have their own
  higher MSRV and use the SDKs (fewer weeks of credential work, more dependencies, and retries
  that must be turned off)?
- **Q6 Accounts and budget:** who owns the AWS account, GCP project and Azure subscription for
  probes and nightly live jobs; monthly cap; Managed HSM (~$3.20/h) for Azure release B;
  a LocalStack project token or not.

Wire formats (permanent once shipped):

- **Q7 AWS reserved context key name** (`anykms-aad` proposed; *superseded by the release plan
  D1: Tink's `associatedData`, lowercase hex*) and the size cap, which may only
  ever rise (aws.md Q1–Q2).
- **Q8 Allowlists:** AWS account and GCP project allowlists optional or required (a key URI from
  config could point at another tenant's key); Azure tenant: require `AZURE_TENANT_ID` or allow
  discovery from the challenge (azure.md recommends the scope come from the allowed host only).
- **Q9 Azure ciphertext frame** (azure.md §7) as specified.

Behavior:

- **Q10** RSA-OAEP SHA-256 only, or SHA-1 unwrap for existing AWS/Azure data?
- **Q11** `ClientRewrap` (plaintext through the client) as a public recipe for GCP, or only
  `EnvelopeAead::rewrap_local`?
- **Q12** Verification: Azure server-side by default with a local option (proposed); AWS verify
  with a foreign ARN → `VerificationFailed` or `NotFound`.
- **Q13** Default TLS provider: move the facade to aws-lc-rs (already compiled for RSA) or keep
  ring?
- **Q14** AWS: one retry after a clock-skew rejection; `KeyMaterialId` as a staleness signal.
- **Q15** Azure: open Premium oct-HSM (preview) keys at all; `az` CLI credential opt-in.
- **Q16** A suite-owned TRACE hygiene case, or per backend as in transit?
- **Q17** `deny.toml`: is MPL-2.0 acceptable if a dependency needs it (less likely without SDKs)?

## 6. First steps once Q1–Q6 are answered

1. D0: PLAN §23 + the corrections in §2.6.
2. In parallel: K1 → C1 → C2 → C3 (one engineer); S1 extract `anykms-http` from transit;
   the three live probes as soon as accounts exist.
3. AWS A1–A3 on top of S1 while the suite redesign proceeds.
