# Cloud backends: consistency and spec review

**Status (2026-10-06):** All findings addressed on `cloud-backends` except: the Azure `KeyDisabled` classification (waits for the T3 probe); GCP `from_env_with`; Azure Z5 (`AZURE_AUTHORITY_HOST`); the AWS RSA-without-backend cross-backend behaviour (item 1.3.4); and the live probes. See [PLAN §24](../PLAN.md#24-cloud-backends-implementation-status-2026-10-06).

Branch `cloud-backends` @ `b669fce`, `/home/laborant/anykms.orig`. Read-only review; nothing built.
Scope: `crates/anykms-{aws,gcp,azure}`, the facade, and docs, checked against `docs/cloud/*`,
PLAN §3, §6, Appendix A and §23.

Verdict legend: **MUST** = fix before release; **SHOULD** = fix in this cycle; **OK-doc** =
acceptable and documented; **OK-undoc** = acceptable but needs a doc line.

## 0. Decisions to take first

These are the places where the three agents diverged. Each fix list below assumes the
recommendation is taken.

| # | Question | Recommendation |
|---|---|---|
| D1 | Backend name strings (`Error::backend()`, `Provider::name()`, `SkippedProvider::backend`) | **Use the crate suffix, not the scheme:** `aws`, `gcp`, `azure`. Transit is the precedent: its backend is `transit` and its schemes are `hashivault`/`openbao`. Today only AWS diverges (`aws-kms`). |
| D2 | Facade registration | **Always register every cloud provider whose feature is on.** shared.md §6.2 says so, and it is the rule that overrides the sub-plans. Transit is skipped only because it has no address without `VAULT_ADDR`; cloud URIs are fully addressed and credentials are lazy (Appendix A "Credentials … lazily", §19 "construction stays sync and I/O-free"). A missing credential becomes a lazy `Configuration` error on first use, as on AWS and GCP. Keep `ANYKMS_AZURE_CREDENTIAL=none` as an explicit skip. A **malformed** environment variable is an **error** from `with_default_providers()` (the transit precedent: "a broken configuration is an error, never a silent skip"). Amend shared.md §6.2, which says "skipped … with the reason", to match. |
| D3 | Tracing field schema | **One schema for all four HTTP backends:** `backend, op, resource, key_version, attempt, http_status, code, request_id, latency_ms, error_kind, outcome`. Add `outcome` to the shared.md §5 allowlist (transit already uses it). Location fields (`region`/`account`, `project`/`location`/`key_ring`, `host`) are allowed as extras only if shared.md §5 lists them; otherwise `resource` carries them. |
| D4 | Typed opener and handle naming | **Follow transit:** `aead_key`, `key_wrap_key`, `digest_signing_key`, `ed25519_key`, `mac_key`, returning `<Cloud>{Aead,KeyWrap,Digest,Ed25519,Mac}Key`. This renames GCP `rsa_kek`/`GcpRsaKek` and Azure `signing_key`/`AzureSigningKey`. |
| D5 | Operator doc file names | `docs/operations-<backend>.md`: rename `docs/azure.md` to `docs/operations-azure.md`. Optionally rename `docs/operations.md` to `docs/operations-transit.md`, leaving a one-line stub. |
| D6 | 3xx classification | Keep **`Configuration`**: all four backends already do this (aws errors.rs:202, gcp errors.rs:260, azure errors.rs:219, transit errors.rs:263; transit's 307 is the only exception). Fix shared.md §5, which says `Unavailable`. |

## 1. Cross-backend consistency

### 1.1 Provider builder, `from_env`, env vars

| Aspect | AWS | GCP | Azure | Fix |
|---|---|---|---|---|
| Builder location | `AwsProviderBuilder` in config.rs:59, re-exported lib.rs:96 | `GcpProviderBuilder` provider.rs:50 | `AzureProviderBuilder` provider.rs:56 | none needed |
| `from_env` on the builder | yes, plus `from_env_with(lookup)` (config.rs:130,136) | yes (provider.rs:329) | **no**, only `AzureProvider::from_env` (provider.rs:312) | Add `AzureProviderBuilder::from_env()` so callers can adjust before `build()` (same shape as AWS and GCP). `from_env_with` is a nice testing seam; add it to GCP and Azure or drop it from AWS. |
| `from_env` with no credential | Ok (lazy) | Ok (lazy) | **`Configuration` error** (provider.rs:305-312, cred/mod.rs:97) | Per D2: return Ok with an "unconfigured" credential that fails with `Configuration` on the first token fetch, naming the variables. Keep the deterministic, no-probe selection of azure.md §4.6. |
| Facade helpers | none | none | `pub fn env_configured()` (provider.rs:297), `env_credential_kind`, `EnvCredentialKind` | After D2, `env_configured` is only needed for the `none` opt-out. Keep `env_credential_kind`, drop `env_configured` from the public API, or mark it `#[doc(hidden)]`. Note that it returns `true` on an invalid env (provider.rs:298), which is surprising for its name. |
| Credential setter | `credentials(impl CredentialSource)` + `credentials_arc` | `credentials(Credentials)` | `credential(impl TokenCredential)` + `credential_arc` | Use the plural `credentials` on Azure too; give GCP an `_arc` variant only if `Credentials` is not already `Arc`-like. Low priority. |
| Allowlists | `allowed_accounts`, `allowed_regions` | `allowed_projects`, `allowed_locations` | `allowed_vaults` | Consistent `allowed_*` pattern; fine. |
| Env allowlists | `ANYKMS_AWS_ALLOWED_ACCOUNTS`, `_REGIONS` | `ANYKMS_GCP_ALLOWED_PROJECTS`, `_LOCATIONS` | `ANYKMS_AZURE_ALLOWED_VAULTS` | Consistent. `ANYKMS_AZURE_ALLOWED_VAULTS` and `ANYKMS_GCP_ALLOWED_LOCATIONS` are missing from azure.md §4.6 and gcp.md §4.1 respectively (OK-undoc). |
| Loopback/test endpoint via env | `ANYKMS_AWS_ALLOW_LOOPBACK_HTTP` + `AWS_ENDPOINT_URL[_KMS]` | `ANYKMS_GCP_ENDPOINT`; **no** loopback env | none (`TestHost` in code only) | Acceptable. Document the asymmetry in each ops doc's "Environment" section. |
| Custom CA from env | `AWS_CA_BUNDLE` | none | none | Acceptable (AWS-standard variable). Mention it in the docs. |
| Hidden test hooks | `__private` module, `AwsProvider::__admin`/`__endpoint`, `AwsProviderBuilder::__count_requests` | `__fuzz` module | `__fuzz` module, no request counter | Rename AWS `__private` to `__fuzz` (with `__admin` kept separately `#[doc(hidden)]`), as transit, GCP and Azure do. Add a request counter to Azure (see §4.3). |
| Exported scheme const | `SCHEMES` only (uri.rs:29) | `SCHEME` + `SCHEMES` | `SCHEME` + `SCHEMES` | Export `SCHEME` from AWS too (`pub const SCHEME: &str = "aws-kms"`); transit is exempt (two schemes). |
| URI type name | `AwsKeyRef` **and** `KeyRef` (lib.rs:107) | `GcpKeyRef` | `AzureKeyUri` | Rename `AzureKeyUri` to `AzureKeyRef` (transit uses `TransitKeyRef`). Drop or `#[doc(hidden)]` the AWS `KeyRef` alias. |

### 1.2 `SCHEMES` and backend name strings (D1)

- `crates/anykms-aws/src/lib.rs:94`: `BACKEND = "aws-kms"`. **MUST:** change to `"aws"`.
  - Update `crates/anykms-aws/tests/mock.rs:1326` (`p.name()`).
  - Update the facade's skip entry `crates/anykms/src/lib.rs:187` and its tests at lib.rs:523,538.
  - Grep docs for `backend = "aws-kms"` / `backend="aws-kms"` in log examples (operations-aws.md).
- GCP `"gcp"` (lib.rs:145) and Azure `"azure"` (lib.rs:112) already follow the convention.
- Schemes `aws-kms`, `gcp-kms`, `azure-kv` match shared.md §6.1. No change.

### 1.3 Facade (`crates/anykms/src/lib.rs`, `Cargo.toml`)

1. **MUST, D2:** the Azure branch (lib.rs:212-234) registers Azure only when `env_configured()`. Replace it with:
   - an unconditional `d.provider(AzureProvider::from_env()?)`;
   - except when `env_credential_kind() == Ok(Some(Disabled))`, which keeps the skip at lib.rs:219.
2. **MUST, D2:** the GCP branch (lib.rs:192-204) swallows every `from_env` error into a skip, with a static reason. This loses the actual message and also hides "no TLS crypto provider", contrary to the transit precedent and to AWS (lib.rs:183 propagates with `?`). Replace it with `d = d.provider(anykms_gcp::GcpProvider::from_env()?);`, and update gcp.md:191 and the CHANGELOG.
3. **SHOULD:** the `with_default_providers` doc comment (lib.rs:112-144) was interleaved by the three merges: GCP bullet, generic paragraph, AWS bullet, "without the transit feature" paragraph, Azure bullet. Rewrite it as:
   - one bullet per backend, in the order transit, aws, gcp, azure;
   - then the skip paragraph;
   - then a "feature off → skip naming the feature" sentence for every backend.
4. **SHOULD:** `rsa-aws-lc-rs` / `rsa-rustcrypto` (Cargo.toml) forward to aws and gcp but **not azure**.
   - `anykms-azure` uses `LocalVerifier` for `AzureOptions::local_verify` (handles.rs:524) through `anykms-recipes` with `default-features = false`.
   - Standalone, local RSA verification on Azure therefore fails at run time with `Unsupported`.
   - Fix: add `rsa-aws-lc-rs`/`rsa-rustcrypto` features to anykms-azure (default `rsa-aws-lc-rs`, as on AWS and GCP) and forward them from the facade.
   - Separately, pick **one** behavior for "RSA key, no RSA backend": GCP fails at open with `Configuration` (provider.rs:366); AWS fails at wrap with `Unsupported`; Azure fails at verify with `Unsupported`. Recommendation: `Configuration` at open, as GCP does, because it is a build configuration error that should surface early.
5. **SHOULD:** the facade `gcp` feature force-enables `anykms-gcp/service-account-key` (Cargo.toml `gcp = [...]`), which pulls aws-lc-rs into every GCP build, even `rustls-ring` + `rsa-rustcrypto` builds.
   - Fix: make `gcp = ["dep:anykms-gcp"]` and add a facade feature `gcp-service-account-key`.
   - Alternatively, keep it but document in the README feature table that `gcp` needs a C toolchain.
6. **SHOULD:** the facade does not forward `http2` (any backend), `cli-credential` or `mhsm-hmac` (Azure). Forward `http2` with `?` for all four; leave the two Azure opt-ins to direct dependents, and say so in the feature table.
7. PLAN §2 crate-layout feature list (PLAN.md:68-70) lacks `aws`, `gcp`, `azure`. See §3.4.

### 1.4 Feature names

| Feature | AWS | GCP | Azure | Transit |
|---|---|---|---|---|
| `rustls-ring` (default), `rustls-aws-lc-rs` | yes | yes | yes | yes |
| `rsa-aws-lc-rs` (default), `rsa-rustcrypto` | yes | yes | **missing** | n/a |
| `tracing`, `http2` | yes | yes | yes | yes |
| extras | none | `service-account-key` (default) | `cli-credential`, `mhsm-hmac` | none |

Names are consistent. The only gap is Azure's missing `rsa-*` features (§1.3 item 4). The Azure Cargo comment for `rustls-*` lacks the trailing "anykms-http selects it." that the other three have (Cargo.toml:15-17); this is cosmetic.

### 1.5 `BackendDetail`

| | `code` | `request_id` | Notes |
|---|---|---|---|
| AWS (errors.rs:237-246) | exception name | `x-amzn-RequestId` (fallback `x-amz-request-id`) | OK |
| GCP (errors.rs:360-370) | `google.rpc.Status` name, or the canonical name for the HTTP status when the body is not JSON | `RequestInfo.requestId` from the error details | OK |
| Azure (errors.rs:243-252) | **outer and inner codes joined with `/`** (e.g. `Forbidden/ForbiddenByRbac`) | `x-ms-request-id`, filtered (client.rs:212-215) | Joined codes are a format nobody else uses |

- **SHOULD (Azure):** set `code` to the **innermost** error code (most specific, e.g. `ForbiddenByRbac`, `KeyDisabled`), so `code` is a single token on all three backends and matches Appendix A ("error code in the code field"). If the outer code matters, put it in the redacted server message or a tracing event. Document the choice in docs/azure.md's runbook.
- All three attach `resource` per handle (aws handles.rs:352-363, azure handles.rs:156-167, gcp equivalent); this is consistent.

### 1.6 Tracing (D3)

Request spans (all `debug_span!("anykms.<backend>", …)`):

| Field | allowlist | transit | AWS client.rs:381 | GCP client.rs:143 | Azure client.rs:150 |
|---|---|---|---|---|---|
| backend, op, http_status, error_kind, attempt, latency_ms | yes | yes | yes | yes | yes |
| `resource` | yes | `key`+`mount`+`server_alias` | `key`+`region`+`account` | `key`+`project`+`location`+`key_ring` | `key`+`host` |
| `key_version` | yes | no | **no** | declared; **never filled** for encrypt (handles.rs:688 records after the span closed) | **no** |
| `code` | yes | n/a | **`aws_error_code`** | **`grpc_status`** | **missing** |
| `request_id` | yes | n/a | yes | **missing** | yes, but **unfiltered** (client.rs:119-125) |
| `outcome` | no | yes | yes | yes | yes |

Token spans: GCP `anykms.gcp.token` (`credential_type`, `token_endpoint_host`); Azure `anykms.azure.token` (`credential`, `outcome`, `error_kind`, `latency_ms`, `expires_in_s`); AWS has **no token span** (only events at client.rs:185 and chain.rs:110).

Fixes:
- **MUST:** add `resource` (`KeyUri::without_query`) to all three request spans. Either drop the split location fields or add them to shared.md §5 as allowed extras.
- **MUST:** rename AWS `aws_error_code` to `code` (client.rs:392,408; errors.rs:254,261) and GCP `grpc_status` to `code` (client.rs:153,170). Record `code` on Azure from `BackendDetail::code`.
- **MUST (Azure):** apply the request-id filter (client.rs:212-215) before `span.record("request_id", …)` at client.rs:119-125. Today an attacker-influenced header value goes to logs unfiltered.
- **MUST (GCP):** record `key_version` inside `Client::call`, or open a handle-level span with `key_version = Empty` so handles.rs:686-689 has a target. As written, it is a no-op.
- **SHOULD:** record `request_id` on the GCP span (client.rs:164-176); record `key_version` on AWS (resolved ARN for sign/MAC/get-public-key) and Azure (the response `kid` version).
- **SHOULD:** use one token-span name and fields: `anykms.<backend>.token` with `backend, credential, outcome, error_kind, latency_ms, expires_in_s`. Rename GCP `credential_type` to `credential`. Add the span to AWS credential refresh. Add these fields to shared.md §5.
- **SHOULD:** update the Tracing sections of docs/operations-aws.md:179-187, docs/operations-gcp.md:190-198 and docs/azure.md:137-144 to the one schema. Azure's section omits `backend` and does not tell operators to cap `reqwest`/`hyper`/`rustls` at INFO; the other two do.

### 1.7 Handle types and openers (D4)

| Family | transit | AWS | GCP | Azure |
|---|---|---|---|---|
| AEAD | `TransitAeadKey` / `aead_key` | `AwsAeadKey` / `aead_key` | `GcpAeadKey` / `aead_key` | `AzureAeadKey` / `aead_key` (MHSM) |
| KEK | (AEAD) | `AwsKeyWrapKey` / `key_wrap_key` | **`GcpRsaKek` / `rsa_kek`** | `AzureKeyWrapKey` / `key_wrap_key` |
| Digest signing | `TransitDigestKey` / `digest_signing_key` | `AwsDigestKey` / `digest_signing_key` | `GcpDigestKey` / `digest_signing_key` | **`AzureSigningKey` / `signing_key`** |
| Ed25519 | `TransitEd25519Key` | `AwsEd25519Key` | `GcpEd25519Key` | n/a |
| MAC | `TransitMacKey` | `AwsMacKey` | `GcpMacKey` | `AzureMacKey` (feature) |
| Info | `TransitKeyInfo` | `AwsKeyInfo` | `GcpKeyInfo` + `GcpVersionInfo` | `AzureKeyInfo` + `AzureVersionInfo` + `AzureKeyType` |

- **SHOULD:** rename `GcpRsaKek`/`rsa_kek` to `GcpKeyWrapKey`/`key_wrap_key` (provider.rs:532; lib.rs:149). Rename `AzureSigningKey`/`signing_key` to `AzureDigestKey`/`digest_signing_key` (provider.rs:363; lib.rs:124). Both crates are unreleased, so the renames cost nothing now and are breaking later.
- **SHOULD (GCP):** `describe_key` returns a `GcpAeadKey` opened `TrustCaller` (provider.rs:541-546), so `describe_key(sig_uri).encrypt(..)` sends a request with no key-type check. Return a describe-only type, or make it `pub(crate)`.
- **SHOULD (AWS):** `aws_info()` / `verify_with_describe()` exist only on `AwsAeadKey` and `AwsDigestKey` (handles.rs:769,776,1103). Add them to all five handles (GCP and Azure expose `*_info()` on every handle).
- **SHOULD (Azure):** the typed API cannot request `local_verify`; `signing_key_with(.., &OpenOptions)` is private (provider.rs:372). Make it public, or add `signing_key_local_verify`.

### 1.8 `KeyInfo` construction

All three use `KeyInfo::new(native_type, caps).with_*` and `KeyVersionInfo::new(v, state).with_created_at(..)`; this is consistent. The differences are backend semantics, and each is documented:

- `backend_key_type`: AWS `KeySpec` (`RSA_2048`), GCP algorithm (`EC_SIGN_P256_SHA256`), Azure a composed `"RSA-HSM 3072"` / `"EC P-256"` (keyinfo.rs:379-385). OK; the field is native by contract.
- Key-level state: AWS `Some`, GCP `None` (per Appendix A), Azure `Some` from the current version.
- `primary_version`: AWS only for asymmetric/HMAC (the ARN), GCP only for `ENCRYPT_DECRYPT`, Azure always.
- **MUST (Azure):** `primary_version` and key-level `state` come from the URI's **pinned** version, not the current one. `azure_info` reads `get_bundle(self.uri.version())` (handles.rs:383) and `to_key_info` uses `self.version` (keyinfo.rs:415). azure.md §9 says primary = current. Every pinned signing URI (the JWKS case) reports the wrong primary.
  - Fix: when the URI is pinned, also GET the versionless bundle for `primary_version`/`state`.
  - Add a mock: describe a pinned URI after rotation.
- Azure sets `Capabilities::MAC` for oct-HSM keys but no `mac_algorithm` (keyinfo.rs:370-372, 412-416). This is correct: the key is not bound to one HS*. Add a doc line.

### 1.9 Package and CI hygiene (divergent between crates)

- `crates/anykms-aws/Cargo.toml:13-17,60`: still excludes `tests/conformance_*.rs` and comments "Not published (path only)". `anykms-conformance` is now versioned (Cargo.toml:26) and published (CHANGELOG). GCP excludes only the live targets; Azure excludes nothing. **SHOULD:** use one rule. Exclude only targets that need credentials or emulators, or none, and fix the stale AWS comment.
- CI layout differs per backend for no stated reason:
  - **AWS:** `aws-emulator`, `aws-localstack`, `aws-live`.
  - **GCP:** a step inside `check` plus `gcp-live`.
  - **Azure:** `azure` plus `azure-live`.

  Each cloud also re-runs mocks inside the workspace `cargo test`. Acceptable, but align the job names (`<cloud>-emulated`, `<cloud>-live`), as shared.md §6.4 planned (`cloud-emulated`, `cloud-live`).
- Live-probe task names differ in docs (`A0`, `T1`, `T3`/`T13`) because each plan numbered its own tasks. Fine, but each research doc should open with the same "probe status" header: script, last run, open rows.

## 2. Spec compliance per backend

### 2.1 AWS (`aws.md` §4–§10, Appendix A AWS column, Q7/Q12/Q14)

Most rows match: `Decrypt`/`ReEncrypt` always pin `KeyId`; local size limits; `IncorrectKeyException` hint; refresh-once; foreign version → `NotFound` with zero requests; grant-token limits; the layered `EncryptionContextAead` refuses `anykms-aad`.

| # | Deviation | Where | Verdict | Fix |
|---|---|---|---|---|
| A1 | **Unversioned signature/tag verifies with the handle's key** (reported departure) | handles.rs:520-523 | **OK, but the docs contradict it.** It is safe: absence cannot select a key. The suite's `Unversioned::UsesCurrent` exists for this case and e2e/mod.rs:391 declares it. | **MUST (doc):** lib.rs:39-40 says "a missing or malformed version `InvalidArgument`". Change it to "a missing version verifies with this handle's key; a malformed one is `InvalidArgument`". Update aws.md §8 and add a bullet to operations-aws.md:100-105. Record in shared.md that GCP and Azure reject unversioned input (`InvalidArgument`) while AWS accepts it, and why: AWS has one key per ARN, so there is no version choice. |
| A2 | **AAD cap 3072 bytes** (4096 base64url chars) (reported departure) | context.rs:27 (`MAX_AAD_BYTES`), :30 (`MAX_CONTEXT_BYTES` 4096) | **OK-doc.** Consistent with Q7 ("starts conservative, may only rise"). Documented in lib.rs:27, operations-aws.md:83-84, research/aws-kms.md:38 (to verify with A0). | aws.md §4: state the chosen 3072. The doc comments on the two `pub const`s should say the value may rise in a minor release. Add a positive boundary test (§4.1). |
| A3 | Foreign ARN → `NotFound` (aws.md §8 says `VerificationFailed`) | handles.rs:527-535 | OK-doc (follows Q12 / Appendix A) | Fix the stale aws.md §8 row. |
| A4 | Clock skew not retried in-backend | client.rs:467-469, errors.rs:191-194 | OK-doc (Q14) | aws.md §4: remove "retried once". |
| A5 | Symmetric `KeyInfo` lists the ARN as its one version, no primary | keyinfo.rs:205-215 | OK-doc (operations-aws.md:94-95) | aws.md §6. |
| A6 | RSA `KeyWrap` wraps locally (OAEP-SHA-256, pinned public key) | handles.rs:1021-1037 | OK-doc (cloud/README §2.5) | Fix the aws.md §5 last row. |
| A7 | Symmetric `key_wrap` is a dedicated `AwsKeyWrapKey` | provider.rs:312-318 | OK-undoc | One line in aws.md §5. |
| A8 | RSA KEK caps include `REWRAP` | keyinfo.rs:177-181 | OK-undoc | aws.md §6. |
| A9 | `AwsKeyInfo` lacks the MRK primary/replica ARNs aws.md §6 lists | keyinfo.rs:16-66 | OK-undoc (`#[non_exhaustive]`) | Add the fields, or drop them from aws.md. |
| A10 | Partial `XksProxy*` mapping | errors.rs:144-151 | OK (control-plane only) | Trim the aws.md §7 row. |
| A11 | Tracing names: `aws_error_code`, no `resource` | client.rs:381-395 | **MUST** (D3) | See §1.6. |

### 2.2 GCP (`gcp.md` §4–§10, Appendix A GCP column)

CRC32C rules match Appendix A: request CRCs and every `verified*` flag are checked, response CRCs are checked, and any failure is `Unavailable` (handles.rs:570-608, 780-806, 1196-1239, 1395-1405). Decrypt sends no version, `used_primary` is surfaced, and `KeyInfo.state` is `None`. Rewrap and DataKeys are `Unsupported` before I/O.

| # | Deviation | Where | Verdict | Fix |
|---|---|---|---|---|
| G1 | **Wrong version shape at open → `KeyMismatch`** (spec §4.4: `Configuration`) (reported departure) | provider.rs:449-466 | **OK-doc.** On GCP the URI shape is the only pre-I/O signal of key family, and the suite requires `KeyMismatch` for "HMAC key opened as AEAD" (anykms-conformance/src/cases/mac.rs:329-349). It is also consistent with AWS/Azure, where a wrong family is `KeyMismatch`. Per-call malformed versions stay `InvalidArgument` (handles.rs:881-891, 944-945, 1324-1330), as on AWS. Documented in gcp.md:17-19 and operations-gcp.md:24. | Update the gcp.md §4.4 table (lines ~221-222) so the plan is not self-contradictory. |
| G2 | Encrypt `key_version` recorded into no span | handles.rs:686-689 | **MUST** | §1.6. |
| G3 | **RSA KEK unwrap skips the OAEP-SHA-256 algorithm check**; `Provider::key_wrap` ignores `key_type_check` for RSA KEKs | handles.rs:1458-1492; provider.rs:571-580 | **MUST.** It violates Q10 ("SHA-1 OAEP keys are `KeyMismatch`"): a SHA-1/SHA-512 OAEP version would unwrap. | Call `self.oaep_key(op)` (cached) before `asymmetricDecrypt`; plumb `key_type_check`. |
| G4 | `describe_key` returns an `Aead`-capable handle | provider.rs:541 | SHOULD | §1.7. |
| G5 | Wrong-length tag → `VerificationFailed` (spec `InvalidArgument`) | handles.rs:1315-1323 | OK-doc (gcp.md:20-21) | none |
| G6 | No RSA backend → `Configuration` at open (spec: `compile_error!`) | provider.rs:365-375 | OK-doc (gcp.md:22-24). Recommended as the cross-backend rule (§1.3 item 4). | none |
| G7 | `ACCESS_TOKEN_SCOPE_INSUFFICIENT` → `Configuration`; `FAILED_PRECONDITION` "incorrect key purpose" → `KeyMismatch` | errors.rs:295-299, 311-327 | OK-undoc | Add both to the gcp.md §7 table and the operations-gcp.md runbook. |
| G8 | `asymmetricDecrypt` KEKs implemented (plan: non-goal) | handles.rs:1416 | OK-doc (gcp.md:25-28) | Update Appendix A (§3.4). |
| G9 | Error texts, empty-plaintext refusal and size limits are still assumptions | research/gcp-kms.md:3-6, 30; errors.rs:10 | OK-doc, **release-blocking until `scripts/probe-gcp.sh` runs** | none |

### 2.3 Azure (`azure.md` §4–§10, Appendix A Azure column, Q8/Q9/Q12/Q15)

The host allowlist, scope-from-host (Q8), frame (Q9), server-side verify by default (Q12), Premium oct-HSM refused and CLI opt-in (Q15), the `kty`/`key_ops` check, the RSA<2048 refusal, `nextLink` validation and `KeyWrapDataKeys` without AAD all match.

| # | Deviation | Where | Verdict | Fix |
|---|---|---|---|---|
| Z1 | **405 → versioned-path fallback** (reported departure) | handles.rs:289-327; flag on `Client` (client.rs:24-27) | **Behavior OK** (azure.md §5.1 plans a fallback "from the cached describe"). Two defects:<br>(a) **MUST:** after the flag flips, every write does an **uncached** `get_bundle(None, op)` (handles.rs:322) plus the POST. That doubles the request rate against Key Vault's 4000/10 s budget, and it is not what the spec says.<br>(b) SHOULD: the flag is per provider, not per host, so one Lowkey/test host flips it for production vaults.<br>Undocumented in docs/azure.md and azure.md. | (a) Use the cached `self.bundle(op)` current version; on 404/disabled, `forget()` and re-read once. Add `.expect(1)` on the GET in tests/mock.rs:318-368.<br>(b) Keep the flag per host.<br>Document it in docs/azure.md and in a new azure.md "Implementation notes" section (GCP has one at gcp.md:11). |
| Z2 | **Disabled key → `PermissionDenied`** (Appendix A: `KeyStateInvalid`) (reported departure) | errors.rs:187 | **OK-doc as interim.** azure.md §8 permits "unverified rows fall back to `PermissionDenied`". Documented in lib.rs:62-65, errors.rs:3-7, docs/azure.md:119, research/azure-kv.md:41. | **SHOULD before 0.2.x:** classify on the **inner error code** (no message matching). Inner `KeyDisabled` → `KeyStateInvalid` on Write/Read, `KeyVersionUnusable` on InputVersion; keep the `PermissionDenied` fallback when absent. Pin the code with T3. Record the interim state in Appendix A and §18 until then. |
| Z3 | `primary_version`/`state` from the pinned version | handles.rs:381-383, keyinfo.rs:412-415 | **MUST** | §1.8. |
| Z4 | Unfiltered `x-ms-request-id` on the span; tracing names off the allowlist | client.rs:119-125, 150-162 | **MUST** | §1.6. |
| Z5 | `.cloud()` narrows host suffixes; the authority comes from `AZURE_AUTHORITY_HOST` | provider.rs:114-121, cred/entra.rs:31-36 | OK-undoc | Fix azure.md §4.1. Consider having `from_env` call `.cloud(AzureCloud::from_authority_host(..))` so a sovereign-cloud credential is not offered public hosts. |
| Z6 | `ANYKMS_AZURE_ALLOWED_VAULTS` not in spec | provider.rs:314 | OK-undoc | azure.md §4.6 and docs/azure.md "Credentials". |
| Z7 | Frame version accepted as 32 hex only | handles.rs:351-361 | OK-undoc | docs/azure-ciphertext.md: "readers accept 32-hex versions only today". |
| Z8 | HMAC 64 KiB local cap (invented); `Unknown("unknown")` per-version fallback | handles.rs:1290-1300; keyinfo.rs:400-402 | OK-undoc | azure.md §5.4 / §9. |
| Z9 | 405 logged as an "unclassified" warn before the fallback | errors.rs:225 | cosmetic | Skip the warn for the 405 the fallback handles. |
| Z10 | Joined `code` (`a/b`) | errors.rs:245 | SHOULD | §1.5. |

## 3. Docs completeness

### 3.1 Operator docs

- **Rename** `docs/azure.md` → `docs/operations-azure.md` (D5). References to update:
  - CHANGELOG.md:80;
  - crates/anykms-azure/README.md:14;
  - docs/cloud/azure.md §12 if it names the path.

  No `.rs` file references `docs/azure.md`.
- **Header style:** operations-aws.md and operations-gcp.md say "Operating anykms with …" and link research docs relatively (`research/aws-kms.md`); docs/azure.md uses `docs/…` paths. Use relative links everywhere, so the docs work on GitHub.
- **Section parity:** every ops doc should have Keys/URIs, Permissions (IAM / key policy / RBAC), Credentials, **Environment** (all `ANYKMS_*` and vendor variables), Limits, Rotation and versions, Runbook, Tracing.
  - AWS lacks a separate "Environment" section (variables are spread over Credentials and Endpoints).
  - Azure lacks "Environment", "Limits" and "Rotation and versions" (the 405 fallback, version pinning for JWKS, the frame).
- **README links:** only GCP links its ops doc from the README feature table (README.md:313). Add rows for `aws` and `azure`.
- **docs/operations.md** (transit) says nothing about the cloud docs. Add a pointer at the top ("for AWS / GCP / Azure see …"). shared.md §6.2 planned "one section per cloud in docs/operations.md"; the separate files are better, so record that decision in shared.md.

### 3.2 README.md

| Line | Problem | Edit |
|---|---|---|
| 10-13 | "Supported backends are … transit … AWS KMS, GCP KMS and Azure Key Vault are planned" | "Supported backends: HashiCorp Vault and OpenBao transit, AWS KMS, Google Cloud KMS, Azure Key Vault and Managed HSM, and an in-process software backend for tests." Drop "planned". |
| 36-43 | Crate table has aws and gcp but **no `anykms-azure` row** and no `anykms-http` row. The conformance row says "not published in 0.1", but it is published now. | Add `anykms-azure` (Key Vault and Managed HSM; host allowlist; framed ciphertexts; facade feature `azure`) and `anykms-http` (internal HTTP plumbing for backends). Change the conformance row to "published; API may change in minor releases". Mention the facade feature in the GCP row like the AWS row does. |
| 110-117 | `with_default_providers()` paragraph talks only about transit | Add "Cloud providers whose feature is on are always registered (credentials are resolved on first use)". |
| 309-321 | Feature table has `gcp` but **no `aws`/`azure` rows**. `rustls-*` rows say "transit TLS". `rsa-*` rows say "local RSA verification" only. | Add `aws` and `azure` rows linking the ops docs. Reword `rustls-*` as "TLS for every HTTP backend" and `rsa-*` as "local RSA verification and local RSA-OAEP wrapping (AWS/GCP KEKs)". |
| 449-453 | Input-size bullet names only AWS | Add GCP (64 KiB plaintext, AAD 64 KiB) and Azure (RSA-OAEP: k−66 bytes; digest-only signing). |
| 456-460 | "`anykms-transit` needs a tokio runtime" | "The HTTP backends (transit, aws, gcp, azure) need a tokio runtime." |
| new | No cloud quick start | Add a three-line snippet per cloud (URI shape + `registry.key_wrap`/`digest_signer`), or one combined block. |

### 3.3 CHANGELOG.md (Unreleased)

- Line 12-13 (AWS): "always registered". Line 69-70 (GCP): "registered by `with_default_providers()`". The Azure entry (71-82) **does not mention registration**. After D2 all three say "always registered (credentials on first use)". Move this into one `anykms` (facade) bullet: features `aws`/`gcp`/`azure`, `rustls-*`/`rsa-*`/`tracing` forwarding, and registration.
- No facade entry exists at all for the new features. Add one under Added.
- Azure entry: rename the doc path (§3.1); add the 405 fallback and the interim disabled-key classification under a "Known limitations" subsection for Unreleased. GCP gets "live probe not run; error texts assumed". AWS gets "A0 probe not run; AAD cap conservative at 3072 bytes".
- Line 123 (`[0.1.0]` Known limitations: "backends are planned, not included") is correct for 0.1.0; leave it.
- After the D1/D4 renames, update handle names in the entries (`GcpRsaKek`, `AzureSigningKey`) and AWS's backend string, if it is mentioned.

### 3.4 Crate READMEs

- `crates/anykms-azure/README.md`: it does not follow the template the other eight use. It lacks the crates.io/docs.rs badges, the "Part of anykms … facade feature `azure`" paragraph, a code example (AWS has one), and the License section with links. Rewrite it from `crates/anykms-aws/README.md`.
- `crates/anykms-gcp/README.md`: no code example (AWS has one). Add a 3-line example and "facade crate (feature `gcp`)".
- All three should link the ops doc with the same absolute GitHub URL form (AWS and GCP do; Azure uses a bare path).

### 3.5 Research docs ("to verify" items)

| Doc | Open items | Action |
|---|---|---|
| docs/research/aws-kms.md | error shape (:26), RAW `Sign` limits (:36), context size (:38), `GenerateMac` `KeyId` (:52), state propagation (:65), `Retry-After` (:66), clock-skew code (:67), China dual-stack host (:72); Floci deviations (:94-99, incl. HMAC_384/512) | Run `scripts/probe-aws.sh` (A0). Release gate for 0.2.0 per §23 Q1. **Done 2026-10-07**: all rows verified live except `Retry-After` (throttling not provoked) and the China dual-stack host. |
| docs/research/gcp-kms.md | the whole §2 "Open facts (to verify with T1)" (:30 onward); the header says the probe has not run (:3-6) | Run `scripts/probe-gcp.sh record`. Gate for the GCP 0.2.x release. |
| docs/research/azure-kv.md | versionless ops (:18), PS salt (:22), verify on a malformed signature (:23), oct-HSM `key_size` (:28), 404 on input version (:40), disabled key/version (:41), nbf/exp (:42), key_ops (:43), damaged input (:44), wrong alg (:45), `Retry-After` (:47), sovereign MHSM suffixes (:58), all of §4 MHSM (:67) | Run `scripts/probe-azure.sh` (T3; T13 needs MHSM budget). Z2 depends on :41. |

Use one header format across the three (probe script, last-run date, count of open rows), and make each ops doc point to it as operations-aws.md:3-6 does.

### 3.6 PLAN.md: exact edits

1. **§0 Summary, PLAN.md:18-20.** Replace "AWS KMS, GCP KMS and Azure Key Vault are deferred. Appendix A shows that the core types can represent them." with: "AWS KMS, GCP Cloud KMS and Azure Key Vault / Managed HSM follow in 0.2 (§23, `docs/cloud/`); Appendix A records how each maps onto the core types."
2. **§2 Crate layout, PLAN.md:56-71.**
   - Add lines for `anykms-http` (shared HTTP plumbing, for anykms backends only), `anykms-aws`, `anykms-gcp` and `anykms-azure` (in-house REST clients on anykms-http; need a tokio runtime).
   - Facade optional features: add `aws, gcp, azure`.
   - Change "`anykms-conformance` … (dev-dependency of backends)" to "(published; dev-dependency of backends)".
   - Line 66: "needs a tokio runtime" applies to all HTTP backends.
3. **§3.5 KeyUri, PLAN.md:309.** "`aws-kms://arn:aws:kms:...` and Azure host-based URIs fit later" becomes "… are implemented (`aws-kms://arn:…`, `gcp-kms://projects/…`, `azure-kv://<host>/keys/…`, §23)".
4. **§10 Milestones, PLAN.md:853 (M5+).** Strike "AWS via LocalStack; Azure standard-vault `KeyWrap` data keys" and add a row: `M6 | Cloud backends (§23): conformance redesign, anykms-http, AWS, GCP, Azure | per-backend mock + emulated/fake conformance green on every PR; live probes A0/T1/T3 pinned in docs/research; live nightly jobs green`.
5. **§18 Implementation status, PLAN.md:1053-1060.** Add rows:
   - `M6 shared` = done: `anykms-http`, conformance redesign C1–C9 published, `WrappedDataKeys`, layered extensions, `DataKeysKey`, recipes R1–R3.
   - `AWS` = implemented; Floci emulated conformance per PR; LocalStack when a token is set; **A0 probe not run**.
   - `GCP` = implemented; fake-server conformance per PR; **T1 not run**.
   - `Azure` = release A + MHSM code implemented; Lowkey conformance per PR; **T3/T13 not run**; disabled key interim `PermissionDenied`; HMAC experimental.
   - Update M4's "9 fuzz targets" note: 24 targets now, cloud targets not yet given a CPU-hour.
6. **§18, PLAN.md:1240-1241.** Replace the "Azure MAC: no HMAC data-plane operation is known … keeps '—'" bullet with: "Azure MAC: Managed HSM has HS256/384/512 (API 7.6+, §23); `anykms-azure` ships it behind the experimental `mhsm-hmac` feature until T13 pins message-vs-digest semantics."
7. **Appendix A, PLAN.md:975-1009.**
   - Title (:975): "admissibility of core types for deferred providers" becomes "core types per cloud provider (implemented, §23)". Intro (:981-983): drop "*planned* … follow-ups"; say rows now describe the implementation and note interim deviations.
   - `KeyWrap` row (:990): AWS "asymmetric RSA `Decrypt` keys as a direct `KeyWrap` (*planned*)" becomes "RSA-OAEP-SHA-256 keys: wrap locally with the pinned public key, unwrap with `Decrypt`". GCP "`asymmetricDecrypt` keys (*planned*)" becomes "… implemented (`GcpKeyWrapKey`, local wrap, server unwrap)". Azure "(*planned*; …)" becomes "RSA-OAEP-256 `wrapKey`/`unwrapKey`; MHSM `A256KW`".
   - `DataKeys` row (:993): AWS "wrapped-only `GenerateDataKeyWithoutPlaintext` *planned*" becomes "wrapped-only via `WrappedDataKeys`". Azure "*planned* (§21)" becomes "`KeyWrapDataKeys` via `Provider::data_keys` (`DataKeysKey`, Q3)".
   - `Aead` AAD row (:989): replace "the limit is taken from AWS documentation when the backend is written" with "AWS documents no limit; the cap is 3072 AAD bytes (4096 base64url characters), conservative until the A0 probe, and may only rise (Q7)". Plaintext limit: "1–4096 bytes".
   - `KeyVersion` row (:994): add "an unversioned signature/tag verifies with the handle's key (no version choice exists per ARN)". Symmetric: "`KeyInfo` lists the ARN as the only version, no primary".
   - Verifier row: GCP "— native → `LocalVerifier`" for signatures; add "`Mac` uses server-side `macVerify`".
   - `Mac` row: Azure "MHSM HS256/384/512, experimental feature `mhsm-hmac` (Premium oct-HSM: not opened, Q15)".
   - Wrong key type row: add a GCP note: "a URI whose version shape does not fit the family (versioned AEAD, unversioned signing/MAC) is `KeyMismatch` at open".
   - Key-unusable row: Azure "disabled key → `KeyStateInvalid`" gets "(interim: `PermissionDenied` until T3 pins the inner error code)".
   - `Mac`/`MessageSigner` input-size row: GCP "limit to be confirmed" becomes the value the backend enforces (cite operations-gcp.md "Limits and quotas"), still marked T1.
   - Error-detail row: Azure "error code" becomes "the innermost error code" (after §1.5).
8. **§23** gets a closing paragraph, "Implementation (2026-10-06)", pointing to §18 and listing the agreed conventions: D1 (backend names), D2 (registration), D3 (span schema), D4 (handle names), D5 (ops doc names).
9. **docs/cloud/*.md status lines.**
   - README.md:3 and shared.md:3 "plan, not implemented" become "implemented; see PLAN §18".
   - aws.md:3 and azure.md:3 ("no code yet" / "Nothing implemented") become "implemented (2026-10-06); see Implementation notes". Add an "Implementation notes" section to aws.md and azure.md, as gcp.md:11 has, listing A1–A10 and Z1–Z8.
   - shared.md §0 "No shared cloud crate" and §5 opening: mark them superseded by README §2.1/Q4 (`anykms-http`).
   - shared.md §5: fix 3xx → `Configuration` (D6) and the allowlist (D3).
   - shared.md §6.2: registration rule (D2).

## 4. Test coverage gaps

### 4.1 AWS (`tests/mock.rs`, `tests/e2e/mod.rs`)

The `error_mapping_table` (mock.rs:842-988) covers every aws.md §7 row, plus `resource`/`code`/`request_id`/redaction, redirects, timeouts, refresh-once, clock skew, local limits, versions and the RSA wrap. Gaps:

- **HMAC-SHA-384/512 conformance** fails against Floci: the fixture maps `TestKeyKind::Hmac` to `HMAC_256` only (e2e/mod.rs:51; research/aws-kms.md:97-99). `Mac` is over-declared for 384/512. **Fix:** do what GCP's fixture does (one key per `MacAlgorithm`, gcp.md:31-35). This is a cross-backend divergence in fixture design that only GCP solved.
- No positive boundary test that exactly 3072 AAD bytes (a 4096-char value) is accepted (mock.rs:66 tests only 3073). Add it; it pins the wire cap.
- No `XksProxyInvalidResponseException` row (add at mock.rs:875).
- No foreign-ARN `public_key_version` test on `AwsEd25519Key` (only the digest key, mock.rs:605).
- Conformance n/a declarations (e2e/mod.rs:353-380) are all correct; nothing is declared n/a that AWS supports.

### 4.2 GCP (`tests/mock.rs`, `tests/e2e.rs`, fake server)

- **Response-integrity failures** are mocked only for encrypt/decrypt/macVerify (mock.rs:511-626). Missing:
  - `asymmetricSign` (`signatureCrc32c`, `verifiedDigestCrc32c`/`verifiedDataCrc32c`);
  - `macSign` (`macCrc32c`, `verifiedDataCrc32c`);
  - `getPublicKey` (`pemCrc32c`);
  - `asymmetricDecrypt` (`verifiedCiphertextCrc32c`, `plaintextCrc32c`);
  - the encrypt `verifiedAdditionalAuthenticatedDataCrc32c` flag.

  Add rows to `response_integrity_failures`. The fake (common/fake.rs:899-965) cannot corrupt these.
- **Name-mismatch checks** are tested only on encrypt (mock.rs:527). Add `getPublicKey`, `macSign`, `macVerify`, `cryptoKeys.get`, `cryptoKeyVersions.get` and list pages naming another key (handles.rs:232-271).
- **Error table only exercises the AEAD path** (mock.rs:216-421). Add `KeyVersionUnusable`/`NotFound` for `asymmetricSign`/`macSign`/`getPublicKey`, plus the verifier-cache drop on those kinds (handles.rs:322-333).
- `BILLING_DISABLED` and `ACCESS_TOKEN_SCOPE_INSUFFICIENT` → `Configuration` are untested (only `SERVICE_DISABLED`, mock.rs:340-346).
- `asymmetricDecrypt`: a tampered blob → `DecryptFailed` and a >512-byte blob refused locally are untested (only the round trip, e2e.rs:344). After G3, add an OAEP-SHA-1 version → `KeyMismatch`.
- **Conformance:** `EmptyPlaintext` is declared **n/a** although unverified (common/fixture.rs:579-582). The backend does not refuse it locally; only the fake does. Declare it `lacks` (reason: T1) so the case is not hidden permanently if the live service accepts empty input. AWS's n/a is justified by documentation, GCP's is not. Nothing else is declared n/a that GCP supports.

### 4.3 Azure (`tests/mock.rs`, `tests/common/mod.rs`)

- **`RequestCount` declared n/a** ("not modelled", common/mod.rs:558-565). AWS (e2e/mod.rs:352,522), GCP (fixture.rs:556,699) and transit all implement `counting()`, so the "rejected before I/O" cases never run on Azure. **MUST:** add a `#[doc(hidden)] __count_requests` on `AzureProviderBuilder` (as AWS does) and implement `Fixture::counting()`.
- **`UnauthorizedProvider` n/a on live** (common/mod.rs:581-584). azure.md §11.1 says *yes*. Add an optional no-role identity (`ANYKMS_AZURE_UNAUTHORIZED_*`), or a `StaticToken` minted for another resource.
- **`ServerErrorMessages` n/a on live** (common/mod.rs:576-580) follows from Z2. Re-enable after the `KeyDisabled` code rule.
- Mock gaps:
  - verify 400 `BadParameter` → `VerificationFailed` and 404 on the signature version → `VerificationFailed` are unit-only (errors.rs:343,351). Add HTTP mocks next to mock.rs:371.
  - MHSM GCM decrypt 400/404 → `DecryptFailed` (mock.rs:963).
  - truncated/invalid JSON success body → `Backend` (azure.md §11.3).
  - the 405 fallback's GET count (mock.rs:345-367, after Z1).
  - 403 on an input-version request.
  - the `x-ms-request-id` filter (overlong or non-graphic value dropped).
  - describe on a pinned URI after rotation (Z3).
  - standard-vault wrap input over k−66 → `InvalidArgument` with zero POSTs, if mock.rs:741 does not already cover it.
- The other n/a declarations (`Extension`, `Rewrap*`, `KeyWrapRewrap`, `WrappedDataKeys`, `MinDecryptionVersion`, `Throttle`, `NativeCiphertext`, `Signing(Ed25519)`; MHSM size cases pending T13) are correct.

### 4.4 Cross-backend test parity

- No hygiene test asserts **span field names** against the allowlist; each only greps TRACE output for secrets (aws tests/hygiene.rs, gcp tests/hygiene.rs:79, azure tests/hygiene.rs:73). After D3, add one shared helper (or one assertion per crate) that collects span field names and checks them against the allowlist. That would have caught `aws_error_code`, `grpc_status` and the missing `code`/`resource`.
- Facade tests (crates/anykms/src/lib.rs:~500-560) cover AWS skip/register only. Add tests for GCP and Azure registration under D2: Azure with no env registers; with `ANYKMS_AZURE_CREDENTIAL=none` it is skipped; a malformed env errors.

## 5. Priority list

**Must-fix before any cloud crate is published:**
1. D1: AWS backend string `aws-kms` → `aws` (aws lib.rs:94, facade lib.rs:187, tests).
2. D2: facade always registers Azure (lazy unconfigured credential); GCP and AWS both propagate malformed-env errors (facade lib.rs:192-234).
3. D3: span schema. `resource` and `code` on all three spans; Azure request-id filter; the GCP `key_version` no-op.
4. G3: GCP RSA KEK unwrap must check OAEP-SHA-256 (Q10).
5. Z1a: Azure 405 fallback must use the cached describe, not a GET per write.
6. Z3: Azure describe `primary_version`/`state` must be the current version.
7. A1 doc: aws lib.rs:39-40 contradicts the code.
8. Azure `RequestCount` fixture support.
9. README/CHANGELOG/PLAN edits of §3 (Azure missing from the README tables, "planned" text, Appendix A *planned* markers, §18 rows).

**Should-fix this cycle:** D4 renames (`GcpRsaKek`, `AzureSigningKey`, `AzureKeyUri`), Azure `rsa-*` features, the GCP `describe_key` type, Azure innermost `code`, the Azure `KeyDisabled` code rule (after T3), the `docs/azure.md` rename, the Azure crate README template, the AWS fixture HMAC-per-algorithm, GCP `EmptyPlaintext` → `lacks`, and the test gaps in §4.

**Release gates already known:** the live probes A0 / T1 / T3 (and T13 for MHSM) and every "to verify" row in docs/research.
