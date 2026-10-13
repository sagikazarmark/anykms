# anykms-azure: implementation plan

Status: **implemented** (2026-10-06) on `cloud-backends`: release A, and release B as code
(mock-tested, never run against a live Managed HSM). The live probes T3 and T13 have not run. See
"Implementation notes" below and PLAN §24. Written 2026-10-05 as a draft for maintainer review;
the plan text is kept, and places where the code departs from it are marked "Implemented as: …".
Plans the Azure Key Vault / Managed HSM backend that `docs/PLAN.md` §10 (M5+), Appendix A, §19, §21 and §22 defer.
Appendix A's Azure column holds decisions already made; this plan honors them and marks the few
places where research changed a fact (§1.3). Sources are listed in §15; facts not confirmed by a
primary source are marked **(unverified)** and become pinning tasks (§13).

## Implementation notes (2026-10-06)

Where the implementation differs from the plan below (rows Z1–Z10 of
[`review-consistency.md`](review-consistency.md) §2.3, plus the review fix round). The operator
guide is [`docs/operations-azure.md`](../operations-azure.md) (D5; it was `docs/azure.md`).

- **Shared HTTP code (Q9):** `anykms-http`, not a copied `zbuf.rs`.
- **Credential trait name (release plan 1.7, R-5):** the plan's `TokenCredential` trait (§2, §3,
  §4.1, §4.5, Q8) is `AzureCredential`, so it no longer shares its name with the Azure SDK's
  `azure_core::credentials::TokenCredential` (which `AzureIdentity` adapts). Besides `token` and
  `invalidate` it has `kind` and `tenant_id`.
- **Names (D4):** the signing handle is `AzureDigestKey`, opened with
  `AzureProvider::digest_signing_key` (and the public `digest_signing_key_with(.., &OpenOptions)`
  for `AzureOptions::local_verify`); KEKs are `AzureKeyWrapKey` (`key_wrap_key`, RSA-OAEP-256 on
  vaults, `A256KW` on Managed HSM); `AzureAeadKey` (`aead_key`) and `AzureMacKey` (`mac_key`,
  feature `mhsm-hmac`). The URI type is `AzureKeyRef` (`from_key_id`), not `AzureKeyUri`.
- **Lazy `from_env` (D2):** `AzureProvider::from_env()` and `AzureProviderBuilder::from_env()`
  build without a credential when none is configured; the first operation is then
  `Configuration` naming the variables. A malformed selection is a `Configuration` error from
  `from_env`. `ANYKMS_AZURE_CREDENTIAL=none` is the one explicit opt-out; the facade skips Azure
  only then (§3, §4.6).
- **Z1, 405 → versioned-path fallback:** a host that refuses versionless writes with 405 (Lowkey
  Vault) is remembered **per host**; writes on its unversioned URIs then name the current version
  from the cached key bundle (re-read once when that version is gone or refused), with no extra
  GET per write and no warning for the handled 405 (§5.1).
- **Key cache:** the key-type check's bundle cache is configurable with
  `AzureProviderBuilder::key_cache_ttl` (default 10 minutes ±10%).
- **Z2, disabled key:** classified on the inner error code since T3 (2026-10-12): `KeyDisabled`,
  `KeyNotYetValid`, `KeyExpired` → `KeyStateInvalid` (the handle's version) or
  `KeyVersionUnusable` (an input version); `KeyOperationForbidden` → `KeyMismatch` (§8).
  Key Vault reads a disabled key, so describe and preflight report its state
  (`Feature::PreflightState` runs live; Lowkey Vault answers 404 and keeps it not applicable).
  `Feature::Disable` is not applicable: there is no key-level flag.
- **Z3, `describe` on a pinned URI:** reports the key's **current** version as primary and its
  state as the key-level state; `AzureKeyInfo::current` names it when it differs from the pinned
  version (§9).
- **Pinned `public_key_version` (security review L1):** a handle opened on a pinned URI serves
  only that version's public key; any other version is `NotFound` before any I/O, matching
  verify, unwrap and decrypt. Publish every version (a JWKS) from the unversioned URI (§4.2).
- **Z4, Z10, tracing and error code (D3):** the shared span schema; `request_id` is recorded only
  after the `x-ms-request-id` filter (≤ 128 visible ASCII characters); `BackendDetail::code` and
  the span's `code` are the **innermost** Azure error code (`ForbiddenByRbac`), not codes joined
  with `/` (§8, §10).
- **Z5, sovereign clouds:** `AzureProviderBuilder::cloud` narrows the host suffixes; the
  credential's authority comes from `AZURE_AUTHORITY_HOST`. `from_env` does **not** derive
  `.cloud(..)` from `AZURE_AUTHORITY_HOST` (not done; operators set both) (§4.1).
- **Z6:** `ANYKMS_AZURE_ALLOWED_VAULTS` (comma-separated exact hosts) is read by `from_env` (§4.6).
- **Z7:** frame versions are accepted as 32 hex characters only today (§7).
- **Z8:** `mhsm-hmac` refuses input over 64 KiB before the request (an anykms limit until T13);
  a version state Azure does not describe is `Unknown("unknown")` (§5.4, §9).
- **RSA features:** `rsa-aws-lc-rs` (default) and `rsa-rustcrypto` give local RSA verification
  (`local_verify`); without one, opening an RSA algorithm for local verification is
  `Configuration`. The facade forwards them (§3).
- **Hardening from the security review:** the Azure CLI credential reads at most 64 KiB of
  output and checks `expires_on` without overflow (L2); `nextLink` keeps the pinned
  `api-version` (§5.2).
- **Tests:** a hidden `AzureProviderBuilder::__count_requests` lets the conformance fixture run
  the rejected-before-I/O cases (`RequestCount`); the live fixture runs `UnauthorizedProvider`
  when `ANYKMS_AZURE_UNAUTHORIZED_TOKEN` is set (§11.1).

## 0. Summary

- **First release (A):** standard and Premium vaults, the keys most users have: RSA and EC
  `DigestSigner` / `DigestVerifier` / `PublicKeys` / `Describe`; RSA-OAEP-256 as a native
  `KeyWrap` (envelope KEK); data keys from the KeyWrap-based recipe (non-empty AAD refused).
  The same handles work for RSA/EC keys on Managed HSM.
- **Second release (B):** Managed HSM `oct-HSM` keys: AES-GCM `Aead` (framed ciphertext),
  `EmulatedDataKeys` over it, native AES-KW `KeyWrap`, HMAC `Mac`. Deferred until a gated real
  MHSM run has pinned the facts no emulator covers (IV/tag sizes, error messages, HMAC input).
  Implemented as: the code shipped with A (mock-tested); HMAC is behind the experimental
  `mhsm-hmac` feature; T13 still has to pin the facts above.
- **Client:** in-house REST client on reqwest + rustls, as transit (§6.1). The official Azure SDK
  for Rust is GA but needs Rust 1.88 (MSRV is 1.85) and fights several anykms rules (§2).
- **Auth:** bearer tokens from a small set of in-house Entra ID credentials, lazily; the token
  scope comes from the allowlisted host suffix, never from a server challenge (§4.4).
- **Proof:** the conformance suite after its capability redesign (PLAN §22, prerequisite P1)
  against Lowkey Vault in CI, wiremock for errors and auth, env-gated real-Azure runs.

## 1. Scope

### 1.1 First release (A): standard vault

| Key (`kty`) | anykms handles | Notes |
|---|---|---|
| `RSA`, `RSA-HSM` 2048/3072/4096 | `DigestSigner`+`DigestVerifier`+`PublicKeys`+`Describe` (PS*/RS*); `KeyWrap` (RSA-OAEP-256) + `Describe`; `DataKeys` (recipe over the `KeyWrap`) | one key may be opened both ways if its `key_ops` allow; docs say a KEK must be dedicated |
| `EC`, `EC-HSM` P-256/P-384/P-521 | `DigestSigner`+`DigestVerifier`+`PublicKeys`+`Describe` (ES256/384/512) | raw r‖s → DER |
| `EC` P-256K | none: `KeyMismatch` at the key-type check | secp256k1 is planned in core (PLAN §21 "Algorithms"); added when `SignatureAlgorithm` gains it |

Works unchanged against `*.managedhsm.azure.net` for RSA-HSM/EC-HSM keys (same REST API).

### 1.2 Second release (B): Managed HSM symmetric keys

| Key | anykms handles |
|---|---|
| `oct-HSM` AES-256 on MHSM | `Aead` (A256GCM, framed, §7) + `DataKeys` (`EmulatedDataKeys` over the `Aead`, AAD bound) + `Describe`; `KeyWrap` native (A256KW, §7) |
| `oct-HSM` AES-128/192 | refused (`KeyMismatch`): wraps 256-bit DEKs at lower strength; revisit on demand |
| `oct-HSM` HMAC keys on MHSM | `Mac` (HS256/384/512, alg bound to key) + `Describe`, subject to open question Q4 |
| `oct-HSM` on Premium vaults | same code path, **not promised** (preview, PLAN Appendix A); conformance never runs it |

### 1.3 Research corrections to PLAN

- **Azure MAC exists** (PLAN §18 "Azure MAC", §17): API 7.6 added HS256/384/512 to `sign`/`verify`
  for `oct-HSM` keys, GA on Managed HSM, public preview on Premium vaults. Appendix A's `Mac` row
  already says so; §18's "no HMAC data-plane op known" is stale. Update §18 when B lands.
- **Server-side `verify` is not deprecated** (2025-07-01): kept "as a convenience";
  Microsoft recommends local verification for performance and throttling (§5.3).
- **KeyVersion:** docs call it a "system-generated, 32 character string", not "hex". The parser
  accepts what Azure issues today (32 hex) and the ciphertext frame length-prefixes the version so
  a format change never breaks stored data (§6.3, §7).
- **China authority host** is `login.partner.microsoftonline.cn` (`login.chinacloudapi.cn` is a
  legacy alias).

### 1.4 Non-goals

Key creation, rotation, deletion, rotation policies, import, backup (IaC; fixtures do it outside
the public API). Secure key release (`/release`, TEE attestation). `securewrapkey`, external keys,
ML-DSA (`AKP`): preview APIs only. RSA1_5 and RSA-OAEP (SHA-1) for wrapping (decrypt-only interop
is open question Q6). AES-CBC/CBCPAD (not AEAD). `RSNULL`. Asymmetric decrypt of foreign
ciphertexts (`AsymmetricDecrypt`, PLAN §10). Certificates and secrets. Key Vault control plane
(ARM). A probing `DefaultAzureCredential` chain (§4.5). wasm.

## 2. Client decision

Evaluated 2026-10 (crates.io, docs.rs sources, `cargo tree` in a scratch crate):

| | Azure SDK for Rust (`azure_security_keyvault_keys` 1.0.1, `azure_core` 1.1.0, `azure_identity` 1.0.0) | in-house |
|---|---|---|
| Status | GA since 2026-05; 0.x broke almost monthly | ours |
| MSRV | **1.88** (since `azure_core` 0.32 / keys 0.11, 2026-02); 1.85 only on pre-GA 0.31/0.10 without the 1.0.1 challenge fix | 1.85 |
| TLS | default `reqwest/rustls` → aws-lc-rs; a custom `HttpClient` transport works (checked: own reqwest + ring compiles without aws-lc) | reqwest `rustls-no-provider`, ring/aws-lc-rs per feature, as transit |
| Retries | 8 retries by default in clients **and** credentials; `RetryOptions::none()` on each | none (PLAN §11) |
| Credentials | Managed, Workload, CLI, azd, ClientSecret, ClientAssertion, Pipelines; ClientCertificate pulls openssl; `DefaultAzureCredential` removed; `WorkloadIdentityCredential::new` reads the token file eagerly | small set, lazy (§4.5) |
| Challenge | `KeyVaultAuthorizer`: unauthenticated first request, `verify_challenge_resource` (host must end in `.<resource host>`) | not used: scope from allowlisted suffix (§4.4) |
| Tests | bearer policy refuses non-`https` URLs → wiremock needs a redirecting transport | loopback HTTP opt-in, as transit |
| Weight | ~88 extra crates (typespec*, async-trait, async-lock, futures, time+macros, url/ICU, uuid, rand 0.10, dyn-clone, syn) | reqwest + serde_json (already in tree) |
| Error detail | typed errors, our mapping still needed | direct access to code, innererror, `x-ms-request-id`, `Retry-After` |

**Decision: in-house** (`client.rs` ≈ transit's). The MSRV gap alone blocks the SDK; the retry,
eager-credential and https-only points would each need workarounds, and the data-plane surface we
use is eight JSON endpoints. Re-evaluate if anykms's MSRV reaches 1.88: the SDK's credential
coverage (certificates, Arc, Pipelines) is the part worth having, and §4.5's `TokenCredential`
trait lets an application plug `azure_identity` in with a ~20-line adapter today (documented
example, no dependency). (Superseded 2026-10-12: the workspace is on 1.91 and the adapter ships
as `AzureIdentity`, feature `azure-identity`; the in-house Azure CLI credential was removed in its
favour. See [credentials-plan.md](credentials-plan.md).)

## 3. Crate layout

```
crates/anykms-azure/
  src/lib.rs        crate docs ("Behavior worth knowing"), BACKEND = "azure", re-exports
      config.rs     AzureProvider builder, AzureCloud, HostPolicy, EnvConfig
      uri.rs        azure-kv:// parser, host allowlist, key-id <-> URI helpers   (fuzzed)
      client.rs     reqwest client, request building, response limits, zeroizing bodies
      credential.rs TokenCredential trait, token cache (single flight, early refresh)
      cred/         managed_identity.rs (IMDS, App Service), workload.rs, client_secret.rs,
                    cli.rs, static_.rs
      errors.rs     status/code/message classification (pinned table, §8)
      keyinfo.rs    KeyBundle/JWK parsing, AzureKeyInfo, JWK -> SPKI DER           (fuzzed)
      framing.rs    anykms ciphertext frame (§7)                                  (fuzzed)
      handles.rs    AzureDigestKey, AzureKeyWrapKey (RSA-OAEP-256; A256KW in B), AzureAeadKey (B),
                    AzureMacKey (B); key-type check + describe cache
      provider.rs   impl Provider (digest_signer, digest_verifier, public_keys, describe,
                    key_wrap, data_keys*, aead (B), mac (B))
      zbuf.rs       copy of transit's zeroizing buffer (or move to a shared private module, Q9)
  tests/ mock.rs (wiremock), hygiene.rs, credentials.rs, conformance_lowkey.rs,
         conformance_azure.rs (env-gated), conformance_mhsm.rs (env-gated), integration.rs, common/
```

Implemented as: transit-style handle names (D4; the plan named the signing and wrapping handles
differently); `uri.rs` has `AzureKeyRef`; `cred/` is `entra.rs`
(workload identity, client secret), `managed_identity.rs`, `cli.rs`, `mod.rs` (`from_env`
selection), with `StaticToken` in `credential.rs`; no `zbuf.rs` (`anykms-http`). Tests:
`mock.rs`, `credentials.rs`, `hygiene.rs`, `vectors.rs`, `lowkey.rs`, `live.rs`,
`conformance_lowkey.rs`, `conformance_azure.rs`, `conformance_mhsm.rs`, `common/`.

- **Deps:** anykms-core, anykms-recipes (`default-features = false`; `KeyWrapDataKeys` and
  `EmulatedDataKeys`, both ungated; PLAN §2 allows backend → recipes), reqwest, rustls,
  rustls-native-certs, serde/serde_json, base64, zeroize, tokio (`sync`), url, httpdate,
  optional tracing. JWK → SPKI: a small DER writer for RSA, `p256`/`p384`/`p521` (workspace
  deps, already in recipes) for EC point validation and SPKI. No openssl, no async-trait.
- **Features:** `default = ["rustls-ring"]` (*superseded by PLAN §25.3 C2: the default is
  `rustls-aws-lc-rs`*); `rustls-ring`, `rustls-aws-lc-rs`, `tracing`,
  `http2`; `cli-credential` (the `az` subprocess source; default **on**? Q7). No `mhsm` feature:
  MHSM support is runtime, gated by the key and host.
  Implemented as: `default = ["rustls-ring", "rsa-aws-lc-rs"]` (*superseded by PLAN §25.3 C2:
  `rustls-aws-lc-rs`*); `rsa-aws-lc-rs` /
  `rsa-rustcrypto` (local RSA verification); `cli-credential` opt-in (Q7); and the experimental
  `mhsm-hmac` for HMAC on Managed HSM (the rest of MHSM support is runtime, as planned).
- **Facade:** feature `azure = ["dep:anykms-azure"]`; `rustls-*` and `tracing` forward with `?`;
  `with_default_providers()` adds `AzureProvider::from_env()` and records it as skipped (with the
  reason) when no Azure configuration is present, like transit.
  Implemented as (D2): Azure is **always registered** when the feature is on, since `from_env`
  builds without a credential (first use is `Configuration`); a malformed environment is an
  error from `with_default_providers()`; only `ANYKMS_AZURE_CREDENTIAL=none` skips it. `rsa-*`
  and `http2` forward too.
- Excluded from the package: `tests/common`, `tests/conformance_*.rs`, `tests/integration.rs`
  (path-only conformance dev-dependency, PLAN §22), until P1 publishes the suite.
  Implemented as: nothing is excluded (`anykms-conformance` is published).
- Size: ≈3–3.5k LOC for A (client 0.8k, credentials 0.9k, handles 0.8k, uri/config 0.6k,
  errors/keyinfo 0.5k), +0.8k for B.

## 4. Configuration, URIs, credentials

### 4.1 Builder

```rust
AzureProvider::builder()
    .credential(WorkloadIdentity::from_env())       // or ManagedIdentity::system(), ClientSecret::new(..),
                                                    // AzureCli::new(), StaticToken::new(..), Arc<dyn TokenCredential>
    .cloud(AzureCloud::Public)                      // authority host for built-in credentials; default Public
    .allowed_vaults(["contoso-prod.vault.azure.net"])   // optional: exact hosts (default: any allowlisted)
    .api_version(ApiVersion::V2025_07_01)           // one pinned value; others unsupported in 0.x
    .connect_timeout(2s).request_timeout(10s)       // per attempt
    .pool_idle_timeout(50s).tcp_keepalive(30s).proxy(Proxy::None).http_version(HttpVersion::Http1)
    .crypto_provider(..)                            // as transit §20
    .build()?;                                      // no I/O
AzureProvider::from_env()?;                         // §4.6
```

TLS, redirects (`Policy::none()`, any 3xx → `Configuration`), response-size caps, zeroizing
request/response buffers and loopback-only plain HTTP all copy transit (§6.2, §20 of PLAN).
`ca_pem` exists only for test hosts (§4.3).

Implemented as: the shared `anykms-http` code instead of copies. `.cloud(..)` also **narrows the
allowed host suffixes** to that cloud's, while the built-in credentials take their authority
from `AZURE_AUTHORITY_HOST` (Z5; `from_env` does not yet set `.cloud(..)` from it). Added:
`.key_cache_ttl(d)` (the key-type check's bundle cache, default 10 minutes),
`.test_host(TestHost::https(..) | TestHost::loopback_http(..))`, `.max_response_bytes(n)`, and
`AzureProviderBuilder::from_env()` to adjust the environment's builder before `build()`.

### 4.2 Key URI

```
azure-kv://<host>/keys/<name>[/<version>]
  host    = <vault>.<suffix>  (one DNS label, [a-z0-9-]{3,24}, lowercased; no port, no userinfo)
  name    = [0-9A-Za-z-]{1,127}
  version = 32 hex chars, case-insensitive, normalized to lowercase
```

- One scheme for vaults and MHSM: the host suffix decides (`vault.*` vs `managedhsm.*`) the token
  scope and which handle kinds may open (`aead`/`mac` refuse vault hosts with `Unsupported` at
  open, no I/O, unless `allow_premium_oct()`; Q3).
- Rejected: query, fragment, percent-encoding, trailing slash, `.`/`..`, other path shapes
  (`/secrets/…`, `/deletedkeys/…`). Names compare case-insensitively (Azure does), so the
  describe cache and the response-`kid` check use lowercased names.
- Helpers: `AzureKeyRef::from_key_id("https://v.vault.azure.net/keys/k/abc…")` and
  `to_key_id()`; `https` is never registered as a scheme.
- **Version pinning.** With a version: every operation uses it (writes too), `public_key()` is
  that version's. Without: writes use the current version (versionless request, version read from
  the response `kid`, §5.1), `public_key()` is the current one (Appendix A).
  Implemented with the pin authoritative for public keys too (security review L1): on a pinned
  URI, `public_key_version(v)` with `v` ≠ the pinned version is `NotFound` before any I/O, as
  verify, unwrap and decrypt already refuse another version. A JWKS of every version comes from
  the unversioned URI.

### 4.3 Host allowlist (security boundary)

A bearer token is sent only to an allowlisted host. Default suffixes (Appendix A, §21: MHSM and
sovereign clouds included, all Microsoft-operated):

| Cloud | Vault suffix → token scope | MHSM suffix → token scope |
|---|---|---|
| Public | `vault.azure.net` → `https://vault.azure.net/.default` | `managedhsm.azure.net` → `https://managedhsm.azure.net/.default` |
| China (21Vianet) | `vault.azure.cn` → `https://vault.azure.cn/.default` | `managedhsm.azure.cn` → `https://managedhsm.azure.cn/.default` (unverified) |
| US Gov | `vault.usgovcloudapi.net` → `https://vault.usgovcloudapi.net/.default` | `managedhsm.usgovcloudapi.net` → `https://managedhsm.usgovcloudapi.net/.default` (unverified) |

- Germany (`vault.microsoftazure.de`) is retired and not listed. Private endpoints keep the public
  hostname (CNAME to `privatelink.vaultcore.azure.net`), so no extra suffix.
- `allowed_vaults([...])` narrows to exact hosts (recommended when URIs come from shared config).
- `HostPolicy::test_host("127.0.0.1:8443", scope)`: exact `host:port`, needs `ca_pem` or
  loopback HTTP, explicit scope. For Lowkey Vault and wiremock only; logged at WARN on every open.
  Implemented as `AzureProviderBuilder::test_host(TestHost::https("127.0.0.1:8443", scope))` or
  `TestHost::loopback_http(..)` (`.managed_hsm()` for an MHSM-shaped test host); no environment
  variable can add one.
- A host outside the policy is `Configuration` at open (no I/O), naming the host.
- The token's cloud is the credential's; a public-cloud credential asked for a China scope fails
  at token time with `Unauthenticated` (Entra's error), and docs say: one provider per cloud.

### 4.4 Challenge flow: not used for discovery

Azure SDKs send an unauthenticated request, read `WWW-Authenticate: Bearer authorization="…/<tenant>",
resource="…"` and fetch a token for that resource/tenant, checking the vault host ends with the
resource's host. **Decision:** anykms derives the scope from the allowlisted suffix (table above)
and the tenant from the credential configuration, so:

- no server-supplied value ever chooses what token is minted or where it goes;
- no extra unauthenticated round trip (and no body stripping) per client;
- Lowkey Vault (which advertises its own base URI as resource) needs no "disable verification".

On a 401 the client reads the challenge for diagnostics only: if its tenant differs from the
credential's, the `Unauthenticated` error says "vault belongs to tenant <id>; configure
AZURE_TENANT_ID" (tenant ids are not secret). Multi-tenant discovery
(`tenant_from_challenge()`) is open question Q2.

### 4.5 Credentials

```rust
pub trait TokenCredential: Send + Sync + fmt::Debug {        // object-safe, like transit's TokenSource
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, Result<AccessToken>>;  // AccessToken: Zeroizing secret + expires_at
    fn invalidate(&self, scope: &str, rejected: &AccessToken) {}
}
```

| Source | Mechanism | Notes |
|---|---|---|
| `WorkloadIdentity` (AKS) | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_AUTHORITY_HOST`; `POST {authority}/{tenant}/oauth2/v2.0/token` `grant_type=client_credentials`, `client_assertion_type=…jwt-bearer`, `client_assertion=<file>`, `scope` | file read **at each exchange** (rotates; lazy, unlike the SDK); bounded read, permission warning as transit `FileToken` |
| `ManagedIdentity` | IMDS `GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<scope minus /.default>`, `Metadata: true`; App Service/Functions `IDENTITY_ENDPOINT` + `X-IDENTITY-HEADER`, api 2019-08-01; user-assigned via `client_id`/`object_id`/`msi_res_id` | never through a proxy; 1 s connect timeout (fail fast off Azure); `expires_on` is a string. Arc and Cloud Shell: later (Q8) |
| `ClientSecret` | same token POST with `client_secret` | secret held as `Zeroizing<String>`, from `AZURE_CLIENT_SECRET` |
| `AzureCli` | `az account get-access-token --resource <r> [--tenant t] -o json`, read `accessToken`, `expires_on` (POSIX, CLI ≥ 2.54) | developer use; 10 s timeout; stderr redacted; never in `from_env` unless asked (§4.6) |
| `StaticToken` | caller-supplied token | tests, Lowkey Vault |
| custom | `Arc<dyn TokenCredential>` | e.g. an `azure_identity` adapter (docs example) |

Implemented as (release plan 1.7): the trait is `AzureCredential`, with `kind` and `tenant_id`
besides `token` and `invalidate`; the `azure_identity` adapter ships as `AzureIdentity`, and
`AzureCli` was removed (see the implementation notes).

- **Cache** per scope in the provider: single flight (`tokio::sync::Mutex`, as transit `Login`),
  refresh 5 min before `expires_at` (or at half-life for tokens under 10 min), never logged.
- **Lazy:** nothing is read or fetched at build (PLAN §19 "Async credentials"); env presence is
  checked at build so a missing configuration is `Configuration` early.
  Implemented as (D2): a **missing** credential configuration is no longer an early error; the
  provider builds and the first operation is `Configuration` naming the variables, as on AWS
  and GCP. A **malformed** one still fails at build.
- **401 handling:** `invalidate`, fetch again, retry the request **once** if the token changed
  (transit §6.2 rule; not multiplied by `Retry`).
- **Errors:** token endpoint 400/401 (`invalid_client`, `AADSTS*`) → `Unauthenticated` with the
  AADSTS code in `BackendDetail::code`; IMDS unreachable/404/410/429/5xx → `Unavailable`
  (retryable; IMDS asks for backoff); CLI missing or not logged in → `Configuration`.
- Client-certificate credentials (JWT signed PS256 with `x5t#S256`) are deferred (Q8): they need
  RSA private-key signing, which anykms does not otherwise do.

### 4.6 `from_env`

Credential selection is **deterministic, by environment, no network probing** (the Rust SDK
dropped `DefaultAzureCredential` for the same reason; Appendix A's "DefaultAzureCredential-style
chain, lazily" is met as "the same sources, picked by env"):

1. `ANYKMS_AZURE_CREDENTIAL` = `workload|managed|secret|cli|none` forces one;
2. else `AZURE_FEDERATED_TOKEN_FILE` set → workload identity;
3. else `AZURE_CLIENT_SECRET` set → client secret;
4. else `IDENTITY_ENDPOINT` set or `ANYKMS_AZURE_MANAGED_IDENTITY=1` → managed identity
   (`AZURE_CLIENT_ID` selects a user-assigned identity);
5. else `Configuration` ("no Azure credential configured"; the facade records the provider as
   skipped).
   Implemented as (D2): `from_env` succeeds with an unconfigured credential whose first token
   fetch is `Configuration` naming the variables; the facade registers the provider. Only
   `ANYKMS_AZURE_CREDENTIAL=none` makes `from_env` fail and the facade skip Azure.

The chosen source is logged at INFO (kind only). `AZURE_AUTHORITY_HOST` picks the cloud.
Implemented as: `AZURE_AUTHORITY_HOST` picks the credential's authority only; the host
suffixes stay those of every cloud unless the builder calls `.cloud(..)` (Z5, not done in
`from_env`). `from_env` also reads `ANYKMS_AZURE_ALLOWED_VAULTS` (comma-separated exact hosts,
Z6).
Plain IMDS without an opt-in is not auto-selected: on a non-Azure host it would hang on the
connect timeout at every operation.

### 4.7 API version

Pin **`2025-07-01`** (latest GA; byte-identical to 7.6 apart from the version string, and the
default of the Rust SDK). It has every operation planned (HS* and `CKM_AES_KEY_WRAP` arrived in
7.6). Lowkey Vault supports it. Previews (`2026-*-preview`) are never sent.

## 5. Operation mapping

All requests: `POST https://<host>/keys/<name>[/<version>]/<op>?api-version=2025-07-01`,
`Authorization: Bearer`, JSON body with only the fields listed; base64url without padding.

### 5.1 Common rules

- **Writes (encrypt, wrapkey, sign) on an unpinned URI** go versionless; the response `kid` must
  parse as `https://<same host>/keys/<same name, case-insensitive>/<version>`, else `Backend`
  (fail closed). The stable swagger marks `{version}` required but the auth docs show versionless
  POSTs: **pin with a live test (T3)**; fallback: the current version from the cached describe,
  refreshed on `KeyVersionUnusable`.
  Implemented as (Z1): versionless writes by default; a host that answers 405 (Lowkey Vault does;
  T3 decides whether Azure ever does) is remembered **per host**, and later writes on its
  unversioned URIs name the current version from the cached key bundle (`key_cache_ttl`); when
  that version is gone or refused, the bundle is re-read once. No GET per write; the handled 405
  logs an INFO event, not a warning.
- **Reads of old data (decrypt, unwrapkey, verify)** always use the version from the input (frame
  or `Signature::key_version`); a missing version is `InvalidArgument` before I/O.
- **Key-type check** before the first operation, via a per-provider describe cache
  (`GET /keys/<name>[/<version>]`, 10 min TTL, dropped on `NotFound`/`KeyMismatch`), as transit
  §3.3; `KeyTypeCheck::TrustCaller` opts out. Needs `keys/read`, in every role we recommend.
- Local validation before I/O: digest algorithm/length vs handle algorithm, signature shape
  (DER parse, scalar sizes), frame parse, wrap input size.

### 5.2 Standard vault (A)

| anykms op | REST | Request → response handling |
|---|---|---|
| `DigestSigner::sign_digest` | `sign` | `{alg, value: digest}` → `{kid, value}`; ECDSA: `value` must be exactly 2×scalar bytes, converted to DER (`ecdsa_der`); RSA: length = modulus bytes. `Signature { alg, key_version: kid version }` |
| `DigestVerifier::verify_digest` | `verify` (server-side) | ECDSA DER → raw r‖s first; `{alg, digest, value}` → `{value: bool}`; `false` → `VerificationFailed`. See §5.3 |
| `PublicKeys::public_key` / `_version` | `GET /keys/<name>[/<v>]` | JWK (`n`,`e` / `crv`,`x`,`y`) → SPKI DER; EC point validated on curve; `key_version` from `kid`. A version ≠ 32 hex → `NotFound` before I/O (the version often comes from a JWT `kid`). Implemented with: on a pinned URI, a version other than the pinned one → `NotFound` before I/O (L1) |
| `KeyWrap::wrap_key` | `wrapkey` | `{alg: "RSA-OAEP-256", value: key}` → `{kid, value}`; input ≤ k−66 bytes (k = modulus bytes) else `InvalidArgument` locally; output framed (§7) |
| `KeyWrap::unwrap_key` | `unwrapkey` (versioned) | frame parsed; `{alg, value}` → `{value}` (zeroizing); every failure that depends on the input → `DecryptFailed` (§8) |
| `KeyWrap::wrapped_key_version` | local | from the frame |
| `DataKeys::generate_data_key` | recipe | `KeyWrapDataKeys` (P4): 32 random bytes, `wrap_key`; non-empty AAD → `Unsupported` before I/O |
| `Describe::describe` | `GET /keys/<name>` + `GET /keys/<name>/versions` (paged) | §9. `nextLink` followed only if same host and path; at most 10 pages, then `versions` is truncated (documented). Implemented with: the pinned `api-version` re-applied to every `nextLink`; on a pinned URI the versionless bundle is read too, for the current version (Z3) |
| `Rewrap` | — | `Unsupported` (no server re-encrypt); envelopes use `rewrap_local` |
| `Aead`, `Mac`, `MessageSigner` | — | not opened (`Unsupported` at open on vault hosts) |

### 5.3 Verify: server or local

Default: **server `verify`**, consistent with transit, honoring disabled keys and the audit log,
needing only `verify/action`. Docs steer high-volume verification (JWKS consumers) to
`CachedVerifier` over the handle's `PublicKeys` (Microsoft's own advice; verify counts against the
vault's 4000/10 s budget). Note: Azure lets `verify` run outside the `nbf`/`exp` window but not on
disabled keys. Option `AzureOptions::local_verify()` (an `OpenOptions` extension) builds the
verifier part from `LocalVerifier`; Q5 asks whether it should be the default.
Implemented as: server-side by default (PLAN §23 Q12); `AzureOptions::local_verify()` is passed
through the public `AzureProvider::digest_signing_key_with(uri, alg, &OpenOptions)`. Local RSA
verification needs the `rsa-aws-lc-rs` (default) or `rsa-rustcrypto` feature; without one,
opening an RSA algorithm with `local_verify` is `Configuration`.

### 5.4 Managed HSM additions (B)

| anykms op | REST | Handling |
|---|---|---|
| `Aead::encrypt` | `encrypt` | `{alg: "A256GCM", value: pt, aad?}` (no `iv`: the service generates it and rejects a client IV); `aad` omitted when empty → `{kid, value, iv, tag}`; `iv` must be 12 B and `tag` 16 B (**unverified**, pinned in T10) else `Backend`; framed |
| `Aead::decrypt` | `decrypt` (versioned) | `{alg, value: ct, iv, tag, aad?}` → `{value}` zeroizing |
| `ciphertext_version` | local | frame |
| `DataKeys` | recipe | `EmulatedDataKeys` over the handle (AAD bound) |
| `KeyWrap` (`Provider::key_wrap` on an AES key) | `wrapkey`/`unwrapkey` | `A256KW` (RFC 3394), native, not `AeadKeyWrap`; 32-byte input only (multiple of 8, ≥16) |
| `Mac::mac` / `verify_mac` | `sign` / `verify` | `{alg: HS256…, value}`; whether `value` is the message or a digest is **unverified** (Q4); server verify. Implemented behind the experimental `mhsm-hmac` feature, sending the message, with a 64 KiB input cap checked before the request (Z8) until T13 |
| plaintext limit | — | undocumented for GCM; conformance `OversizePlaintext` declared only once measured (T10) |

## 6. Algorithms and key-type check

### 6.1 Algorithm mapping

| anykms | Azure `alg` | key |
|---|---|---|
| `EcdsaP256Sha256` / `P384Sha384` / `P521Sha512` | `ES256` / `ES384` / `ES512` | `EC`/`EC-HSM`, `crv` P-256/P-384/P-521 (must match) |
| `RsaPssSha256/384/512` | `PS256/384/512` | `RSA`/`RSA-HSM` |
| `RsaPkcs1v15Sha256/384/512` | `RS256/384/512` | `RSA`/`RSA-HSM` |
| `HmacSha256/384/512` (B) | `HS256/384/512` | `oct-HSM` (MHSM) |
| `KeyWrap` on RSA | `RSA-OAEP-256` (SHA-256, MGF1-SHA-256) | `RSA`/`RSA-HSM` |
| `Aead` (B) | `A256GCM` | `oct-HSM` 256-bit |
| `KeyWrap` on AES (B) | `A256KW` | `oct-HSM` 256-bit |
| — (not used) | `RSA-OAEP` (SHA-1), `RSA1_5`, `A*CBC*`, `CKM_AES_KEY_WRAP*`, `ES256K`, `RSNULL` | |

- **PSS salt:** Azure PS* follow RFC 7518 (salt = hash length) (unverified on the REST page;
  pinned by conformance: the independent `LocalVerifier` enforces salt = hash).
- **Ed25519:** Azure has no OKP keys; `MessageSigner` is never opened.

### 6.2 Key-type check (on open + first use)

From the cached `KeyBundle.key`:

- `kty` family and `crv`/modulus must fit the asserted algorithm; mismatch → `KeyMismatch`.
- `key_ops` must contain the operation (`sign` and `verify` for signer handles; `wrapKey` and
  `unwrapKey` for `KeyWrap`; `encrypt`+`decrypt` for `Aead`) → else `KeyMismatch` naming the
  missing op. A verify-only handle needs only `verify`.
- `aead` on an `oct-HSM` key: GA API versions do not report the key size (`key_size` is
  preview-only), so AES-128/192 cannot be refused before use; B trusts the caller here and the
  docs warn (Q3).
- HMAC vs AES `oct-HSM`: both are `kty: oct-HSM`; distinguished by `key_ops` (`sign`/`verify`
  vs `encrypt`/`decrypt`) (unverified, T10).
- P-256K and RSA keys smaller than 2048 → `KeyMismatch`.

## 7. Ciphertext framing

Azure returns raw RSA/AES-KW output and, for GCM, `iv` and `tag` separately; no version is
embedded. Appendix A decided a frame; concrete layout (all integers u8):

```
"AZK" | format 0x01 | alg | vlen | version[vlen] | body
alg  0x01 RSA-OAEP-256   body = ct (exactly the modulus size; checked against the key on unwrap)
     0x02 A256GCM        body = iv[12] | ct | tag[16]     (B)
     0x03 A256KW         body = ct (input + 8)            (B)
vlen = 1..=64, version = [0-9a-z] (32 hex today)
```

Implemented as specified (a wire format, PLAN §23 Q9; `docs/azure-ciphertext.md`), except that
readers accept 32-hex versions only today (Z7); the frame keeps room for longer ones.

- Refinement of Appendix A's `version ‖ iv ‖ ct ‖ tag`: the magic, format and alg bytes let
  `ciphertext_version` reject foreign bytes, keep algorithm choice explicit (an RSA-OAEP SHA-1 or
  a 384-bit-tag variant gets a new alg code, never a reinterpretation), and the length-prefixed
  version survives a non-hex version format.
- Not authenticated by the frame itself: tampering the version selects another version (fails
  as `DecryptFailed`), tampering `alg` is refused by the handle's alg check before I/O.
- Ciphertexts are **not native** (unlike transit): other Azure tools need the frame stripped.
  `docs/azure-ciphertext.md` documents the format with vectors; a parse helper
  `anykms_azure::framing::parse` is public for migration out.
- `EnvelopeAead` over an Azure `KeyWrap` stores this frame in its wrapped-key slot (v1 limit:
  check that the slot length field fits a 4096-bit RSA frame: 4+1+1+32+512 = 550 bytes; T5).
- Fuzz target `azure_framing` (parse, round trip).

## 8. Error mapping

`BackendDetail`: `http_status`; `code` = `error.code` plus inner codes joined with `/`
(`Forbidden/ForbiddenByRbac`) (implemented as the **innermost** code alone, `ForbiddenByRbac`,
so `code` is one token on every backend; Z10); `request_id` = `x-ms-request-id` (dropped unless
it is at most 128 visible ASCII characters); `server_message` verbatim for
pinned messages, else redacted (transit rule; Azure messages can carry client IPs and object ids).
Pinned by wiremock cases and recorded live responses (`scripts/probe-azure.sh`, T3).

| Response | ErrorKind |
|---|---|
| 401 (any body) after the one refresh-and-retry | Unauthenticated (challenge tenant hint, §4.4) |
| 403 `Forbidden` / `AccessDenied` / inner `ForbiddenByRbac`, `ForbiddenByPolicy` | PermissionDenied |
| 403 inner `ForbiddenByFirewall` ("Client address … not authorized") | PermissionDenied, message "network rule" (the IP is redacted) |
| 403 "… not allowed on a disabled key" (unverified text) on versionless or URI-pinned request | KeyStateInvalid |
| same, request version taken from the input (decrypt, unwrap, verify) | KeyVersionUnusable |
| 403 nbf/exp ("not yet valid" / "expired", unverified text) | KeyStateInvalid (Appendix A); only writes are refused by Azure |
| 403 "operation not allowed by key_ops" (unverified) | KeyMismatch (normally caught by the key-type check) |
| 404 `KeyNotFound` on GET or a write | NotFound (also a soft-deleted key; docs say so) |
| 404 on a versioned decrypt/unwrap/verify after the key-type check saw the key | DecryptFailed / VerificationFailed (version from the input does not exist); under `TrustCaller`: NotFound |
| 400 `BadParameter` on decrypt/unwrap | DecryptFailed (tag mismatch, padding, wrong key: indistinguishable on purpose) |
| 400 `BadParameter` on verify | VerificationFailed (malformed signature) |
| 400 `BadParameter` elsewhere; 413 | InvalidArgument |
| 400 key-size-incorrect / algorithm-not-supported for the key | KeyMismatch |
| 409 `Conflict` (key being recovered/deleted) | KeyStateInvalid |
| 429 `Throttled` | Throttled; `Retry-After` parsed if sent (unverified; docs only advise 1/2/4/8/16 s backoff) |
| 500, 502, 503, 504; connect refused/reset; truncated body | Unavailable |
| client timeout | Timeout |
| 3xx | Configuration (never followed) |
| 200 with unparsable body, mismatched `kid`, wrong `iv`/`tag`/signature size | Backend (success bodies never fingerprinted) |
| token endpoint failures | §4.5 |
| anything else | Backend (+ tracing warn) |

Unverified rows are first implemented on `code` + status only, falling back to the less specific
kind (`PermissionDenied`, `InvalidArgument`) until T3 pins the messages, so nothing is ever
misclassified, only under-classified (PLAN §12).

Implemented as: T3 (2026-10-12) pinned the inner error codes, and classification uses them,
never message text: `KeyDisabled`, `KeyNotYetValid`, `KeyExpired` → `KeyStateInvalid` on writes
and reads, `KeyVersionUnusable` on input versions; `KeyOperationForbidden` → `KeyMismatch`; a 403
without one stays `PermissionDenied`. The key-size and algorithm rows (400 `BadParameter`, no
inner code) stay `InvalidArgument`. The live conformance run declares `ServerErrorMessages`
supported.

## 9. KeyVersion, KeyInfo, KeyState

- **`KeyVersion`:** the 32-char version from `kid`, lowercased. `as_u64()` is `None`.
  `Signature`/`Tag`/`PublicKey`/`Decrypted` carry it.
- **`KeyInfo`:** `backend_key_type` = `kty` plus size/curve (`"RSA-HSM 3072"`, `"EC P-256"`,
  `"oct-HSM"`); `capabilities` from `kty` + `key_ops` (`SIGN|VERIFY|PUBLIC_KEY`,
  `KEY_WRAP` for RSA with wrap/unwrap ops, `DATA_KEYS` only via the recipe so **not** set on RSA,
  B: `AEAD|DATA_KEYS|KEY_WRAP` / `MAC`); `signature_algorithms` from `kty`/`crv`;
  `primary_version` = current version (versionless `kid`); `versions` from `/versions`
  (`created`, per-version state).
  Implemented as planned, also for a pinned URI: `describe` then reads the versionless bundle
  too, so `primary_version` and the key-level `state` are the **current** version's, and
  `AzureKeyInfo::current` names it when it differs from the pinned one (Z3). `oct-HSM` keys get
  the `MAC` capability (with `mhsm-hmac`) but no `mac_algorithm`, since an HMAC key is not bound
  to one `HS*`.
- **`KeyState`** (per version; key level = current version):

| Azure attributes | KeyState |
|---|---|
| `enabled: true`, within `nbf`/`exp` | Enabled |
| `enabled: false` | Disabled |
| `nbf` in the future | Unknown("not-yet-valid") |
| `exp` passed | Unknown("expired") |
| soft-deleted | not visible: GET is 404 → `NotFound` (reading `/deletedkeys` needs extra rights; not done) |
| (implemented) a version whose attributes Azure leaves out | Unknown("unknown") (Z8) |

- **`AzureKeyInfo`** (backend type, via downcast): `kty`, `crv`, `key_ops`, `nbf`, `exp`,
  `recovery_level`, `recoverable_days`, `exportable`, `hsm_platform`, `managed`, `tags` (names
  only? Q10), `vault_kind` (Vault | ManagedHsm). Implemented with `tag_names` (names only, Q10),
  `key_type` (`AzureKeyType`), `rsa_bits`, `current` (Z3) and per-version `AzureVersionInfo`.
- No local `nbf`/`exp` pre-check (clock skew); the server decides.

## 10. Observability and secret hygiene

- Spans `anykms.azure` per HTTP request: `op`, `backend`, `host`, `key`, `http_status`,
  `outcome`, `error_kind`, `attempt`, `latency_ms`, `request_id` (`x-ms-request-id`, not secret).
  Token acquisition gets its own span: `credential` (kind), `outcome`, `latency_ms`, `expires_in_s`.
  Implemented as the shared schema (D3, shared.md §5): `anykms.azure` spans with `backend`, `op`,
  `resource` (the key URI, which carries the host and key), `key_version`, `attempt`,
  `http_status`, `code` (the innermost Azure code), `request_id` (recorded only after the
  `x-ms-request-id` filter, Z4), `latency_ms`, `error_kind`, `outcome`; token spans
  `anykms.azure.token` add `backend` and `error_kind`. The hygiene test pins the field names.
- Events: token refresh, 401 retry, `Backend` fallback (redacted fingerprint for error bodies
  only), challenge-tenant mismatch, test-host open (WARN).
- Never logged or in `Debug`/`Display`/`source()`: access tokens, client secrets, federated
  token contents, IMDS/CLI response bodies, plaintext, AAD, data keys, wrapped keys, digests,
  request bodies, query strings (IMDS URLs carry `client_id` — stripped too).
- Token, secret and plaintext buffers are `Zeroizing`; `az` stdout read into a zeroizing buffer.
- `tests/hygiene.rs` copies transit's: marker secrets at TRACE (reqwest, hyper included), every
  credential source, error paths, `source()` chains.

## 11. Testing

### 11.1 Conformance declarations (after P1)

| Feature | Lowkey (std vault) | real std vault | real MHSM (B) |
|---|---|---|---|
| `Aead`, `Rewrap` | n/a (no AES on standard vaults) | n/a | `Aead` yes, `Rewrap` n/a |
| `DataKeys` | via KeyWrap recipe (P4 cases), AAD refused | same | yes (emulated, AAD bound) |
| `KeyWrap` | yes (RSA-OAEP-256) | yes | yes (RSA and A256KW) |
| `Mac` | n/a | n/a | yes if Q4 resolves |
| `Describe`, `RequestCount` | yes | yes | yes |
| `Signing(ES256/384/512, PS*, RS*)` | yes | yes | yes |
| `Signing(Ed25519)` | n/a | n/a | n/a |
| `Rotate`, `Disable` | yes (data-plane rotate / update attributes) | yes | yes |
| `MinDecryptionVersion`, `Throttle`, `NativeCiphertext` | n/a | n/a | n/a |
| `UnauthorizedProvider` | skip (accepts any token) | yes (identity without a role) | yes |
| `OversizePlaintext` | n/a (KeyWrap input size is checked locally; own case) | n/a | after T10 |

Implemented as: `RequestCount` is supported through the hidden
`AzureProviderBuilder::__count_requests`; `UnauthorizedProvider` runs on real Azure when
`ANYKMS_AZURE_UNAUTHORIZED_TOKEN` (a token of an identity without a role) is set, else it is
declared not applicable; `ServerErrorMessages` is not applicable on real Azure until the
`KeyDisabled` code rule lands (T3); Managed HSM size cases wait for T13.

Fixture admin path (create, rotate, disable, delete+purge) uses the data plane
(`POST /keys/<n>/create`, `PATCH /keys/<n>/<v>`, `POST /keys/<n>/rotate`); on real Azure it needs
`Key Vault Crypto Officer` for the fixture identity and purges keys at teardown (names carry a run
id; a janitor deletes leftovers older than a day).

### 11.2 Lowkey Vault (CI, every PR)

`nagyesta/lowkey-vault` (v7.3.x, pinned by tag and digest like the Vault images) in
`compose.yaml` (profile `azure`): HTTPS 8443 with its self-signed cert (fixture downloads the
PKCS#12 from `:8080/metadata/default-cert`, converts to `ca_pem`), `LOWKEY_VAULT_RELAXED_PORTS`,
api-version 2025-07-01 supported. Covers RSA/EC sign/verify, RSA-OAEP-256 wrap/unwrap, get,
versions, rotate, disable. **Does not cover:** A*GCM, A*KW, HS*, MHSM hosts, RBAC/403, real error
messages. The suite must therefore not pin message-level mappings against it (fixture declares
`ErrorFidelity::Emulator`, or those cases live only in the real-Azure binary). Test host via
`HostPolicy::test_host`.

### 11.3 Mocks (wiremock, server-free, every PR)

Error table rows (each code/inner code, unverified rows with recorded bodies once pinned); 401 →
refresh → single retry → `Unauthenticated` with tenant hint; challenge never changes the scope;
3xx not followed and no token sent; `Retry-After` seconds/date/absent; response `kid` for another
key/host → `Backend`; wrong signature/iv/tag sizes; truncated JSON; slow server → `Timeout`;
`nextLink` to another host ignored; IMDS, App Service, token endpoint (workload, secret) and a fake
`az` binary; token cached, refreshed early, single flight under concurrency. wiremock's MSRV
(PLAN §18) excludes this file from the MSRV job like transit's mocks.

### 11.4 Real Azure (env-gated)

- `ANYKMS_AZURE_VAULT_URL` + credentials: standard vault suite, run nightly and before release
  from GitHub Actions via OIDC federation (workload identity, no stored secret). Cost: cents.
  Includes the probe script (`scripts/probe-azure.sh record|diff`) that pins error messages for
  disabled, expired, not-yet-valid, missing version, firewall, bad ciphertext.
- `ANYKMS_AZURE_MHSM_URL`: MHSM suite, **manual / release-gated only**. ~$3.20/h per pool, needs
  activation (security-domain download with 3+ RSA keys), bills while soft-deleted until purged.
  *Implemented as:* `scripts/azure-test-setup.sh mhsm-up` provisions and activates the pool and
  assigns local RBAC; then `scripts/test-env.sh --dotenv env ANYKMS_AZURE_LIVE=1
  ANYKMS_AZURE_MHSM_URL=https://<pool>.managedhsm.azure.net cargo test -p anykms-azure
  --all-features --test conformance_mhsm` runs the suite, and
  `scripts/azure-test-setup.sh mhsm-down` deletes and purges the pool (≈1 h budget). No CI job
  runs it.
- Without the variables: reported as `skip`, never passed (`ANYKMS_REQUIRE_FIXTURE=1` in the
  dedicated jobs).

### 11.5 Fuzzing

`azure_uri`, `azure_framing`, `azure_response` (KeyBundle/JWK/KeyOperationResult/error bodies),
`jwk_spki`; seeds via `fuzz/examples/gen_seeds.rs`.

## 12. Operator docs (shipped)

Implemented as [`docs/operations-azure.md`](../operations-azure.md) (D5; first written as
`docs/azure.md`), with Environment, Limits, Rotation and versions (the 405 fallback, pinned URIs,
`describe`), Runbook and Tracing sections, plus `docs/azure-ciphertext.md` for the frame.

- **RBAC (vaults, recommended; default for new vaults since control-plane API 2026-02-01):**
  signing/verify + KEK + data keys: `Key Vault Crypto User` scoped to the key
  (`keys/read`, `sign`, `verify`, `wrap`, `unwrap`, `encrypt`, `decrypt`; it also has `update`
  and `backup`). Envelope-only services: `Key Vault Crypto Service Encryption User`
  (`read`, `wrap`, `unwrap`) is the least privilege. Verify-only consumers: a custom role with
  `keys/read` + `keys/verify/action`, or `PublicKeys` + `CachedVerifier` with `keys/read`.
  Never `Key Vault Crypto Officer` for applications.
- **Access policies (legacy, still supported):** `get` plus the op permissions
  (`sign`, `verify`, `wrapKey`, `unwrapKey`, `encrypt`, `decrypt`); no `create`, `delete`,
  `update`, `purge`.
- **Managed HSM local RBAC:** `Managed HSM Crypto Service Encryption User` (read, wrap, unwrap)
  for KEKs; `Managed HSM Crypto User` for Aead/Mac/sign (it also grants create, delete, import:
  recommend a custom role with `read`, `encrypt`, `decrypt`, `wrap`, `unwrap`, `sign`, `verify`),
  assigned at `/keys/<name>` scope.
- `key_ops` on the key should list only what the application uses (it is what the key-type check
  reads); a KEK must be dedicated (PLAN §5.1).
- Soft delete and purge protection on; the runbook maps `NotFound` to "deleted? recover it".
- Throttling: vault limits per 10 s (software RSA-2048 4000, RSA-3072 1000, RSA-4096 500,
  EC 4000; HSM keys half), 5× per subscription; use `CachedVerifier`, `EnvelopeAead`, and a
  shared `RetryBudget` per vault. MHSM is not throttled but has fixed capacity.
- Firewall/private endpoints: 403 `ForbiddenByFirewall` is a network rule, not RBAC.
- Credentials: which source `from_env` picks, AKS workload-identity setup, `AZURE_TENANT_ID` for
  guests/multi-tenant, token lifetime and role-propagation delay (up to ~24 h for managed
  identity token claims).

## 13. Task breakdown

Shared prerequisites (planned separately; listed with exactly what Azure needs):

- **P1 Conformance capability redesign (PLAN §22 "Deferred").** Needed: `Feature::{Aead, Rewrap,
  DataKeys, Mac, Describe, KeyWrap}`, undeclared-fails, `TypedHandles::aead`/`mac_key` defaulting
  to `Unsupported`, `TestKeyKind::KeyWrap` (RSA for Azure; `create_key` decides the key type),
  `describe::*` not routed through `typed.aead`, the KeyWrap-gated envelope cases (round trip,
  format, `rewrap_local`, wrong KEK) **without** an `Aead` requirement, and an Azure-shaped proof
  fixture over local (signing + KeyWrap only). Also: a way for a fixture to say its error
  messages come from an emulator (Lowkey), so message-level cases are skipped there.
- **P2 Layered extension handles.** Needed only for `AzureOptions` read through `OpenOptions`
  extensions (local verify, Q5) — already possible; no Azure-specific requirement beyond that.
- **P3 Native `KeyWrap` part on `AeadKey`.** Not required: `Provider::key_wrap` returns a native
  `KeyWrapKey` for MHSM AES keys directly. Nice to have so `aead_key.into_key_wrap()` on MHSM
  uses A256KW; Azure B adopts it if it lands.
- **P4 KeyWrap-based data keys recipe.** Needed: `KeyWrapDataKeys<K: KeyWrap>` (ungated in
  recipes) implementing `DataKeys`, refusing non-empty AAD with `Unsupported` before any I/O,
  with its Emulates/Enforced-by box; **plus a Registry path**: either an optional `DataKeys` part
  on `KeyWrapKey` or `Provider::data_keys` → `DataKeysKey` (Azure prefers the new handle: a
  `KeyWrapKey` with data keys blurs "KEK must be dedicated" but both work; Q1). Conformance
  `datakeys::*` cases gated on `KeyWrap + DataKeys` with `DataKeyAad::Refused`.

Azure tasks:

| # | Task | Size | Depends on |
|---|---|---|---|
| T1 | Crate scaffold, features, facade feature, CI per-crate checks, deny | S | — |
| T2 | URI parser + host allowlist + `test_host` + fuzz target | M | T1 |
| T3 | Live probe against a real vault: versionless POST, error bodies (disabled, nbf/exp, missing version, bad ciphertext, firewall, 429 headers), ECDSA r‖s, PS salt; `scripts/probe-azure.sh` + baseline | M | Azure subscription |
| T4 | Client: reqwest/rustls config, no redirects, zeroizing bodies, size caps, error classification table, `x-ms-request-id` | M | T1, T3 for pins |
| T5 | Credentials: trait, cache, workload, managed (IMDS/App Service), secret, CLI, static; `from_env` | L | T4 |
| T6 | KeyBundle/JWK parsing, JWK→SPKI, `AzureKeyInfo`, describe + versions paging, key-type check cache | M | T4 |
| T7 | Signing handles (sign, server verify, public keys), `local_verify` option | M | T6 |
| T8 | Frame (§7) + RSA-OAEP-256 `KeyWrap` handle + `docs/azure-ciphertext.md` + vectors + fuzz | M | T6 |
| T9 | Provider + Registry wiring, `KeyWrapDataKeys` data keys | S | T7, T8, P4 |
| T10 | Lowkey Vault compose profile + fixture + conformance binary; mocks; hygiene | L | P1, T9 |
| T11 | Real-vault gated job (OIDC), janitor, nightly | M | T10 |
| T12 | Operator docs, runbook rows, README, PLAN §18/Appendix A updates | S | T9 |
| — | **Release A** | | T1–T12 |
| T13 | MHSM provisioning script; live pins: GCM iv/tag sizes, plaintext limit, HS* input, oct key distinctions, MHSM error bodies and token scope | M | MHSM budget |
| T14 | AES-GCM `Aead` + `EmulatedDataKeys` + A256KW `KeyWrap` (frame alg 0x02/0x03) | M | T13, (P3) |
| T15 | HMAC `Mac` | S | T13, Q4 |
| T16 | MHSM conformance binary, docs | M | T14, T15 |
| — | **Release B** | | T13–T16 |

Estimate: A ≈ 8–10 days after P1/P4, B ≈ 4–5 days plus MHSM time.

Status: T1, T2 and T4–T12 done (the T11 live job is written and waits for the Azure identity);
T14–T16 done as code, mock-tested; T3 and T13 (the live probes) have not run. P1–P4 shipped
(P4 as `Provider::data_keys` → `DataKeysKey`, Q1).

## 14. Risks and open questions

Risks:

- **Message-string classification** (disabled vs RBAC are both 403 `Forbidden`): mitigated by
  under-classification fallbacks, the probe baseline and live nightly runs (PLAN §12).
- **Emulator fidelity:** Lowkey Vault accepts any token and has its own error texts; CI-green
  says nothing about Azure's errors. Real-vault nightly is the backstop.
- **No emulator for B at all;** MHSM cost means B is tested rarely.
- **Non-native ciphertexts:** Azure data encrypted by anykms is readable by other tools only after
  stripping the frame (documented, parse helper public).
- **Versionless write semantics** depend on an undocumented-in-swagger behavior (T3; fallback in §5.1).
- **Entra token endpoint drift** (sovereign authority hosts, IMDS api versions) is ours to track
  without the SDK.

Open questions (maintainer decision needed). Answered since (PLAN §23 and the implementation):
Q1 new `DataKeysKey` handle (§23 Q3); Q2 `AZURE_TENANT_ID` required, the challenge tenant is
only a hint; Q3 vault hosts refused for `aead`/`mac` (`Unsupported`, §23 Q15), AES size trusted
and documented; Q4 HMAC behind the experimental `mhsm-hmac` feature until T13; Q5 server-side
verify by default (§23 Q12); Q7 opt-in `cli-credential` (§23 Q15); Q8 certificates and the rest
deferred; Q9 `anykms-http` (§23 Q4); Q10 tag names only; Q11 the `AZK` frame (§23 Q9); Q12 AWS
first (§23 Q1). Q6 is still open.

1. **Q1 Data-keys handle:** `Provider::data_keys` → new `DataKeysKey`, or an optional `DataKeys`
   part on `KeyWrapKey`? (P4; recommendation: new handle.)
2. **Q2 Multi-tenant:** support `tenant_from_challenge()` (tenant from the 401 challenge, scope
   still from the suffix), or require `AZURE_TENANT_ID`? Recommendation: require it in A.
3. **Q3 Premium oct-HSM and AES key size:** allow `aead`/`mac` on vault hosts behind
   `allow_premium_oct()` (preview, unpromised), or refuse? And since GA API versions do not report
   an `oct-HSM` key's size, accept that AES-128/192 keys cannot be refused before use (only the
   docs warn)? Recommendation: refuse vault hosts in B; trust the caller on AES size, documented.
4. **Q4 HMAC input:** if `sign` with HS* takes a digest rather than the message, `Mac` would
   compute HMAC(digest), which is not portable HMAC. Ship `Mac` only if it is message-based
   (with a documented size cap), else leave `Mac` unsupported and say why.
5. **Q5 Verify default:** server `verify` (proposed) or `LocalVerifier` (Microsoft's
   recommendation, saves throttling budget, keeps verifying when the vault is unreachable but
   also after a key is disabled)?
6. **Q6 Interop with existing Azure-wrapped data:** add `RSA-OAEP` (SHA-1) as a decrypt/unwrap-only
   frame alg so existing DEKs can be imported into envelopes, or leave it to `AsymmetricDecrypt`?
7. **Q7 `az` CLI credential:** default feature, opt-in feature, or omitted (subprocess spawning in
   a library)? Recommendation: opt-in feature `cli-credential`, never chosen by `from_env` unless
   `ANYKMS_AZURE_CREDENTIAL=cli`.
8. **Q8 Credential breadth for A:** certificate, Azure Arc, Cloud Shell, Azure Pipelines — defer
   all (custom `TokenCredential` covers them), or include certificates?
9. **Q9 Shared transport code:** copy transit's TLS/redirect/zbuf/error-redaction code into the
   Azure crate, or extract a private `anykms-http` crate first (also useful for AWS/GCP if they go
   in-house)? Recommendation: extract before T4.
10. **Q10 Tags in `AzureKeyInfo`:** expose key tags (may hold operator metadata) or not at all?
11. **Q11 Frame magic:** `"AZK"` + format byte as above, or reuse a common anykms framing for all
    cloud backends that need one (none other does today)?
12. **Q12 Release order:** ship A before AWS/GCP once P1 and P4 exist, or keep PLAN §10's order
    (AWS first, which also delivers P1)?

## 15. Sources

- REST (api-version 2025-07-01): [encrypt](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/encrypt/encrypt),
  [sign](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign),
  [verify](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/verify/verify),
  [get key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key);
  spec: https://github.com/Azure/azure-rest-api-specs/tree/main/specification/keyvault/data-plane/Keys
- Keys: https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys,
  https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details,
  https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details,
  https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates
- Auth and errors: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication-requests-and-responses,
  https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes,
  https://learn.microsoft.com/en-us/azure/key-vault/general/common-error-codes,
  https://devblogs.microsoft.com/azure-sdk/guidance-for-applications-using-the-key-vault-libraries/
- Limits: https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits,
  https://learn.microsoft.com/en-us/azure/key-vault/general/overview-throttling,
  https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/scaling-guidance
- RBAC: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security,
  https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/built-in-roles,
  https://learn.microsoft.com/en-us/azure/key-vault/general/access-control-default
- Entra: https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token,
  https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity,
  https://azure.github.io/azure-workload-identity/docs/quick-start.html,
  https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud,
  https://learn.microsoft.com/en-us/cli/azure/account
- SDK: https://crates.io/crates/azure_security_keyvault_keys,
  https://docs.rs/crate/azure_core/1.1.0/source/CHANGELOG.md,
  https://docs.rs/crate/azure_identity/1.0.0/source/CHANGELOG.md,
  https://docs.rs/crate/azure_security_keyvault_keys/1.0.1/source/src/authorizer.rs
- Emulator: https://github.com/nagyesta/lowkey-vault
- MHSM lifecycle and pricing: https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-cli,
  https://prices.azure.com/api/retail/prices
