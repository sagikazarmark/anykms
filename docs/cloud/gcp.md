# anykms-gcp: plan for the GCP Cloud KMS backend

Status: **implemented (T2–T12) on 2026-10-06; the live probe T1 ran on 2026-10-12** (results in
`docs/research/gcp-kms.md` §2); see "Implementation notes" below. Written 2026-10-05 against the 0.1 tree (`dd3cc82`).
It honors PLAN.md Appendix A (GCP column), §19 "Decisions for the cloud backends", §20, §21 and §22.
Where this plan narrows or extends one of those, it says so. Sources are listed at the end ([S1]…).
The shared prerequisites are planned elsewhere: the conformance capability redesign (§22
"Deferred"), layered extension handles, and new handle parts. §13 states exactly what GCP needs
from them.

## Implementation notes (2026-10-06)

Where the implementation differs from the plan below:

- **Shared HTTP code (Q4):** `anykms-http` (TLS provider precedence, the no-redirect client,
  zeroizing bodies, `Retry-After`, the single-flight `CredentialCache`), not copies.
- **Version rules at open** fail with `KeyMismatch`, not `Configuration` (§4.4): the conformance
  suite expects `KeyMismatch` for a key opened as the wrong kind (an HMAC key version opened as an
  AEAD key, an AEAD key opened as a MAC key). Both are config-class errors.
- **A tag of the wrong length** in `verify_mac` is `VerificationFailed` (the suite's contract for
  truncated tags), still before any request; a tag of another algorithm stays `InvalidArgument`.
- **RSA backend (Q5):** no `compile_error!`. Without `rsa-aws-lc-rs`/`rsa-rustcrypto`, RSA
  signing, verifying and public-key handles and RSA KEKs fail to open with `Configuration` naming
  the features, so `--no-default-features` builds and lints like every other crate.
- **`asymmetricDecrypt` KEKs are implemented** (§1 non-goal): `Provider::key_wrap` with a
  versioned URI opens an `RSA_DECRYPT_OAEP_*_SHA256` version as `GcpKeyWrapKey` (local
  `rsa_oaep_sha256_encrypt` wrap with the cached public key, server unwrap). It needed no core
  part: `KeyWrapKey::new` takes any `KeyWrap`.
- **Metadata server** default host is `169.254.169.254` (no DNS), `GCE_METADATA_HOST` overrides.
- **Empty input** (T1, 2026-10-12): empty plaintexts are accepted, so the fixtures declare
  `EmptyPlaintext` supported; an empty Ed25519 message and empty `macVerify` data are refused,
  so `EmptyMessage` is *not applicable*.
- **`getPublicKey` is `GET …/cryptoKeyVersions/<n>/publicKey`.** The first live run (T1) found
  the client, the mock tests and the fake all using `…:getPublicKey`, which Cloud KMS refuses.
- **Handle names (D4):** the RSA KEK is `GcpKeyWrapKey` (`GcpProvider::key_wrap_key`), and
  `describe_key` returns a describe-only `GcpDescribeKey` (it cannot encrypt or sign).
- **RSA KEK unwrap checks OAEP-SHA-256 (Q10):** before `asymmetricDecrypt`, the version's
  algorithm must be `RSA_DECRYPT_OAEP_*_SHA256` (`KeyMismatch` otherwise; cached), and
  `Provider::key_wrap` honors `key_type_check` for RSA KEKs.
- **Credential-file URLs (security review M1, L6):** `token_uri`, `token_url` and the
  impersonation URL must each equal the fixed URL for that field (no other `*.googleapis.com`
  host, no query); see §4.3. A plain-`http://` `AuthEndpoints::custom` needs
  `allow_loopback_http`, as `Endpoint::custom` does.
- **Facade (D2):** `with_default_providers()` propagates a `GcpProvider::from_env()` error (a
  malformed `ANYKMS_GCP_*` variable) instead of recording a skip (§3).
- **Tracing (D3):** the shared span schema, with `code` = the `google.rpc.Status` name and
  `request_id`; token spans `anykms.gcp.token` (§10).
- **Errors (G7):** `ACCESS_TOKEN_SCOPE_INSUFFICIENT` (like `SERVICE_DISABLED` and
  `BILLING_DISABLED`) is `Configuration`, and a pinned "incorrect key purpose" message is
  `KeyMismatch` (§7).
- **Conformance fixture (T11):** `tests/conformance.rs` runs the redesigned suite against an
  in-process fake Cloud KMS server on every PR; `tests/conformance_live.rs` runs it against a real
  key ring (env-gated, nightly). The suite asks for an HMAC key per algorithm
  (`TestKeyKind::Hmac(alg)`; Cloud KMS binds the algorithm to the key) and for a missing-key URI
  per kind (`missing_key_uri(kind)`: version 1 of a missing key for signing, MAC and RSA KEK
  kinds), so the fixture creates and opens Cloud KMS keys as they are, with no adaptation layer.

## 0. Summary

- **Crate.** `anykms-gcp`, scheme `gcp-kms`. URIs are Cloud KMS resource names
  (`gcp-kms://projects/my-project/locations/l/keyRings/r/cryptoKeys/k[/cryptoKeyVersions/n]`). This is the
  spelling Tink uses.
- **Client.** An in-house REST/JSON client on reqwest, like transit (§6.1), plus in-house
  Application Default Credentials (ADC). The official `google-cloud-kms-v1` / `google-cloud-auth`
  crates are rejected for now: their MSRV is 1.91 and rises monthly, they retry internally, and
  their default TLS provider is aws-lc (§2).
- **Native capabilities.**
  - `Aead`, including `decrypt_with_info` with `used_primary`.
  - `KeyWrap` through `AeadKeyWrap`.
  - `DigestSigner` (ECDSA P-256/P-384, RSA PSS/PKCS#1) and `MessageSigner` (Ed25519).
  - `Mac` with server-side `macVerify`.
  - `PublicKeys` and `Describe`.
- **Verification.** Signature verification runs locally through `LocalVerifier`, inside the
  backend, and the docs say so.
- **Not provided natively.** `Rewrap` and `DataKeys` are not part of GCP handles. They report
  `Unsupported` before any I/O. The recipes (`EmulatedDataKeys`, `EnvelopeAead::rewrap_local`)
  are opt-in and explicit.
- **Versions.** Signing and MAC URIs must name a version. The "newest ENABLED version" mode (§21)
  is specified here but ships in the release after the first one (§4.4).
- **Blocked by** the conformance capability redesign. The crate code itself is not blocked.

## 1. Scope

First release (the first `anykms-gcp` release, lockstep with the workspace version it lands in):

| In | Notes |
|---|---|
| `Aead` on `ENCRYPT_DECRYPT` keys (`GOOGLE_SYMMETRIC_ENCRYPTION`, `EXTERNAL_SYMMETRIC_ENCRYPTION`) | all protection levels: SOFTWARE, HSM, EXTERNAL, EXTERNAL_VPC |
| `decrypt_with_info` | `used_primary` from `DecryptResponse.usedPrimary`; `key_version` stays `None` |
| `KeyWrap` | `Provider::key_wrap` = `self.aead(..).map(KeyWrapKey::from_aead)`, as on transit and local |
| `DigestSigner` / `DigestVerifier` | `EC_SIGN_P256_SHA256`, `EC_SIGN_P384_SHA384`, `RSA_SIGN_PSS_*`, `RSA_SIGN_PKCS1_*` (§6) |
| `MessageSigner` / `MessageVerifier` | `EC_SIGN_ED25519` (software only [S2]) |
| `Mac` | `HMAC_SHA256/384/512`; `macSign` plus server-side `macVerify` |
| `PublicKeys`, `Describe` | `getPublicKey`; `cryptoKeys.get` plus `cryptoKeyVersions.list` |
| Credentials | ADC chain (§4.3); explicit sources; custom `CredentialSource` trait |
| Endpoints | global (default), regional REP, custom (PSC, private, test) |

Non-goals, each with where it goes:

- **Signing-key version following.** The newest-enabled mode is follow-up task T13.
- **Algorithms core lacks.** secp256k1 (`EC_SIGN_SECP256K1_SHA256`) and `HMAC_SHA224` arrive
  when core adds the variants (planned in §21). `HMAC_SHA1` and `RSA_SIGN_RAW_PKCS1_*` are never
  mapped.
- **PQC.** `PQ_SIGN_ML_DSA_*`, `SLH_DSA` and the KEMs wait for `MuSigner` (§12) and a KEM
  capability.
- **`asymmetricDecrypt` (RSA-OAEP) as a native `KeyWrap`.** It needs a native `KeyWrap` part on
  `KeyWrapKey`. That part is AWS-driven (§22) and follows it. Implemented as: included in the
  first release as `GcpKeyWrapKey` (see "Implementation notes"); no new part was needed.
- **`RawEncrypt` / `RawDecrypt` (`RAW_ENCRYPT_DECRYPT` keys).** They are low-level primitives
  with caller-managed IVs [S7]. They are interop-only and have no portable contract. Revisit on
  demand.
- **Signing with EXTERNAL / EXTERNAL_VPC keys.** Cloud EKM signing requires `data`, not `digest`
  [S8]. So `DigestSigner` cannot work, and these keys are refused with `KeyMismatch` (§6).
- **Admin APIs.** Key and version creation, rotation, IAM and import belong to IaC; fixtures do
  them outside the public API (PLAN §1).
- **Out-of-scope credential types.** gRPC, mTLS (`*.mtls.googleapis.com`), universe domains other
  than `googleapis.com`, AWS-sourced and executable-sourced workload identity federation.

## 2. Client and dependency decision

| | `google-cloud-kms-v1` 1.15 (official) | in-house REST plus official `google-cloud-auth` | in-house REST plus in-house ADC |
|---|---|---|---|
| MSRV | 1.91 (1.85 last held in 1.6.0, 2026-03; bumped 1.88 → 1.90 → 1.91 since) [S10] | 1.91 (`google-cloud-auth` 1.17) [S10] | 1.85 ✅ |
| Transport | HTTP/JSON over reqwest 0.13 (`gax-internal/_internal-http-client`) [S10] | reqwest 0.13 (already in tree) | reqwest 0.13 |
| TLS | default `default-rustls-provider` = aws-lc; without it the app must install a process default [S11] | auth crate's own reqwest client, same constraint | per-client rustls provider, same selection as transit (§20) ✅ |
| Retries | gax retry, backoff, throttler; must be forced to `NeverRetry` per client [S12] | none | none ✅ |
| Extra deps | gax, gax-internal (opentelemetry 0.33, tracing-opentelemetry, hyper, prost), wkt, iam, location, longrunning, lro, serde_with, async-trait | jiff, time, thiserror, tokio `fs`+`process`, hex | `serde_json`, `base64`, aws-lc-rs (already the default RSA backend) |
| Zeroization | plaintext in `bytes::Bytes`; no control | ✅ for KMS bodies | ✅ |
| Error detail | `gax::error::Error`, status plus details | our mapping | our mapping |
| Credential coverage | full ADC incl. AWS and executable WIF, impersonation | same | metadata server, SA key, authorized_user, file/url WIF, impersonation (§4.3) |
| wiremock testability | endpoint override works; retries and auth must be disabled | ✅ | ✅ |
| Effort | S for KMS calls; M for wrapping, CRC32C and error mapping | M | M + L (auth) |

**Decision: in-house REST client and in-house ADC.** The reasons:

- MSRV 1.85 is a workspace convention (PLAN §2), and the official crates moved six minor Rust
  versions in six months.
- The in-house client keeps one TLS-provider policy across backends (no process-global install,
  FIPS default wins).
- It keeps one retry layer: PLAN §11 says "no retries below `Retry`".
- It keeps the zeroizing request and response buffers of §4.
- The KMS data-plane surface is seven calls.

ADC is the costly part. The common production paths are cheap: the metadata server (GKE Workload
Identity, GCE, Cloud Run) and file-sourced WIF.

**Re-evaluate** when the official crates' MSRV policy stabilizes. A `google-cloud-auth` adapter
implementing our `CredentialSource` (open question Q3) would give full ADC coverage to apps that
accept the higher MSRV. It would not change the core client.

Other options looked at:

- `gcp_auth` 0.12.7 has MSRV 1.85. It brings its own hyper-rustls stack, does I/O at construction
  (not lazy, against §19), and supports no WIF or impersonation [S13].
- The community `google-cloud-kms` crate (yoshidan) was last released in 2024-11.

## 3. Crate layout, features, facade

Mirrors `anykms-transit`:

```
crates/anykms-gcp/src/
  lib.rs        crate docs ("Behavior worth knowing", TLS, zeroization, IAM), BACKEND = "gcp", __fuzz
  config.rs     GcpConfig, Endpoint, EnvConfig (from_env), HTTP/TLS options (copied from transit, Q4)
  uri.rs        GcpKeyRef { project, location, key_ring, key, version: Option<u64> } + strict parser
  client.rs     request builder, zeroizing bodies, JSON (int64-as-string), CRC32C, response checks
  crc32c.rs     table-driven Castagnoli (~40 LOC; inputs ≤ 64 KiB); RFC 3720 test vectors
  errors.rs     google.rpc.Status JSON → ErrorKind (§7); RetryInfo / Retry-After
  auth/         CredentialSource trait, Token, cache + single-flight, adc.rs, metadata.rs,
                service_account.rs (self-signed JWT), authorized_user.rs, external_account.rs,
                impersonated.rs, static/none
  handles.rs    GcpAeadKey, GcpDigestKey, GcpEd25519Key, GcpMacKey, GcpVerifier (version → LocalVerifier cache)
  keyinfo.rs    GcpKeyInfo (purpose, algorithm, protection level, primary, rotation period) → KeyInfo; key-type check
  provider.rs   GcpProvider, GcpProviderBuilder, impl Provider
  zbuf.rs       zeroizing buffers (copied from transit, Q4)
tests/  mock.rs (wiremock), hygiene.rs, auth.rs, conformance_gcp.rs (env-gated), integration.rs (env-gated)
```

Implemented as: no `config.rs` copies or `zbuf.rs` (`anykms-http`); `wire.rs` holds the proto3
JSON helpers; `auth/` has `adc.rs`, `metadata.rs`, `service_account.rs`, `file.rs`, `oauth.rs`,
`external_account.rs`, `impersonated.rs`; `handles.rs` also has `GcpKeyWrapKey` (RSA KEK) and
`GcpDescribeKey` (describe-only). Tests: `mock.rs`, `auth.rs`, `hygiene.rs`, `e2e.rs` and
`conformance.rs` against an in-process fake Cloud KMS, `live.rs` and `conformance_live.rs`
(env-gated).

Estimated size: about 4.5k LOC in `src` (auth is about 1.5k), the same order as transit.

Cargo features:

```toml
[features]
default = ["rustls-ring", "rsa-aws-lc-rs", "service-account-key"]   # superseded by PLAN §25.3 C2: rustls-aws-lc-rs
rustls-ring = ["rustls/ring"]            # TLS provider; same precedence rules as transit (§20)
rustls-aws-lc-rs = ["rustls/aws-lc-rs"]
rsa-aws-lc-rs = ["anykms-recipes/rsa-aws-lc-rs"]   # RSA verification backend for LocalVerifier (§21: explicit)
rsa-rustcrypto = ["anykms-recipes/rsa-rustcrypto"]
service-account-key = ["dep:aws-lc-rs"]  # RS256 for self-signed JWTs; aws-lc only (no RustCrypto RSA private-key ops, RUSTSEC-2023-0071)
tracing = ["dep:tracing"]
http2 = ["reqwest/http2"]
```

Notes on the features:

- **Recipes dependency.** `anykms-recipes` is taken with `default-features = false`: local
  verification only, no `jose` and no `envelope`.
- **RSA backend.** With neither `rsa-*` feature on, a `compile_error!` explains the choice. §21
  requires that RSA verification cannot fail at run time. The per-crate
  `--no-default-features` CI job therefore adds `--features rsa-rustcrypto` for this crate (Q5).
  Implemented as: no `compile_error!`; RSA handles and RSA KEKs fail to **open** with
  `Configuration` naming the features, so the failure is still before any operation.
- **Service-account keys.** Without `service-account-key`, a service-account JSON is a
  `Configuration` error naming the feature.
- **Async runtime.** `tokio` with `sync` only (token single-flight), as in transit.

**Facade.**

- `gcp = ["dep:anykms-gcp"]`.
- `rustls-ring` / `rustls-aws-lc-rs` forward to `anykms-gcp?/…`.
- `rsa-*` forward to `anykms-gcp?/rsa-*`.
- `tracing` forwards.
- `with_default_providers()` registers `GcpProvider::from_env()`. That call does no I/O (ADC is
  lazy, §19), so it fails only on a malformed environment, which then appears in `skipped()`.
  Implemented as: a malformed environment is an **error** from `with_default_providers()`, not
  a skip (D2); `http2` forwards too. The facade's `gcp` feature also enables
  `service-account-key`.

## 4. Configuration, URIs, credentials, versions

### 4.1 Configuration

```rust
GcpProvider::builder()
  .credentials(Credentials::adc())                 // default; or ::metadata_server(), ::service_account_file(p),
                                                   // ::external_account_file(p), ::static_token(..), ::none(), ::custom(Arc<dyn CredentialSource>)
  .endpoint(Endpoint::Global)                      // https://cloudkms.googleapis.com (default)
                                                   // Endpoint::Regional → https://cloudkms.{location}.rep.googleapis.com [S9]
                                                   // Endpoint::custom("https://kms.p.googleapis.com") (PSC/private; http only for literal loopback + allow_loopback_http)
  .quota_project("billing-proj")                   // x-goog-user-project; also read from ADC files (needed with user credentials)
  .allowed_projects(["prod-kms"]).allowed_locations(["europe-west1"])   // optional allowlists (§4.2)
  .connect_timeout(2s).request_timeout(10s).pool_idle_timeout(50s).tcp_keepalive(30s)
  .http_version(HttpVersion::Http1).proxy(Proxy::None).crypto_provider(..).ca_pem(..)   // as transit
  .public_key_ttl(60s)                             // verifier cache (§8); 0 disables
  .build()?;
GcpProvider::from_env()?;   // GOOGLE_APPLICATION_CREDENTIALS (via ADC), ANYKMS_GCP_ENDPOINT, ANYKMS_GCP_QUOTA_PROJECT,
                            // GOOGLE_CLOUD_QUOTA_PROJECT, ANYKMS_GCP_ALLOWED_PROJECTS; GCE_METADATA_HOST honored (tests, emulators)
```

Implemented with `ANYKMS_GCP_ALLOWED_LOCATIONS` as well, and `GcpProviderBuilder::from_env()` so
callers can adjust the builder before `build()`. There is no `from_env_with(lookup)` seam (AWS
has one). Test endpoints come from `auth_endpoints(AuthEndpoints::custom(..))` and
`Endpoint::custom`; plain `http://` needs `allow_loopback_http()` for both (L6).

- **Transport.** Redirects are never followed. The TLS-provider selection is transit's (§20).
  Proxy settings from the environment are ignored unless configured explicitly.
- **Regional endpoints** are derived from the URI's location and never from caller text. The
  location `global` with `Endpoint::Regional` is a `Configuration` error at open. A regional host
  that does not exist fails as DNS `Unavailable`; the docs tell operators to check Google's list.

### 4.2 URI grammar

```
gcp-kms://projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>[/cryptoKeyVersions/<n>]
```

- **Segments.**
  - project: `[a-z][a-z0-9-]{4,28}[a-z0-9]`, optionally prefixed with a legacy
    domain-scoped `domain.tld:`.
  - location: `[a-z0-9-]+`.
  - ring and key: `[A-Za-z0-9_-]{1,63}`.
  - version: `[1-9][0-9]{0,19}`.
- **Rejected:** a query, a fragment, percent-encoding, an empty segment, `.` or `..`, and
  `gcp-kms:///projects/…` (empty authority, with a hint).
- **URL building.** Segments are re-encoded when the request URL is built (§18 rule). The parser
  is fuzzed (`gcp_uri`).
- **No alias.** Resource names are global, so there is no alias (unlike transit). One provider
  holds one credential and one endpoint. Different credentials per project means two providers
  under a `Registry`; that needs the alias design of Q6.
- **Allowlists.** `allowed_projects` and `allowed_locations` are optional, but the docs strongly
  recommend them. Without them, a key URI injected through config could name an attacker-owned
  key that grants `allUsers` encrypt rights, and data would be encrypted under it (exfiltration).
  Making them mandatory is Q7.

### 4.3 Credentials

The object-safe trait:

```rust
pub trait CredentialSource: Send + Sync + Debug {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>>;   // Token { secret: SecretString, expires_at: Option<SystemTime> }
    fn invalidate(&self, rejected: &Token);
    fn quota_project(&self) -> Option<&str> { None }
}
```

- **Cache.** One cached token per source. Refresh happens 4 minutes before expiry. Fetches are
  single-flight (`anykms_http::credentials::CredentialCache`; since release plan 2.1 every waiter
  shares the fetch's result, a failure included, and an early refresh holds up only its caller).
- **401 handling.** On a 401 the client calls `invalidate` and retries exactly once if a different
  token comes back. This is the §19 exception, and it is never multiplied by `Retry`.
- **Laziness (§19).** Nothing resolves before the first operation.

Every chain step logs the source it picked at INFO, never a value. **ADC order** [S14]:

1. `GOOGLE_APPLICATION_CREDENTIALS` names a JSON file, which is parsed by `type`.
2. The gcloud ADC file (`$HOME/.config/gcloud/application_default_credentials.json`;
   `%APPDATA%\gcloud\…` on Windows).
3. The metadata server, reached through `GCE_METADATA_HOST` or `metadata.google.internal`, with
   header `Metadata-Flavor: Google`. The first probe uses a 1 s connect timeout.

| `type` / source | First release | Mechanism |
|---|---|---|
| metadata server | ✅ | `GET …/instance/service-accounts/default/token`. Plain HTTP only to the fixed metadata host or `169.254.169.254` (or `GCE_METADATA_HOST`), never a redirect. |
| `service_account` | ✅ (feature `service-account-key`) | Self-signed JWT (RS256, `scope` claim `https://www.googleapis.com/auth/cloud-platform`, 1 h). No token-endpoint round trip. The private-key PEM is held zeroizing. Docs repeat Google's warning against SA keys [S14]. |
| `authorized_user` | ✅ | Refresh token → `oauth2.googleapis.com/token`; `quota_project_id` honored. Dev use. |
| `external_account` (WIF), `file`/`url` subject token | ✅ | STS token exchange → optional `service_account_impersonation_url`. Covers GitHub Actions OIDC, AKS/EKS-style projected tokens and on-prem Kubernetes. |
| `impersonated_service_account` | ✅ | Source credential → `iamcredentials…:generateAccessToken`. |
| `external_account` with `aws` or `executable` source; `external_account_authorized_user`; `gdch` | ❌ → `Configuration` naming the type | Later on demand, or through the adapter of Q3. |

- **Token endpoints.** Only the URLs fixed for each `type` are allowed (Google hosts over
  `https`). A credential file's `token_url`, `service_account_impersonation_url` or
  `token_uri` must each equal the fixed URL for that field exactly (no other `*.googleapis.com`
  host, no query, port or userinfo; two legacy OAuth token URLs map to `oauth2.googleapis.com`),
  except `credential_source.url` for file/url subject tokens, which is local by design. This keeps a planted credential file from
  sending subject tokens to arbitrary hosts.
- **File reads** are bounded (64 KiB) and errors name the path, never the contents (transit rule).
- **Failure kinds.** No credentials found is `Configuration`. The metadata server or a token
  endpoint being unreachable or returning 5xx is `Unavailable`; since release plan 2.1 (R-30) that
  failure is returned for 5 s without another fetch. A token endpoint returning 400 or 401
  (`invalid_grant`) is `Unauthenticated`.

### 4.4 Version pinning and the newest-enabled mode

Per Appendix A and §19:

| Handle | URI | Behavior |
|---|---|---|
| `aead`, `key_wrap` (`ENCRYPT_DECRYPT` KEK) | **unversioned** | encrypt uses the primary; decrypt finds the version itself |
| `key_wrap` (RSA KEK, `GcpKeyWrapKey`) | **versioned** | wraps locally with the pinned version's public key; unwraps with `asymmetricDecrypt` on it. A version that is not `RSA_DECRYPT_OAEP_*_SHA256` is `KeyMismatch` (Q10) |
| digest/message signer, verifier, `public_keys` | **versioned required** | signs with the pinned version; `public_key()` = the pinned version's key |
| `mac` | **versioned required** | `macSign` on the pinned version; `verify_mac` on the tag's version (§5) |
| `describe` (`GcpDescribeKey`) | either | describes the key (a version in the URI is only labeled) |

A URI of the wrong shape is **`KeyMismatch` at open**, before any I/O (implemented; this plan
first said `Configuration`). On GCP the shape is the only pre-I/O signal of the key family, and
the conformance suite requires `KeyMismatch` for a key opened as the wrong family (an HMAC key
opened as AEAD), as on AWS and Azure. The hints stay: a versioned AEAD URI says "decrypt cannot
take a version"; an unversioned signing or MAC URI says "append `/cryptoKeyVersions/N`; Cloud
KMS asymmetric and MAC keys have no primary version". A malformed version passed per call (a
signature's or tag's version, `public_key_version`) is `InvalidArgument`.

**Newest-enabled mode** (§21). Decision: **not in the first release**; it is follow-up task T13.
Its API is fixed now so that it lands additively:

- Opt-in through `GcpProviderBuilder::version_selection(VersionSelection::NewestEnabled { refresh,
  min_age })` or an `OpenOptions` extension of the same type.
- It applies only to unversioned signing and MAC URIs. A versioned URI always pins.
- It resolves through `cryptoKeyVersions.list` (`filter=state=ENABLED`), comparing versions
  numerically, never as strings. It re-resolves every `refresh` (default 5 min).
- `min_age` (default 1 h) skips versions created more recently. Relying parties' JWKS caches then
  hold the new key before anything is signed with it ("publish before use").
- It needs `cloudkms.cryptoKeyVersions.list`.
- `public_key()` returns the resolved version, and signatures carry it as `key_version`.

It is deferred because it adds a background-refresh state machine, list permissions and its own
conformance cases (rotation followed by the handle, `min_age`). The first release is useful
without it: rotation is a config change.

## 5. Operation mapping

All calls are `POST {endpoint}/v1/{name}:{method}` (getPublicKey and get/list are `GET`). Bodies
use proto3 JSON: bytes as standard base64, and `Int64Value` CRC32C fields as JSON strings. The
parser accepts a string or a number. Each request sends only the fields its operation needs (§4);
in particular an empty AAD omits both `additionalAuthenticatedData` and its CRC.

The response checks apply to every row. Any failure discards and zeroizes the result:

- **CRC32C.** A `verified*Crc32c` flag that is not `true` for a CRC that was sent, or a response
  CRC that does not match, is `Unavailable` (retryable; Appendix A, [S6]).
- **Name.** The response `name` must equal the expected version name, or for encrypt start with
  `<key>/cryptoKeyVersions/`. A mismatch is `Backend` with a fixed message ("response for another
  key"), never retried [S6].

| anykms op | GCP call (`name`) | Request fields | Response checks and mapping |
|---|---|---|---|
| `Aead::encrypt` | `cryptoKeys.encrypt` (key) [S3] | `plaintext`, `plaintextCrc32c`; `additionalAuthenticatedData` + CRC if non-empty. Local check before I/O: plaintext ≤ 64 KiB and AAD ≤ 64 KiB, else `InvalidArgument` (HSM's 8 KiB combined limit is left to the server → `InvalidArgument`) | `verifiedPlaintextCrc32c` (and the AAD flag), `ciphertextCrc32c`, name prefix → `Ciphertext` (opaque bytes). The used version goes to the tracing span only |
| `Aead::decrypt` | `cryptoKeys.decrypt` (key; never a version [S4]) | `ciphertext`, `ciphertextCrc32c`; AAD + CRC if non-empty | `plaintextCrc32c` → zeroizing plaintext |
| `Aead::decrypt_with_info` | same call | same | `Decrypted::new(pt).with_used_primary(Some(usedPrimary))`; `key_version` `None` |
| `Aead::ciphertext_version` | none | — | `Ok(None)` (opaque, Appendix A) |
| `KeyWrap` | via `AeadKeyWrap` (encrypt/decrypt, empty AAD) | — | — |
| `Rewrap`, `DataKeys` | **not provided** (§9) | — | `Unsupported` before I/O through the opaque handle |
| `DigestSigner::sign_digest` | `cryptoKeyVersions.asymmetricSign` (pinned version) [S5] | `digest: {sha256 \| sha384 \| sha512: b64}`, `digestCrc32c` | `verifiedDigestCrc32c`, `signatureCrc32c`, exact name → `Signature { alg, key_version: "N", bytes }` (ECDSA DER, RSA raw: already the core encodings) |
| `MessageSigner::sign_message` (Ed25519) | same | `data`, `dataCrc32c` | `verifiedDataCrc32c`, `signatureCrc32c`, name |
| `DigestVerifier` / `MessageVerifier` | **local** | — | `Signature::key_version` must be decimal (else `InvalidArgument`; `None` → `InvalidArgument`, as transit). Public key of that version of *this* key from the cache (§8), then `LocalVerifier::new(pk, alg)` |
| `Mac::mac` | `cryptoKeyVersions.macSign` (pinned) | `data`, `dataCrc32c`. Local check: ≤ 64 KiB (HSM's 16 KiB [S15] left to the server) | `verifiedDataCrc32c`, `macCrc32c`, name, tag length = the algorithm's output length → `Tag { key_version: "N" }` |
| `Mac::verify_mac` | `cryptoKeyVersions.macVerify` (**the tag's version** of this key) | `data`, `dataCrc32c`, `mac`, `macCrc32c`. Local before I/O: tag algorithm = handle algorithm and length = output length (`InvalidArgument`); version decimal | `verifiedDataCrc32c` and `verifiedMacCrc32c` true; `success == verifiedSuccessIntegrity`, else `Unavailable` [S6]; `success == false` → `VerificationFailed` |
| `PublicKeys::public_key` / `public_key_version(v)` | `cryptoKeyVersions.getPublicKey` (pinned, or `versions/v` of this key) [S16] | no `publicKeyFormat` (PEM default) | `pemCrc32c`, name, `algorithm` = expected; PEM → SPKI DER; SPKI key type (and RSA bits) must match the algorithm → `PublicKey { key_version: "N" }`. `v` that is not decimal → `InvalidArgument`; a missing version → `NotFound` (never another key: the name is built from the handle's key) |
| `Describe` | `cryptoKeys.get` + `cryptoKeyVersions.list` (paged, `pageSize=1000`) | — | §8 |

There are no backend retries: CRC failures surface as `Unavailable` for the caller's
`RetryLayer`. Every data-plane call is safe to retry (encrypt gives a fresh ciphertext; sign and
MAC are idempotent).

## 6. Algorithms and the key-type check

| GCP `CryptoKeyVersionAlgorithm` [S2] | anykms | Handle |
|---|---|---|
| `GOOGLE_SYMMETRIC_ENCRYPTION`, `EXTERNAL_SYMMETRIC_ENCRYPTION` | AEAD | `aead`, `key_wrap` |
| `EC_SIGN_P256_SHA256` / `EC_SIGN_P384_SHA384` | `EcdsaP256Sha256` / `EcdsaP384Sha384`, `AsymmetricKeyType::EcP256/EcP384` | digest |
| `RSA_SIGN_PSS_{2048,3072,4096}_SHA256`, `RSA_SIGN_PSS_4096_SHA512` | `RsaPssSha256`, `RsaPssSha512` (salt = digest length [S8], which `LocalVerifier` enforces) | digest |
| `RSA_SIGN_PKCS1_{2048,3072,4096}_SHA256`, `RSA_SIGN_PKCS1_4096_SHA512` | `RsaPkcs1v15Sha256`, `RsaPkcs1v15Sha512`; `Rsa { bits }` from the name, cross-checked with the SPKI | digest |
| `EC_SIGN_ED25519` | `Ed25519` | message |
| `HMAC_SHA256/384/512` | `HmacSha256/384/512` | `mac` |
| `EC_SIGN_SECP256K1_SHA256`, `HMAC_SHA224` | none yet (§21 planned variants) → `KeyMismatch` "not supported by anykms yet" | — |
| `HMAC_SHA1`, `RSA_SIGN_RAW_PKCS1_*`, `PQ_*`, `RSA_DECRYPT_OAEP_*`, `KEM_*`, `ML_KEM_*`, `AES_*` (raw) | none → `KeyMismatch` | — |
| `RSA_DECRYPT_OAEP_{2048,3072,4096}_SHA256` | Implemented as: an RSA KEK (`GcpKeyWrapKey`, local OAEP-SHA-256 wrap, `asymmetricDecrypt` unwrap); the other `RSA_DECRYPT_OAEP_*` variants (SHA-1, SHA-512) stay `KeyMismatch` (Q10) | `key_wrap` (versioned) |

GCP has no P-521, no SHA-384 RSA and no PSS/PKCS#1 with SHA-512 below 4096 bits. Those
algorithms are *not applicable* in conformance.

**Key-type check.** It works as on transit (§3.3): once per handle before the first operation,
cached per provider with a 10-minute TTL, dropped on `NotFound`, `InvalidArgument` or
`Unsupported`, with `KeyTypeCheck::TrustCaller` as the opt-out. The source differs by handle so
that the narrowest IAM role suffices:

- **Signing handles** use `getPublicKey` on the pinned version. Its `algorithm` and
  `protectionLevel` decide the check, and the key it returns seeds the verifier cache, so the
  check costs no extra request when verification follows. The `signerVerifier` role is enough.
  - Asserted algorithm ≠ mapped algorithm → `KeyMismatch`. This includes PSS vs PKCS#1, which the
    server cannot catch: the algorithm is bound to the key, so a "PSS" request on a PKCS#1 key
    silently returns PKCS#1.
  - `protectionLevel` EXTERNAL or EXTERNAL_VPC → `KeyMismatch` (§1).
- **AEAD** uses `cryptoKeys.get`: `purpose` must be `ENCRYPT_DECRYPT`, else `KeyMismatch`.
  `RAW_ENCRYPT_DECRYPT` and `ASYMMETRIC_DECRYPT` say what they are in the message.
- **MAC** uses `cryptoKeyVersions.get` on the pinned version: `algorithm` must map to the asserted
  `MacAlgorithm`. Independently of the check, every tag's length is checked against the algorithm,
  so even `TrustCaller` cannot return a mislabeled tag.
- **Under `TrustCaller`.**
  - The server still enforces purpose; an observed purpose-mismatch error is pinned to
    `KeyMismatch` by the probe (T1).
  - The server still enforces the digest algorithm (`INVALID_ARGUMENT` → `InvalidArgument`).
  - PSS vs PKCS#1 is not caught, and the docs say so.
- `verify_with_describe()` / preflight at startup works as on transit. *Implemented as `impl Preflight` (architecture plan A5).*

## 7. Error mapping

REST errors are `{"error": {"code", "message", "status", "details": [...]}}`. `BackendDetail`
gets `http_status`, `code` = `status` (e.g. `"FAILED_PRECONDITION"`, Appendix A),
`server_message` (pinned messages verbatim, others redacted, §3.6) and `request_id` from a
`google.rpc.RequestInfo` detail when one is present (it is not guaranteed). Every message used
below is pinned by the probe baselines (T1) and the mock tests.

| Response | ErrorKind |
|---|---|
| 400 `INVALID_ARGUMENT` on **decrypt** | `DecryptFailed` (wrong key, wrong AAD, tampered: "Decryption failed: verify that 'name' refers to the correct CryptoKey" [S17]); input sizes are checked locally first, so nothing else is expected |
| 400 `INVALID_ARGUMENT` with a pinned checksum-mismatch message (any op) | `Unavailable` (Google: verify the CRC, then retry a limited number of times [S6]) |
| 400 `INVALID_ARGUMENT` / `OUT_OF_RANGE`, other ops | `InvalidArgument`, or `KeyMismatch` for pinned purpose or algorithm messages |
| 400 `FAILED_PRECONDITION` "…cryptoKeyVersions/N is not enabled, current state is: DISABLED / DESTROYED / DESTROY_SCHEDULED" [S17] | `KeyVersionUnusable` (§20; it is a config or caller error depending on the op) |
| 400 `FAILED_PRECONDITION`, state `PENDING_GENERATION` / `PENDING_IMPORT` | `KeyVersionUnusable` with `retry_hint(2 s)` (§20 names this case) |
| 400 `FAILED_PRECONDITION`, other (EKM, Key Access Justifications, ...) | `Backend` (warn event) until pinned; candidates are EKM unreachable → `Unavailable` and a KAJ denial → `PermissionDenied` (Q8) |
| 401 `UNAUTHENTICATED` (after the one refresh retry) | `Unauthenticated` |
| 403 `PERMISSION_DENIED` (incl. "…denied on resource … (or it may not exist)" [S18], VPC-SC "Request is prohibited by organization's policy") | `PermissionDenied` |
| 403 with `ErrorInfo.reason` `SERVICE_DISABLED` / `BILLING_DISABLED` (API not enabled) | `Configuration` |
| 403 with `ErrorInfo.reason` `ACCESS_TOKEN_SCOPE_INSUFFICIENT` (token lacks the cloud-platform scope; implemented, G7) | `Configuration` |
| 400 `FAILED_PRECONDITION` (or `INVALID_ARGUMENT`) "… has incorrect key purpose" (implemented, G7) | `KeyMismatch` |
| 404 `NOT_FOUND` | `NotFound` |
| 429 `RESOURCE_EXHAUSTED` [S19] | `Throttled`; `retry_after` from the `Retry-After` header or the `google.rpc.RetryInfo.retryDelay` detail |
| 409 `ABORTED`, 503 `UNAVAILABLE`, 502, non-JSON 5xx from the front end, connection refused or reset, truncated body | `Unavailable` |
| 504 `DEADLINE_EXCEEDED`; client connect or request timeout | `Timeout` |
| 501 `UNIMPLEMENTED` | `Unsupported` |
| 500 `INTERNAL`, `UNKNOWN`, anything else | `Backend` (status and redacted message; warn event) |
| 3xx | `Configuration` (never followed) |
| Rejected TLS certificate | `Configuration`; DNS failure `Unavailable` "DNS lookup failed" (as transit) |
| CRC32C, verified-flag or `verifiedSuccessIntegrity` failure | `Unavailable` |
| response `name` mismatch; undecodable or oversized success body | `Backend` (fixed message, no body fingerprint) |

Two notes on this table:

- **403 vs 404.** A missing key returns `NOT_FOUND` only when the caller has permission on the
  parent (key ring); otherwise it returns 403 "(or it may not exist)". The docs say this, and the
  conformance fixture grants its data-plane identity at the key-ring level (§11).
- **Disable propagation.** Disabling takes effect "usually within a minute" [S20]. A disabled
  version can keep working briefly, and the runbook says so.

## 8. Versions, `KeyInfo` and state

- **`KeyVersion`.** The last segment of the version name, a decimal string (`"3"`), so `as_u64()`
  works. Versions are not unique across keys; `public_key_version` and `verify` only ever build
  names under the handle's own key (`sign::*::foreign_versions`).
- **`KeyInfo`** (from `cryptoKeys.get` plus `cryptoKeyVersions.list`):
  - `backend_key_type`: the primary's `algorithm`, or for keys without a primary the
    `versionTemplate.algorithm` (for a versioned URI, that version's algorithm).
  - `capabilities`:
    - `ENCRYPT_DECRYPT` → `AEAD | KEY_WRAP`. Never `REWRAP` or `DATA_KEYS`: they are not native.
    - `ASYMMETRIC_SIGN` → `SIGN | VERIFY | PUBLIC_KEY`. `VERIFY` is reported because the handle
      verifies; rustdoc and the docs say it is local.
    - `MAC` → `MAC`.
    - Other purposes → `NONE`.
  - `signature_algorithms` / `mac_algorithm`: the mapping in §6, empty or `None` when unmapped.
  - `state`: **`None`** (Appendix A: there is no key-level state).
  - `primary_version`: `Some` for `ENCRYPT_DECRYPT`, `None` otherwise.
  - `versions`: every listed version, with `created_at` from `createTime`. Version states:

    | GCP state | `KeyState` |
    |---|---|
    | `ENABLED` | `Enabled` |
    | `DISABLED` | `Disabled` |
    | `DESTROY_SCHEDULED` | `PendingDeletion` |
    | `DESTROYED` | `Destroyed` |
    | `PENDING_GENERATION`, `PENDING_IMPORT`, `IMPORT_FAILED`, `GENERATION_FAILED`, `PENDING_EXTERNAL_DESTRUCTION`, `EXTERNAL_DESTRUCTION_FAILED` | `Unknown(name)`, verbatim |
- **`GcpKeyInfo`** (backend type, reached via `downcast_ref`) adds `purpose`, `protection_level`,
  `rotation_period`, `next_rotation_time`, `destroy_scheduled_duration` and the import-only flag.
- **Verifier cache.** One public key per version, immutable, held for `public_key_ttl` (default
  60 s, matching GCP's disable propagation [S20]) and then re-fetched. A re-fetch that fails with
  `KeyVersionUnusable` or `NotFound` drops the entry, so local verification stops at most about
  one TTL after the version is disabled. Signatures fail closed only after the server does; the
  docs state this.
- **`used_primary`** is the only staleness signal. `ciphertext_version` is `None` (Appendix A).

## 9. What GCP handles implement, and what the recipes provide

| Capability | GCP handle | How a caller gets it otherwise | Surfaced how |
|---|---|---|---|
| `Rewrap` (native ciphertexts) | ✗ | Decrypt plus encrypt in application code (exposes plaintext); no recipe | `AeadKey::supports_rewrap() == false`; `rewrap` → `Unsupported` before I/O; no `REWRAP` capability bit |
| Envelope KEK rotation | via `KeyWrap` | `EnvelopeAead::rewrap_local` (the DEK is briefly in memory) or `rewrap_to`; `EnvelopeAead::rewrap` needs `Rewrap` and so is `Unsupported` | docs: "GCP: use `rewrap_local`" |
| `DataKeys` | ✗ | `EmulatedDataKeys::new(key)` wrapped explicitly by the caller (local DEK + `encrypt` with AAD; AAD binding works) | `supports_data_keys() == false`; no `DATA_KEYS` bit; no provider option attaches it (opt-in is Q2) |
| Verification | ✓, local | built in through `LocalVerifier` (§19) | rustdoc "Emulates / Enforced by" box copied onto `GcpDigestKey` / `GcpEd25519Key`; `VERIFY` documented as local |
| `ciphertext_version` | `None` | `decrypt_with_info().used_primary()` | docs: how to find stale rows |
| Finding stale envelope rows | partly | `Envelope::parse` gives the wrapped DEK, but `KeyWrap` has no `unwrap_with_info`, so `used_primary` is lost through `EnvelopeAead` | Q9 (recipes change) |

Nothing emulates silently. The only built-in emulation is local verification, which §19 decided.

## 10. Observability and secret hygiene

- **Spans** (`tracing` feature): one per HTTP request (`anykms.gcp`, like transit §18). Fields:
  `op`, `backend`, `project`, `location`, `key_ring`, `key`, `key_version` (from the request name
  or the encrypt response), `http_status`, `code` (the gRPC status), `outcome`, `error_kind`, `attempt`,
  `latency_ms`. Token fetches get their own span: `credential_type` and `token_endpoint_host`,
  never a token.
  Implemented as the shared schema (D3, shared.md §5): `anykms.gcp` spans with `backend`, `op`,
  `resource` (the key URI, which carries project, location, key ring and key), `key_version`
  (recorded on the encrypt span from the response), `attempt`, `http_status`, `code` (the
  `google.rpc.Status` name), `request_id`, `latency_ms`, `error_kind`, `outcome`; token spans
  `anykms.gcp.token` with `backend`, `credential`, `outcome`, `error_kind`, `latency_ms`,
  `expires_in_s`.
- **Events:**
  - the credential source chosen (INFO, once);
  - a token refresh and a refresh failure;
  - a 401 refresh retry;
  - a CRC or integrity failure (op and field name only);
  - a name mismatch;
  - a fallback to `Backend` (redacted message fingerprint; none for success bodies);
  - a `Configuration` refusal from an allowlist.
- **Resource labels.** Every handle error carries `gcp-kms://projects/…/cryptoKeys/k[/cryptoKeyVersions/n]`.
  Resource names are not secret.
- **Secrets.**
  - Tokens are `SecretString` in a sensitive `Authorization` header.
  - Refresh tokens, SA private keys and subject tokens are `Zeroizing`, with a redacting `Debug`.
  - Request JSON goes into a pre-sized zeroizing buffer; responses are read into a zeroizing
    buffer, with `Content-Length` trusted only up to 64 KiB and a cap on response size.
  - Plaintexts are decoded into `Zeroizing`.
  - Token-endpoint error bodies are reduced to `error` / `error_description` codes, never echoed
    whole.
  - The zeroization limits section covers what is not wiped: reqwest/hyper/rustls copies, header
    values and the environment.
- **Hygiene test.** It captures TRACE output (reqwest and hyper included) across encrypt, decrypt,
  sign, MAC, every credential type in the mock and each error path, then asserts that the marker
  plaintext, AAD, token, refresh token, SA key and subject token never appear, `source()` chains
  included.

## 11. Testing

**There is no official emulator.** Community emulators were evaluated and none is used in CI:

- `blackwell-systems/gcp-kms-emulator` has REST, but no MAC and no CRC32C, and signs with
  secp256k1 only [S21].
- `fake-cloud-kms` is gRPC only.
- `floci-gcp`, `cloudburrow` and `localgcp` have unverified fidelity of error codes and messages.

They may serve users' own development loops, so the docs show a `Endpoint::custom` +
`Credentials::none()` setup.

1. **Probe script (T1, first task).** `scripts/probe-gcp.sh record|diff` runs against a real
   project and stores normalized responses in `scripts/probe-baseline/gcp/`, in the same model as
   `probe-transit.sh`. It resolves the open API facts:
   - empty-plaintext encrypt (conformance round-trips `b""`);
   - the Ed25519 `data` size limit (undocumented [S15]; Appendix A "to be confirmed" stays open
     for signing, while MAC is 64 KiB, or 16 KiB on HSM);
   - getPublicKey and macVerify on a DISABLED version;
   - the exact `FAILED_PRECONDITION` messages and `ErrorInfo` reasons, purpose-mismatch messages,
     checksum-error messages and `RequestInfo` presence;
   - whether 429 carries `Retry-After` or `RetryInfo`.
2. **Mock tests (wiremock, per PR, server-free).** Built from the probe baselines:
   - exact request bodies (minimal fields, CRCs, base64, int64 as strings, no AAD when empty);
   - every row of §7;
   - CRC mismatch, flag false and `verifiedSuccessIntegrity` contradiction → `Unavailable`;
   - name mismatch → `Backend`;
   - a 3xx is never followed;
   - a 401 refreshes once, and only once;
   - token caching and single-flight under concurrency;
   - the metadata-server, authorized_user, external_account (STS and impersonation) and
     self-signed JWT flows against mocked token endpoints, including allowlist refusals for
     planted `token_url`s;
   - lazy ADC: building the provider does no I/O;
   - timeouts.

   The MSRV job excludes them like transit's (wiremock needs 1.88).
3. **Unit tests and fuzzing.** URI parser, CRC32C vectors, JSON decoding, and the PEM/algorithm
   cross-check. Fuzz targets: `gcp_uri`, `gcp_response` (success bodies through a hidden hook)
   and `gcp_classify`.
4. **Real-GCP conformance (env-gated).** `tests/conformance_gcp.rs` with `run_or_skip`. It needs
   `ANYKMS_GCP_PROJECT`, `ANYKMS_GCP_LOCATION`, `ANYKMS_GCP_KEY_RING` and ADC. Without them every
   case is `skip`; `ANYKMS_REQUIRE_FIXTURE=1` turns that into a failure in the nightly job.
   - **Fixture provisioning** goes outside the public API. The fixture's admin client (test code,
     reqwest plus the crate's public credential sources) runs as an admin identity with
     `roles/cloudkms.admin` on the test key ring:
     - it creates `t-<run>-<n>` keys with `destroyScheduledDuration=24h`;
     - it polls asymmetric versions out of `PENDING_GENERATION`;
     - rotate = create a version, then `updatePrimaryVersion` for AEAD keys;
     - disable = disable versions, then poll until the data plane refuses (bounded 2 min; [S20]);
     - at the end it schedules every version for destruction (key rings and keys cannot be
       deleted; destroyed versions are not billed).
   - **Data-plane identity.** A separate service account holds only the §12 roles **on the key
     ring**, so a missing key gives `NotFound`, not 403.
   - **`UnauthorizedProvider`.** A third SA with no roles, its token minted by impersonation.
   - **Setup script.** `scripts/gcp-test-setup.sh` (gcloud, idempotent) creates the key ring, the
     three SAs, the IAM bindings and a GitHub OIDC Workload Identity pool. The nightly CI job
     authenticates through `google-github-actions/auth`, which writes an `external_account` file
     and so dogfoods the WIF path. It is never run on fork PRs.
   - **Feature declarations** for the redesigned suite (§13):

     | Feature | GCP |
     |---|---|
     | `Aead`, `Mac`, `Describe`, `KeyWrap` (via `from_aead`) | Yes |
     | `Rewrap`, `DataKeys`, `RewrapWithAad` | NotApplicable("no native rewrap/data keys; recipes") |
     | `Signing(EcdsaP256Sha256 \| EcdsaP384Sha384 \| RsaPssSha256 \| RsaPssSha512 \| RsaPkcs1v15Sha256 \| RsaPkcs1v15Sha512 \| Ed25519)` | Yes |
     | `Signing(EcdsaP521Sha512 \| RsaPssSha384 \| RsaPkcs1v15Sha384)` | NotApplicable |
     | `Rotate` (AEAD) | Yes |
     | `MinDecryptionVersion`, `Throttle` | NotApplicable |
     | key-level `Disable` | NotApplicable (no key-level state) |
     | `DisableVersion` (new) | Yes |
     | `OversizePlaintext` (65 537) | Yes |
     | `NativeCiphertext` (raw REST encrypt in the fixture) | Yes |
     | `UnauthorizedProvider` | Yes |
     | `RequestCount` (counting `CredentialSource`) | Yes |

     `FixtureCaps`: `ciphertext_versions = false`, `hmac_versions_listed = true`, plus the new
     fields in §13.

     Implemented as: `tests/conformance_live.rs` (real GCP) and `tests/conformance.rs` (an
     in-process fake Cloud KMS, every PR); `EmptyPlaintext` is supported and `EmptyMessage`
     *not applicable* (T1);
     `Extension`, key-level `Disable` and `MinDecryptionVersion` are *not applicable*.
5. **Integration tests (env-gated)** cover what conformance does not:
   - unversioned signing URI → `Configuration` (implemented as `KeyMismatch`, §4.4);
   - versioned AEAD URI → `Configuration` (implemented as `KeyMismatch`, §4.4);
   - `used_primary` after rotation;
   - the regional endpoint;
   - the quota project;
   - the PSS-vs-PKCS#1 `KeyMismatch`;
   - an HSM key smoke test (8 KiB limit → `InvalidArgument`);
   - each ADC credential type the environment provides.
6. **Cost.** Software key versions are billed monthly while not destroyed, and HSM versions cost
   more. Expect roughly 60 keys per run, destroyed after 24 h. The nightly job runs once a day;
   per-PR real-GCP runs are manual (`workflow_dispatch`).

## 12. Operator docs to ship

Add a `docs/operations.md` section, or `docs/operations-gcp.md` if it grows. Implemented as
[`docs/operations-gcp.md`](../operations-gcp.md) (D5), with runbook rows for G7 and Q10. It
covers:

- **IAM, bound on the key or the key ring, never the project** [S22]:

  | Use | Role |
  |---|---|
  | AEAD / KEK | `roles/cloudkms.cryptoKeyEncrypterDecrypter`; split into `cryptoKeyEncrypter` / `cryptoKeyDecrypter` for write-only or read-only services |
  | Signing | `roles/cloudkms.signerVerifier`. It includes `viewPublicKey`, which the key-type check and local verify need; `roles/cloudkms.signer` alone works only with `TrustCaller` and no verification |
  | MAC | `roles/cloudkms.signerVerifier` (`useToSign` + `useToVerify`) |
  | Verify-only services, JWKS publishers | `roles/cloudkms.publicKeyViewer` |
  | `describe` and the AEAD/MAC key-type check | `cloudkms.cryptoKeys.get`, `cloudkms.cryptoKeyVersions.get`, `cloudkms.cryptoKeyVersions.list`, through `roles/cloudkms.viewer` on the key or a custom role (the operational roles carry no metadata permissions) |
  | App identities, never | `roles/cloudkms.admin`, `cryptoKeyVersions.destroy`, `cryptoOperator` (too broad) |
- **The 403 "(or it may not exist)" behavior**, and that VPC Service Controls denials are
  `PermissionDenied`.
- **Quotas** [S19]: cryptographic requests per calling project; HSM symmetric 500 QPS and
  asymmetric 50 QPS per region in the hosting project; EKM 100 QPS. 429 → `Throttled`. Share a
  `RetryBudget` per project (the §11 retry budgets). Per-second enforcement can trip even when the
  per-minute view looks fine.
- **Size limits.** Encrypt 64 KiB each for plaintext and AAD (HSM: 8 KiB combined); MAC 64 KiB
  (HSM: 16 KiB); Ed25519 input TBD. Bulk data goes through `EnvelopeAead`.
- **Rotation.**
  - AEAD: automatic `rotationPeriod` is fine; find stale rows with
    `decrypt_with_info().used_primary()`; rotate envelopes with `rewrap_local`.
  - Signing and MAC: create a version, publish the JWKS (`jose::jwks_from_versions`), switch the
    URI's version, keep the old version ENABLED until its tokens expire, then disable it. The
    newest-enabled mode comes later.
- **Disabling and destroying.** Propagation takes about a minute, plus the public-key cache TTL.
  Destroying a version loses its data, after `destroyScheduledDuration` (≥ 24 h); restore it
  while it is DESTROY_SCHEDULED.
- **Protection levels.** HSM limits and quotas. EXTERNAL keys: Aead only, availability depends on
  the EKM, and EKM errors show as `Backend` or `Unavailable`.
- **Credentials.** The ADC order. Prefer the metadata server or Workload Identity Federation over
  SA keys. `quota_project` with user credentials. Credential files from untrusted sources are
  refused for non-Google token URLs.
- **Endpoints.** Regional REP and PSC.
- **Runbook rows** for each `ErrorKind` with the GCP causes from §7.
- **Startup check.** Call `preflight()` on each handle (credentials are
  lazy, §19).

## 13. Dependencies on the shared prerequisites

GCP needs **no new core types** for its first release: `decrypt_with_info`, `KeyVersionUnusable`,
`retry_hint`, `Unauthenticated`, `BackendDetail::{code, request_id}`, `KeyWrapKey::from_aead` and
`KeyInfo::state: Option` already exist. It needs **no layered extension handle** either: there
are no backend-specific per-operation options, and the newest-enabled mode is an `OpenOptions`
extension, which exists.

It is **blocked on the conformance redesign** (§22 "Deferred", steps 1–7). Beyond that design it
needs the following. Each item names the redesign agent's deliverable it extends.

| # | Need | Why GCP |
|---|---|---|
| P1 | §22 capability gating (`Aead`, `Rewrap`, `DataKeys`, `Mac`, `Describe`, `KeyWrap`), `Undeclared` fails, `AeadBridge` builder | no `Rewrap` or `DataKeys` |
| P2 | **Version-scoped disable**: `Feature::DisableVersion`, `Fixture::disable_version(&TestKey, &KeyVersion)`; cases for AEAD (old ciphertext → `KeyVersionUnusable`, caller class; disabled primary → encrypt `KeyVersionUnusable`, config class), signing (sign, verify and public key of the disabled version), MAC; `describe` shows that version `Disabled` with key `state() == None`. Key-level `Disable` cases expecting `KeyStateInvalid` stay for transit and local | Appendix A: `FAILED_PRECONDITION` on a version → the version-scoped kind |
| P3 | **Rotation per family**: AEAD rotate (primary moves) separate from signing/MAC rotate, where the fixture returns the new **versioned** URI (`TestKey::with_version`) and the old handle keeps signing with the pinned version; `public_key()` follows only under the newest-enabled mode (a later feature flag) | pinned signing keys |
| P4 | `TestKey` URIs for signing and MAC keys are versioned; the cases must not strip or add a version | URI rule |
| P5 | `FixtureCaps::key_state_per_version` (accept `state() == None`, check `versions()`), `primary_version_for_signing_keys = false` | §8 |
| P6 | A `used_primary` case gated on `FixtureCaps::reports_used_primary` (after rotation: old ciphertext `Some(false)`, new `Some(true)`) | the only staleness signal |
| P7 | `FixtureCaps::oversize_mac_input: Option<usize>` (65 537), and later `oversize_message_input` for Ed25519 once T1 finds the limit | Appendix A "to be confirmed"; shared with AWS's 4 KiB + 1 |
| P8 | Fixture state changes may take a bounded wait: `disable`/`disable_version` return only once the data plane refuses (the fixture's job), and cases do not assume instant effect beyond that; a provider knob (`public_key_ttl(0)`) for the fixture's provider | disable propagation ([S20]) and the verifier cache |
| P9 | `VERIFY` capability semantics in `describe` cases: present when the handle verifies, local or not | §19 local verification |

Planned later, not blocking: native `KeyWrap` part (AWS-driven) → GCP `asymmetricDecrypt` KEKs;
core `EcdsaSecp256k1Sha256` / `HmacSha224` → mapping rows; `KeyWrap::unwrap_with_info` (Q9).
Implemented as: the `asymmetricDecrypt` KEKs shipped without a new part (`KeyWrapKey::new`
takes any `KeyWrap`); the other two are still later.

## 14. Tasks

| # | Task | Size | Depends on |
|---|---|---|---|
| T1 | Test project + `scripts/gcp-test-setup.sh` + `scripts/probe-gcp.sh` with baselines; resolve the §11.1 facts and update §7 and Appendix A | M | GCP project and billing (maintainer) |
| T2 | Crate scaffold, features, lints, `deny.toml` entries, CI per-crate jobs (incl. the `rsa-rustcrypto` no-default exception) | S | — |
| T3 | `uri.rs` + allowlists + `gcp_uri` fuzz target | S | T2 |
| T4 | HTTP client: TLS/proxy/timeouts (from transit), zeroizing bodies, proto3-JSON helpers, CRC32C, name checks, `errors.rs` per §7 | L | T1 (messages), T2 |
| T5 | Credentials: trait, cache and single-flight, 401 refresh-once, metadata server, ADC file discovery, authorized_user, SA self-signed JWT, external_account file/url + STS + impersonation, impersonated SA, static/none; mock tests | L | T4 |
| T6 | `GcpAeadKey` (encrypt, decrypt, `decrypt_with_info`), key-type check cache, `Describe` / `GcpKeyInfo` | M | T4 |
| T7 | Signing handles, `GcpVerifier` (public key cache → `LocalVerifier`), `PublicKeys` | M | T4 |
| T8 | `GcpMacKey` (macSign, macVerify, tag checks) | S | T4 |
| T9 | `GcpProvider` (all openers, `key_wrap` via `from_aead`, version rules at open), `from_env`, facade features and `with_default_providers` | M | T5–T8 |
| T10 | Mock suite + TRACE hygiene test + fuzz `gcp_response`, `gcp_classify` | M | T9 |
| T11 | Conformance fixture (admin client, provisioning, cleanup, declarations), `conformance_gcp.rs`, nightly WIF workflow | M | T9, **P1–P9** |
| T12 | Docs: crate rustdoc, operator section, runbook rows, README/CHANGELOG, PLAN Appendix A and §18 updates | S | T11 |
| T13 | Newest-enabled mode (§4.4) + its conformance cases | M | T12, P3 |
| T14 | Later: secp256k1 / HMAC-224 rows (after core), `asymmetricDecrypt` `KeyWrap` (after the native part), optional `google-cloud-auth` adapter (Q3) | S each | core / AWS work |

Status: T1–T12 done (T1 on 2026-10-12); T13 open; of T14 the `asymmetricDecrypt`
`KeyWrap` is done.

Critical path: T1 → T4 → T5/T6–T8 → T9 → T10. T11 waits for the redesign. About 3–4 weeks of
focused work, auth being the largest single item.

## 15. Risks and open questions

Risks:

- **Error messages are not a contract.** `FAILED_PRECONDITION` sub-cases, checksum and purpose
  messages are matched on text. Mitigations: prefer `ErrorInfo.reason` where present; pin with
  probe baselines and rerun them per release; unknown messages fall back to `Backend` (never
  misclassified) with a warn event.
- **ADC surface.** Owning credential flows is security-sensitive and drifts with Google
  (universe domains, new `type`s). Mitigations: a narrow first set, unknown types refused by name,
  host allowlists for token URLs, and the Q3 adapter as an escape hatch.
- **Real-GCP CI** needs a funded project and secrets, and does not run on fork PRs, so regressions
  can surface nightly rather than per PR. The mock suite carries the per-PR load.
- **Eventual consistency.** Disable propagation (about 1 min) and the IAM change delay make the
  real-GCP suite slow and potentially flaky. Fixture polling (P8) bounds it.
- **Undocumented limits.** Ed25519 input size; empty-plaintext behavior. If GCP rejects empty
  plaintext, the `aead::roundtrip` empty case needs a declaration (an `EmptyPlaintext` feature),
  and the docs must state it.
- **Duplicated HTTP plumbing.** `zbuf.rs`, TLS selection and proxy handling are copied from
  transit (Q4). Implemented as: shared through `anykms-http`, nothing copied.

Open questions for the maintainer. Answered since (PLAN §23 and the implementation): Q1 in-house
(§23 Q5); Q4 `anykms-http` now (§23 Q4); Q5 `Configuration` at open, no `compile_error!`; Q7
allowlists optional (§23 Q8). Q2, Q3, Q6, Q8, Q9 and Q10 are still open.

- **Q1.** Confirm the in-house client over `google-cloud-kms-v1` (§2). The alternative is giving
  `anykms-gcp` its own MSRV (1.91+, tracking Google's).
- **Q2.** Should `GcpProviderBuilder::emulated_data_keys()` (explicit, provider-level opt-in)
  attach `EmulatedDataKeys` as the `AeadKey` data-keys part for config-driven code? It would still
  report no `DATA_KEYS` capability, and the span would say so. Default in this plan: no.
- **Q3.** Ship an optional `google-cloud-auth` adapter feature (higher MSRV, excluded from the
  MSRV job) for AWS-sourced and executable WIF, GDCH and future types? (Answered 2026-10-12:
  shipped as `Credentials::google_cloud_auth`, inside the MSRV job at 1.91,
  [credentials-plan.md](credentials-plan.md).)
- **Q4.** Extract the shared HTTP plumbing (TLS provider selection, zeroizing buffers, redirect
  policy, `Retry-After` parsing) into a published `anykms-http` crate now, or copy it into
  `anykms-gcp` and extract it when Azure (the next REST backend) arrives? Default: copy, with a
  test that keeps the two in sync.
- **Q5.** RSA backend enforcement: a `compile_error!` without an `rsa-*` feature (this plan), or
  an unconditional `aws-lc-rs` dependency?
- **Q6.** Per-project credentials and endpoints. A URI authority alias
  (`gcp-kms://<alias>/projects/…`) breaks Tink-compatible spelling. Alternative: per-project
  overrides in config keyed by project ID. Defer until asked?
- **Q7.** Make `allowed_projects` mandatory, with an explicit `allow_any_project()`, given the
  exfiltration risk in §4.2?
- **Q8.** EKM and Key Access Justifications failure classes (`Unavailable` vs `PermissionDenied`
  vs `Backend`). Pin them only from observed responses (needs an EKM test setup), or leave them as
  `Backend` in the first release?
- **Q9.** Add `KeyWrap::unwrap_with_info` (or `EnvelopeAead::decrypt_with_info`) so envelope
  users on GCP can find rows wrapped under a non-primary version without rewrapping
  unconditionally? This is a recipes and core change, shared with Azure.
- **Q10.** Ship the newest-enabled mode in the first release after all? It is about M in size, and
  rotating signing keys without a config change is the main operational gap.

## Sources

- [S1] PLAN.md Appendix A, §19–§22 (this repository).
- [S2] Key purposes and algorithms: https://docs.cloud.google.com/kms/docs/algorithms
- [S3] `cryptoKeys.encrypt`: https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt
- [S4] `cryptoKeys.decrypt`: https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/decrypt
- [S5] `asymmetricSign`: https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign ; `macSign` / `macVerify`: …/cryptoKeyVersions/macSign, …/cryptoKeyVersions/macVerify ; field docs: https://github.com/googleapis/googleapis/blob/master/google/cloud/kms/v1/service.proto
- [S6] Data integrity guidelines (CRC32C, verified flags, name checks, limited retries): https://docs.cloud.google.com/kms/docs/data-integrity-guidelines
- [S7] `rawEncrypt`: https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/rawEncrypt
- [S8] Creating and validating digital signatures (data vs digest, EKM requires data, DER, PSS salt = digest length): https://docs.cloud.google.com/kms/docs/create-validate-signatures
- [S9] Service endpoints and regional endpoints: https://docs.cloud.google.com/kms/docs/reference/rest , https://docs.cloud.google.com/kms/docs/reference/service-apis-overview , https://docs.cloud.google.com/docs/security/compliance/access-regional-google-apis-endpoints
- [S10] crates.io `google-cloud-kms-v1`, `google-cloud-auth`, `google-cloud-gax`, `google-cloud-gax-internal` (versions, `rust_version`, dependencies; queried 2026-10-05): https://crates.io/crates/google-cloud-kms-v1
- [S11] docs.rs `google-cloud-kms-v1` (GA status, `default-rustls-provider`): https://docs.rs/google-cloud-kms-v1/latest/google_cloud_kms_v1/
- [S12] docs.rs `google-cloud-gax` `ClientBuilder` and `retry_policy` (`NeverRetry`, `Aip194Strict`): https://docs.rs/google-cloud-gax/latest/google_cloud_gax/client_builder/struct.ClientBuilder.html
- [S13] docs.rs `gcp_auth`: https://docs.rs/gcp_auth/latest/gcp_auth/
- [S14] Application Default Credentials: https://docs.cloud.google.com/docs/authentication/application-default-credentials
- [S15] MAC limits (64 KiB; 16 KiB on HSM): https://docs.cloud.google.com/kms/docs/create-validate-mac-signatures ; Ed25519 limit undocumented: https://discuss.google.dev/t/cloud-kms-software-ed25519-exact-asymmetricsign-message-size-limit/399425
- [S16] `getPublicKey`: https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey ; CryptoKeyVersion states: https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions
- [S17] Observed error texts: "is not enabled, current state is: DISABLED" (https://github.com/getsops/sops/issues/1421); "Decryption failed: verify that 'name' refers to the correct CryptoKey" (https://github.com/googleapis/nodejs-kms/issues/145)
- [S18] "Permission … denied on resource … (or it may not exist)": https://github.com/hashicorp/terraform-provider-google/issues/5103
- [S19] Quotas (`RESOURCE_EXHAUSTED`, HTTP 429, per-second enforcement): https://docs.cloud.google.com/kms/quotas
- [S20] Enable and disable key versions (propagation "usually within a minute"): https://docs.cloud.google.com/kms/docs/enable-disable
- [S21] Community emulators: https://github.com/blackwell-systems/gcp-kms-emulator , https://github.com/winor30/fake-cloud-kms , https://github.com/floci-io/floci-gcp
- [S22] Permissions and roles: https://docs.cloud.google.com/kms/docs/reference/permissions-and-roles
