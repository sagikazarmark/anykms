# anykms-aws: AWS KMS backend plan

Status: **implemented** (2026-10-06) on `cloud-backends`; the live probe **A0 is done**
(2026-10-07, us-east-1; results in `docs/research/aws-kms.md`) and the live conformance suite
passed on real AWS (356 passed, 0 failed, at the end of wave W8; PLAN §25.3). See "Implementation notes" below and PLAN §24. Written 2026-10-05 as a draft for
maintainer review; the plan text is kept, and places where the code departs from it are marked
"Implemented as: …". Inputs: `docs/PLAN.md` §0–3, §6 (the transit model), §8, §10–12, Appendix A (AWS column = decisions
already made, honored here), §19 "Decisions for the cloud backends", §20, §21 (AWS AAD encoding,
cloud backend notes), §22 (deferred conformance redesign). Facts from the AWS API reference, the
KMS developer guide and crates.io as of 2026-10-05 (sources at the end). Anything marked
**verify** must be confirmed against real AWS in task A0 before code depends on it.

Shared prerequisites (conformance redesign, layered extension handles, new handle parts) are
planned elsewhere; §13 lists exactly what this backend needs from each.

## Implementation notes (2026-10-06)

Where the implementation differs from the plan below (rows A1–A10 of
[`review-consistency.md`](review-consistency.md) §2.1, plus the review fix round):

- **Shared HTTP code (cloud README Q4):** `anykms-http` (TLS provider precedence, the
  no-redirect client, zeroizing bodies, `Retry-After`, the single-flight credential cache), not a
  copied `zbuf.rs` (Q10 below).
- **Backend name** is `aws` (D1), not `aws-kms`; the scheme stays `aws-kms`, exported as `SCHEME`.
- **Region grammar (security review L3):** a region must have the AWS region shape
  (`<area>-<name>…-<n>`, e.g. `eu-west-1`, `us-gov-west-1`) and belong to the ARN's partition
  (`cn-*` only in `aws-cn`, `us-gov-*` only in `aws-us-gov`, the ISO and European Sovereign Cloud
  prefixes only in theirs). A label such as `s3` is `InvalidArgument`, so a derived host is always
  a KMS endpoint. `allowed_regions` and per-region endpoints use the same rule.
- **Endpoints (L4):** configured endpoints are validated once at build; derived ones are computed
  on each open (a `format!`). There is no endpoint cache that grows with the regions of opened
  URIs.
- **Key administration (L5):** the hidden `Admin` API (`AwsProvider::__admin`,
  `anykms_aws::__test::Admin`) exists only with the non-default `test-fixtures` feature (*implemented as the hidden
  `__test-fixtures`, refused without debug assertions; superseded by §25.3 C1*), which the
  crate's tests and examples enable through a path dev-dependency, and it honors the provider's
  `allow_loopback_http`. Other fuzz hooks are in `__fuzz` (no `__private` module).
- **URI type:** `AwsKeyRef` with `key_id()` / `alias_name()`; the key/alias enum is private.
- **A1, unversioned verify input:** a signature or tag **without** a version verifies with the
  handle's key (an ARN names one key, so absence cannot select a key; conformance
  `Unversioned::UsesCurrent`). GCP and Azure refuse it with `InvalidArgument`. See §8.
- **A2, AAD cap:** 3072 AAD bytes (4096 base64url characters) and 4096 bytes for native contexts
  (`MAX_AAD_BYTES`, `MAX_CONTEXT_BYTES`); the caps may only rise (§4, Q2). A0 measured the real
  limit at a single 8140-character value (8150 bytes of key and value), about twice both caps;
  they are kept, and raising them is the maintainer's call (PLAN §23 Q7). *Superseded in part
  by the release plan D1 and R-50: the AAD is 6144 hex characters under `associatedData`
  (about 1.3× headroom), and the AAD cap binds only the operations that produce a ciphertext,
  never `Decrypt`.*
- **A0 results (2026-10-07):** real AWS answers a malformed ARN with `NotFoundException`
  "Invalid arn …" (not `InvalidArnException`), now `Configuration` by message; the
  `InvalidSignatureException` text carries the expected canonical request after a blank line,
  so only its first paragraph is kept; fixed texts recorded live are pinned. An invalid grant
  token is accepted (AWS ignores tokens it does not need; not an error, §9). `GetPublicKey`
  succeeds on a disabled key. *Implemented as (architecture plan A3(f)): the backend sends an
  uncached `DescribeKey` before `GetPublicKey` and refuses a key that is not enabled.* The recorded error bodies, redacted, are replayed by the
  mock test `recorded_aws_error_responses` (§7).
- **A3, foreign ARN on verify:** `NotFound` before any request, as for `public_key_version`
  (Appendix A, PLAN §23 Q12), not `VerificationFailed` (§8, Q5).
- **A4, clock skew:** not retried inside the backend. A skew rejection records the server's clock
  offset and is a retryable `Unavailable`, so the caller's `Retry` signs the next attempt with the
  corrected clock (PLAN §23 Q14; §4, Q6).
- **A5, symmetric `KeyInfo`:** lists the key ARN as its one version, with no primary version (§6).
- **A6, RSA `KeyWrap`:** wraps **locally** with RSAES-OAEP-SHA-256 over the pinned public key
  (`GetPublicKey`) and unwraps with `Decrypt` (cloud README §2.5, Q12), not with server-side
  `Encrypt`. It needs the `rsa-aws-lc-rs` (default) or `rsa-rustcrypto` feature; without one,
  wrapping fails with `Unsupported` (§5).
- **A7, symmetric KEK handle:** `key_wrap` returns a dedicated `AwsKeyWrapKey`
  (`AwsProvider::key_wrap_key`), not `KeyWrapKey::from_aead` over the AEAD handle (§5).
- **A8, RSA KEK capabilities** include `REWRAP` (`ReEncrypt` with both algorithms) (§6).
- **A9, `AwsKeyInfo`** has no multi-Region primary/replica ARNs (only `multi_region`); the type is
  `#[non_exhaustive]`, so they can be added later (§6).
- **A10, `XksProxy*`:** only the connectivity exceptions that reach the data plane
  (`XksProxyUriUnreachableException`, `XksProxyInvalidResponseException`) are mapped to
  `Unavailable`; the other `XksProxy*` exceptions are control-plane only (§7).
- **Alias responses:** for alias URIs, every key ARN AWS returns (`DescribeKey`, `Sign`,
  `GenerateMac`, `GetPublicKey`) must be in the alias's partition, region and account, else
  `Backend`; key URIs keep the equality check (§8).
- **Every handle** has `aws_info()` and `verify_with_describe()`. *Implemented as (architecture
  plan A5): `impl Preflight`, and `AwsKeyInfo` attached to every `describe()` result.*
- **Tracing (D3):** the shared span schema (`resource`, `code`), plus an `anykms.aws.token` span
  for credential fetches (§10).
- **Emulator:** Floci on every PR (no token needed), LocalStack when `LOCALSTACK_AUTH_TOKEN` is set
  (§11, Q3).
- **Built since:** the `sdk-credentials` bridge (Q8), with `credential_process` and profile web
  identity moved to it and MSRV 1.91 ([credentials-plan.md](credentials-plan.md), PLAN §28).

## 1. Scope

First release of `anykms-aws` (lockstep version with the workspace):

- **Symmetric keys** (`SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`): `Aead`, `Rewrap` (incl. AAD),
  `DataKeys` (AAD bound), `Describe`; `KeyWrap` through `AeadKeyWrap`.
- **Signing keys**: ECDSA P-256/384/521 and RSA 2048/3072/4096 (PSS and PKCS#1 v1.5, SHA-256/384/512)
  as `DigestSigner` + `DigestVerifier` + `PublicKeys` + `Describe`; Ed25519
  (`ECC_NIST_EDWARDS25519`, pure) as `MessageSigner` + `MessageVerifier` + `PublicKeys` + `Describe`.
- **HMAC keys** (`HMAC_256/384/512`): `Mac` + `Describe`.
- **Native encryption-context maps and grant tokens** through the layered extension mechanism (§9).
- **Gated on prerequisites, droppable without breaking anything** (parts are additive):
  wrapped-only data keys (`GenerateDataKeyWithoutPlaintext`) and RSA `ENCRYPT_DECRYPT` keys as a
  native `KeyWrap` (RSAES-OAEP-SHA-256).
- Credentials: environment, shared config/credentials files (static keys, `credential_process`),
  web identity (EKS IRSA / OIDC), ECS and EKS Pod Identity container credentials, EC2 IMDSv2, plus
  a public `CredentialSource` trait for anything else.

Non-goals (first release), each with where it goes:

- Key lifecycle (`CreateKey`, policies, aliases): IaC; fixtures do it through a hidden admin call.
- `ED25519_PH_SHA_512` (double-hashes, Appendix A), ML-DSA (`MuSigner`, §12), SM2, secp256k1
  (`ECC_SECG_P256K1`) and `HMAC_224` (no core variants yet; §21 4.8 — additive later), ECDH
  `DeriveSharedSecret`, `GenerateRandom`, data key pairs, Nitro `Recipient` attestation, `DryRun`.
- SSO / IAM Identity Center, profile `role_arn` chaining, `AssumeRole` with MFA: use a custom
  `CredentialSource` or the optional SDK bridge (§2, open question Q8).
- MRK-aware key matching (Appendix A: one replica ARN per region, shared logical `kek_id`).
- Local (client-side) verification inside the backend: verification stays server-side; high-volume
  verifiers use `CachedVerifier` (recipes) over `PublicKeys`.
- Decrypt-side DEK cache, metrics layer: M5 items owned elsewhere.

## 2. Client decision

| | `aws-sdk-kms` + `aws-config` | in-house SigV4 on reqwest |
|---|---|---|
| MSRV | **1.94.1** for every current release (`aws-sdk-kms` 1.123.0, `aws-config` 1.12.0, `aws-sigv4` 1.6.0, `aws-smithy-runtime` 1.16.0). Last `aws-sdk-kms` with MSRV ≤ 1.85 is 1.77.0 (2025-07); `aws-config`/`aws-sigv4` have none in their last 100 releases | 1.85 (workspace) |
| Security fixes on our MSRV | an MSRV-aware resolver holds users on old SDK releases; a downstream project had to raise its MSRV to 1.94.1 to get the SDK fix for RUSTSEC-2026-0253 | ours to ship |
| TLS | `default-https-client` = rustls **aws-lc** (+ `prefer-post-quantum`), its own hyper client next to reqwest; `rustls-ring` only via the legacy hyper-0.14 path | reuse transit's per-client provider selection (§20): `ServerConfig`-style override → process default → aws-lc-rs → ring |
| Retries | SDK standard retry must be disabled (`RetryConfig::disabled()`) everywhere, including inside `aws-config`'s IMDS/STS clients | none below `Retry` by construction (§11, §19) |
| Redirects, timeouts, proxies, zeroizing bodies | partly configurable; plaintext passes through SDK `Blob`s we cannot zeroize | same controls and zeroizing buffers as transit (§4, §6.2) |
| Credential chain | complete (SSO, role chaining, process, IMDS, container, web identity), lazy | the subset in §1, lazy; ~1.5k LOC incl. STS web identity |
| Weight | aws-smithy-* runtime stack + hyper-util/tower + aws-lc-rs TLS | reqwest + serde_json + hmac/sha2 (already in the tree) |
| Testability | `endpoint_url` to wiremock works; error metadata via `ProvideErrorMetadata` | wiremock, same harness as transit |

**Decision: in-house**, mirroring transit (§6.1). MSRV alone decides it (the workspace is 1.85 and
the SDK moves its MSRV to ~stable−2 continuously); control over retries, zeroization and TLS
provider confirms it. SigV4 for a JSON-1.1 POST with a fixed header set is ~300 LOC plus the AWS
SigV4 test-suite vectors. Expected crate size ≈ transit (4–5k LOC with credentials).

Escape hatch (Q8): an off-by-default `sdk-credentials` feature adapting
`aws_credential_types::provider::ProvideCredentials` into `CredentialSource`, for users on a new
toolchain who need SSO or role chaining. It carries the SDK's MSRV; the MSRV CI job excludes it.
(Superseded 2026-10-12: built as `credentials::SdkCredentials`; with the workspace on 1.91 the
MSRV-aware resolver holds the SDK types on releases that build there, so the MSRV job keeps it.
See [credentials-plan.md](credentials-plan.md).)

## 3. Crate layout and integration

```
crates/anykms-aws/
  src/lib.rs          crate docs ("Behavior worth knowing", TLS provider, zeroization limits), BACKEND = "aws"
  src/config.rs       AwsProvider builder options, EnvConfig (from_env)
  src/provider.rs     AwsProvider: Provider impl, typed openers, describe cache, per-endpoint clients
  src/uri.rs          aws-kms:// ARN grammar (fuzzed), AwsKeyRef { partition, region, account, key } + key_id()/alias_name()
  src/endpoint.rs     partition/region → host (standard, FIPS, dual-stack), endpoint overrides
  src/client.rs       JSON 1.1 POST (X-Amz-Target: TrentService.<Op>), no redirects, timeouts, zbuf bodies,
                      x-amzn-RequestId capture, clock-skew tracking
  src/sigv4.rs        AWS4-HMAC-SHA256 signer; signing key in Zeroizing
  src/credentials/    mod.rs (CredentialSource trait, Credentials, cache + single-flight refresh),
                      env.rs, profile.rs (INI parser, fuzzed; credential_process), imds.rs, container.rs,
                      web_identity.rs (STS AssumeRoleWithWebIdentity), chain.rs
  src/errors.rs       exception → ErrorKind table (§7), BackendDetail
  src/context.rs      AAD ↔ EncryptionContext wire encoding (§4), EncryptionContext type, size check
  src/handles.rs      AwsAeadKey, AwsDigestKey, AwsEd25519Key, AwsMacKey (+ AwsRsaKeyWrap, gated)
  src/keyinfo.rs      AwsKeyInfo (from DescribeKey), KeySpec/KeyUsage/algorithm mapping (§6)
  src/zbuf.rs         copied from transit (see Q10)
  tests/              mock.rs (wiremock), credentials.rs, hygiene.rs, conformance_localstack.rs,
                      conformance_live.rs, integration.rs, sigv4_vectors.rs + tests/data/
```

Implemented as: the backend name is `aws`, not the scheme (D1); the key/alias distinction is
private to `uri.rs` (`AwsKeyRef::key_id()` / `alias_name()`); no `zbuf.rs` (`anykms-http`); the
hidden admin call in `admin.rs` behind the `test-fixtures` feature (*now `__test-fixtures`,
superseded by §25.3 C1*); credentials split into
`env.rs`, `profile.rs`, `process.rs`, `imds.rs`, `container.rs`, `sts.rs`, `chain.rs`; tests
`mock.rs`, `credentials.rs`, `hygiene.rs`, `emulator.rs`, `conformance_emulator.rs`,
`conformance_live.rs` and the shared `tests/e2e/` fixture.

Cargo features: `default = ["rustls-ring"]` (*implemented as `rustls-aws-lc-rs`, §25.3*);
`rustls-ring`, `rustls-aws-lc-rs` (same precedence
rules as transit, §20); `tracing`; `http2`; `sdk-credentials` (Q8). Dependencies: core, zeroize,
serde, serde_json, base64, sha2, hmac, reqwest (`rustls-no-provider`, `json`), rustls,
rustls-native-certs, httpdate, tokio (`sync` for single-flight refresh), optional tracing. Test
targets that need `anykms-conformance` or AWS are excluded from the package, as in transit (§22).
Implemented as: `default = ["rustls-ring", "rsa-aws-lc-rs"]` (*superseded by §25.3 C2: the
default is `rustls-aws-lc-rs`*), plus `rsa-aws-lc-rs` / `rsa-rustcrypto` (local RSA-OAEP wrap,
A6) and the test-only `test-fixtures` (*now the hidden `__test-fixtures`, §25.3 C1*); no
`sdk-credentials`. `anykms-conformance` is published, so only the targets that need an emulator
or AWS credentials (and the A0 probe example) are excluded (*superseded by the release review,
PLAN §26: the package ships no test targets, only the SigV4 vectors its unit test reads*).

Facade (`anykms`): feature `aws = ["dep:anykms-aws"]`; `rustls-ring` / `rustls-aws-lc-rs` and
`tracing` forward with `anykms-aws?/…`; re-export as `anykms::aws`. `with_default_providers()`
always registers `AwsProvider::from_env()` when the feature is on: construction does no I/O and
needs no variable (the region comes from the ARN), so it is never "skipped" for missing config; a
malformed variable (e.g. `AWS_USE_FIPS_ENDPOINT=maybe`) is a `Configuration` error from
`with_default_providers()`. Without the feature, the skip entry lists scheme `aws-kms`.
Implemented as planned (D2); the skip entry's backend name is `aws` (D1), and `rsa-*` and `http2`
forward too.

## 4. Configuration, key URIs, AAD encoding

```rust
AwsProvider::builder()
  .credentials(CredentialSource::default_chain())      // or ::static_(..), ::env(), ::profile("p"), custom impl
  .allowed_accounts(["111122223333"])                  // optional allowlists (Q4)
  .allowed_regions(["eu-west-1", "eu-central-1"])
  .endpoint("eu-west-1", "https://vpce-0abc-xyz.kms.eu-west-1.vpce.amazonaws.com")  // per-region override
  .fips(true).dual_stack(false)
  .connect_timeout(2s).request_timeout(10s).pool_idle_timeout(50s).tcp_keepalive(30s)
  .http_version(HttpVersion::Http1).proxy(Proxy::None)
  .crypto_provider(p)
  .build()?;
AwsProvider::from_env()?;
```

- **URI grammar** (Appendix A; also Tink's format, so Tink key URIs open unchanged):
  `aws-kms://arn:<partition>:kms:<region>:<account>:key/<key-id>` or `…:alias/<alias-name>`.
  Strict parser: partition ∈ {`aws`, `aws-cn`, `aws-us-gov`} built in (others only with an explicit
  endpoint); region `[a-z0-9-]+`; account 12 digits; key id UUID or `mrk-` + 32 hex; alias name
  `[A-Za-z0-9/_-]{1,256}`, never `aws/…` (AWS-managed keys cannot sign/MAC and are not app KEKs —
  refused with a hint). No query, fragment, percent-encoding or whitespace. Bare key IDs and alias
  names are refused with a hint (region and account must be explicit). Fuzzed.
  Implemented as: the region must have the AWS region shape (`<area>-<name>…-<n>`, at most 32
  characters) and belong to the partition (`cn-*` only in `aws-cn`, `us-gov-*` only in
  `aws-us-gov`, the ISO and EUSC prefixes only in theirs; security review L3), not
  `[a-z0-9-]+`.
- **Address policy.** The URI picks partition, region and account, never a host: the host is
  derived (`kms[-fips].<region>.amazonaws.com[.cn]`, dual-stack `kms[-fips].<region>.api.aws`) or
  comes from `.endpoint(region, url)` / `AWS_ENDPOINT_URL_KMS` / `AWS_ENDPOINT_URL`. `http://` only
  for literal loopback IPs with `.allow_loopback_http()` (emulators), as in transit. Accounts and
  regions outside a configured allowlist → `Configuration` at open. Without an allowlist any account
  is accepted (documented: a URI from untrusted input could point at an attacker's key, which then
  receives plaintext on `encrypt`; Q4).
- **Signing region** = the ARN's region; one lazily built client per endpoint, shared credentials.
  Implemented as: one HTTP client and shared credentials for the provider; the endpoint is
  resolved per open (per-region override, global override, else derived) and nothing is cached
  per region (L4).
- **`from_env`**: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`, `AWS_PROFILE`,
  `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`
  (+ `AWS_ROLE_SESSION_NAME`), `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `_FULL_URI` +
  `AWS_CONTAINER_AUTHORIZATION_TOKEN[_FILE]`, `AWS_EC2_METADATA_DISABLED`,
  `AWS_EC2_METADATA_SERVICE_ENDPOINT[_MODE]`, `AWS_REGION`/`AWS_DEFAULT_REGION` (STS only),
  `AWS_USE_FIPS_ENDPOINT`, `AWS_USE_DUALSTACK_ENDPOINT`, `AWS_ENDPOINT_URL[_KMS]`,
  `AWS_CA_BUNDLE` (replaces roots, as `ca_pem`). Plus `ANYKMS_AWS_ALLOWED_ACCOUNTS` /
  `_REGIONS`. The chosen credential source is logged at INFO (kind only). Implemented with
  `ANYKMS_AWS_ALLOW_LOOPBACK_HTTP` too, and `AwsProviderBuilder::from_env_with(lookup)` as a
  testing seam (`docs/operations-aws.md` "Environment").
- **Credentials** are lazy (§19): resolved on the first operation, cached, refreshed 5 min before
  expiry by one task at a time (tokio `Mutex`, as transit `Login`). Container endpoints must be
  `169.254.170.2`, `169.254.170.23`, `[fd00:ec2::23]`, loopback, or HTTPS (the SDK's allowlist).
  IMDSv2 only (token PUT, hop limit, 1 s timeouts, no IMDSv1 fallback). Secrets are `SecretString`;
  file-based sources reuse transit's permission checks. On `ExpiredTokenException` /
  `UnrecognizedClientException` / `InvalidClientTokenId` the source is invalidated and the request
  retried **once** if it returns different credentials (§11 exception for authentication).
- **Clock skew.** Every response's `Date` updates a skew offset used for signing. A
  `RequestTimeTooSkewed` / "Signature expired" rejection is retried once with the corrected offset
  (same once-only authentication exception; Q6). Implemented as: not retried in the backend; the
  rejection records the offset and is a retryable `Unavailable`, and the caller's `Retry` signs
  the next attempt with the corrected clock (PLAN §23 Q14, A4).
- **AAD encoding (wire format, never changes; §21 0.3).** Empty AAD → no `EncryptionContext` at all.
  Non-empty → `{"anykms-aad": base64url_nopad(aad)}` (reserved key name: Q1, must be fixed before the
  first ciphertext ships; *superseded by the release plan D1: `{"associatedData": lowercase_hex(aad)}`,
  Tink's mapping*). Same mapping on `Encrypt`, `Decrypt`, `ReEncrypt` (source = destination),
  `GenerateDataKey`. **Size limit:** AWS documents no encryption-context size limit (searched the
  API reference, developer guide and quotas pages; grant constraints cap values at 384 chars, which
  is a different limit). A0 probes the real limit; the backend enforces
  `encoded_len(aad) ≤ min(probed limit − key length, 8192 chars)` before I/O with
  `InvalidArgument` on every operation (raising the cap later is non-breaking, lowering it is not;
  Q2). Pinned by a vector test (fixed AAD → exact request JSON). Implemented as: a fixed cap of
  3072 AAD bytes (4096 base64url characters) and 4096 bytes of keys and values for native contexts
  (`MAX_AAD_BYTES`, `MAX_CONTEXT_BYTES`); the caps may only rise (A2, PLAN §23 Q7). A0 measured
  the real limit at an 8140-character value (8141 is `ValidationException` "Invalid
  EncryptionContext"), so both caps keep about 2× headroom. Mock tests pin both 3072 (accepted) and 3073 (refused).
  *Superseded by the release plan D1 and R-50:* non-empty AAD is Tink's
  `{"associatedData": lowercase_hex(aad)}` (Java `AwsKmsAead`, Python, C++ and Go's default), so
  ciphertexts with AAD interoperate with Tink; the 3072-byte cap (6144 hex characters, 6158 bytes
  with the key, under the measured 8150) binds `Encrypt`, `GenerateDataKey*` and `ReEncrypt`,
  never `Decrypt`, so raising it never strands a ciphertext.

## 5. Operation mapping

Every request sends only the parameters listed; `GrantTokens` is added when the handle carries
the grant-token extension (§9). `KeyId` is the URI's ARN (key or alias) unless stated.

| anykms op | AWS call, parameters | Response handling, local checks |
|---|---|---|
| `Aead::encrypt` | `Encrypt`: `KeyId`, `Plaintext`, `EncryptionContext` iff aad ≠ ∅ | plaintext 1..=4096 B else `InvalidArgument` before I/O (empty is rejected by AWS: min length 1). Blob → `Ciphertext` unchanged |
| `Aead::decrypt` | `Decrypt`: **`KeyId` always** (Appendix A), `CiphertextBlob`, `EncryptionContext` iff aad ≠ ∅ | blob 1..=6144 B else `DecryptFailed` locally. `Plaintext` decoded into `Zeroizing` |
| `ciphertext_version` / `decrypt_with_info` | — | `None` / `key_version None`, `used_primary None` (Appendix A; Q7) |
| `Rewrap` | `ReEncrypt`: `SourceKeyId` = `DestinationKeyId` = handle key, `Source/DestinationEncryptionContext` = same map | AAD supported (`RewrapWithAad = Yes`). Needs `kms:ReEncryptFrom` + `ReEncryptTo` |
| `DataKeys` | `GenerateDataKey`: `KeyId`, `KeySpec=AES_256`, context iff aad ≠ ∅ | plaintext length == 32 else `Backend`; `DataKeyAad::Bound` |
| wrapped-only data keys (gated, P3) | `GenerateDataKeyWithoutPlaintext`: same params | `Ciphertext` only |
| `DigestSigner::sign_digest` | `Sign`: `KeyId`, `Message`=digest, `MessageType=DIGEST`, `SigningAlgorithm` (§6) | digest alg must match the handle's (before I/O). `Signature{bytes, key_version = response KeyId (key ARN)}` |
| `DigestVerifier::verify_digest` | `Verify`: `KeyId` = **resolved key ARN**, `Message`, `MessageType=DIGEST`, `Signature`, `SigningAlgorithm` | version rules §8. `KMSInvalidSignatureException` → `VerificationFailed`; `SignatureValid=false` (never documented) → `VerificationFailed` |
| `MessageSigner` / `MessageVerifier` (Ed25519) | `Sign` / `Verify` with `SigningAlgorithm=ED25519_SHA_512`, `MessageType=RAW` | message 1..=4096 B else `InvalidArgument` before I/O. Never `DIGEST`, never `ED25519_PH_SHA_512` |
| `Mac::mac` / `verify_mac` | `GenerateMac` / `VerifyMac`: `KeyId`, `Message`, `MacAlgorithm` (+`Mac`) | message 1..=4096 B; tag length == alg output before I/O; `KMSInvalidMacException` → `VerificationFailed`. `Tag.key_version` = response `KeyId` (**verify** it is the key ARN) |
| `PublicKeys::public_key` | `GetPublicKey`: `KeyId` = URI | `PublicKey` = DER SPKI as returned, type from `KeySpec`; `key_version` = response `KeyId`; checks response `KeyUsage`/`KeySpec` match the handle |
| `PublicKeys::public_key_version(v)` | `GetPublicKey`: `KeyId` = `v` only if `v` == the handle's resolved ARN | any other value → `NotFound` with zero requests (Appendix A). Response `KeyId` must equal `v`, else `Backend` |
| `Describe` | `DescribeKey`: `KeyId` = URI | `KeyInfo` + `AwsKeyInfo` (§6); also feeds the key-type check and the resolved-ARN cache |
| `KeyWrap` (symmetric) | via `AeadKeyWrap` (empty AAD → no context) | `Provider::key_wrap = aead(..).map(KeyWrapKey::from_aead)`. Implemented as: a dedicated `AwsKeyWrapKey` (`key_wrap_key`) over `Encrypt`/`Decrypt` with no context (A7) |
| `KeyWrap` (RSA, gated) | wrap: `Encrypt` `EncryptionAlgorithm=RSAES_OAEP_SHA_256`; unwrap: `Decrypt` with `KeyId` + algorithm; rewrap: `ReEncrypt` with both algorithms | opened by `Provider::key_wrap` on RSA `ENCRYPT_DECRYPT` keys as `KeyWrapKey::new(..).with_rewrap().with_describe()`; `wrapped_key_version None`; never `RSAES_OAEP_SHA_1`. Implemented as: wrap is **local** RSAES-OAEP-SHA-256 over the pinned public key (`GetPublicKey`, cached), no `Encrypt` request; unwrap and rewrap as planned (A6, Q12) |

Response decoding: borrowed `&str` from the zeroizing body (transit pattern); unknown response
fields ignored (AWS adds fields such as `KeyMaterialId`), missing required fields → `Backend`.

## 6. Algorithm and key-type mapping; key-type check

| KeySpec | KeyUsage | Opens as | anykms algorithm ↔ AWS |
|---|---|---|---|
| `SYMMETRIC_DEFAULT` | `ENCRYPT_DECRYPT` | `aead`, `key_wrap` | — |
| `ECC_NIST_P256` / `P384` / `P521` | `SIGN_VERIFY` | `digest_signer/verifier`, `public_keys` | `EcdsaP256Sha256`↔`ECDSA_SHA_256`, `EcdsaP384Sha384`↔`ECDSA_SHA_384`, `EcdsaP521Sha512`↔`ECDSA_SHA_512`; `EcP256/384/521` |
| `RSA_2048/3072/4096` | `SIGN_VERIFY` | same | `RsaPss{256,384,512}`↔`RSASSA_PSS_SHA_*` (AWS salt = hash length, matches core), `RsaPkcs1v15*`↔`RSASSA_PKCS1_V1_5_SHA_*`; `Rsa{bits}` |
| `RSA_*` | `ENCRYPT_DECRYPT` | `key_wrap` (gated) | `RSAES_OAEP_SHA_256` |
| `ECC_NIST_EDWARDS25519` | `SIGN_VERIFY` | `message_signer/verifier`, `public_keys` | `Ed25519`↔`ED25519_SHA_512` + `RAW` |
| `HMAC_256/384/512` | `GENERATE_VERIFY_MAC` | `mac` | `HmacSha256/384/512`↔`HMAC_SHA_256/384/512` |
| `HMAC_224`, `ECC_SECG_P256K1`, `SM2`, `ML_DSA_*`, `KEY_AGREEMENT` | — | nothing | `KeyMismatch` at check |

- **Check (§3.3, `KeyTypeCheck::Describe` default):** one cached `DescribeKey` per URI per provider
  before the first operation. The asserted `SignatureAlgorithm`/`MacAlgorithm` must be in the key's
  `SigningAlgorithms`/`MacAlgorithms`, `KeySpec`+`KeyUsage` must match the table; otherwise
  `KeyMismatch`. A digest-signer open of an Ed25519 key is `KeyMismatch` (Ed25519 is message-only).
  Unlike transit, AWS also rejects mismatches server-side (`InvalidKeyUsageException`), so
  `TrustCaller` is safe for type confusion; it only loses the resolved ARN (fetched from the first
  `Sign`/`GenerateMac`/`GetPublicKey` response instead).
- **`KeyInfo`:** `backend_key_type` = KeySpec; capabilities: symmetric `AEAD|REWRAP|DATA_KEYS|KEY_WRAP`,
  signing `SIGN|VERIFY|PUBLIC_KEY`, HMAC `MAC`, RSA-encrypt `KEY_WRAP|PUBLIC_KEY` (only once the
  gated part ships); `signature_algorithms` mapped (unmappable ones dropped, listed verbatim on
  `AwsKeyInfo`); `mac_algorithm`; `state` from `KeyState`: `Enabled`, `Disabled`,
  `PendingDeletion` mapped; `Creating`, `PendingImport`, `PendingReplicaDeletion`, `Unavailable`,
  `Updating` → `Unknown(verbatim)`. `primary_version` / `versions`: asymmetric and HMAC → the key
  ARN (state, `CreationDate`); symmetric → `None` / empty. Implemented as: symmetric keys list the
  key ARN as their one version, with no primary version (A5); RSA KEKs report
  `KEY_WRAP|PUBLIC_KEY|REWRAP` (A8).
- **`AwsKeyInfo`:** ARN, account, region, key id, key spec/usage, all algorithm lists verbatim,
  `origin`, `key_manager`, `multi_region` (+ primary/replica ARNs), `custom_key_store_id`,
  `current_key_material_id`, `deletion_date`, `valid_to`. Implemented without the multi-Region
  primary/replica ARNs (A9; `#[non_exhaustive]`, additive later), with `key_state` and
  `creation_date`.

## 7. Error mapping

AWS JSON 1.1 errors: exception name from `x-amzn-ErrorType` or body `__type` (strip any
`namespace#` prefix and `:…` suffix), message from `message`/`Message`. Every error carries
`BackendDetail { http_status, code = exception name, request_id = x-amzn-RequestId,
server_message }` (message verbatim only for pinned messages, else redacted, §3.6) and
`resource` = the URI. Pinned by mock tests from recorded real responses and by the live suite.
A0 (2026-10-07): every recorded exception is HTTP 400 with the bare type in the body's `__type`
and no `x-amzn-ErrorType` header; `AccessDeniedException` and `SerializationException` use
`Message`; several exceptions carry no message. The 26 recorded error bodies (redacted:
fixture account and key ids) are in `crates/anykms-aws/tests/data/aws-errors-2026-10-07.json`.

| AWS response | ErrorKind | Notes |
|---|---|---|
| `NotFoundException` | NotFound | missing key or alias |
| `InvalidCiphertextException` | DecryptFailed | wrong context, tampered, truncated |
| `IncorrectKeyException` | DecryptFailed | message: "ciphertext is under another key (alias repointed? route old ciphertexts with EnvelopeKeyring)" (Appendix A) |
| `KMSInvalidSignatureException`, `KMSInvalidMacException` | VerificationFailed | |
| `DisabledException`, `KMSInvalidStateException` | KeyStateInvalid | `KMSInvalidStateException` on a custom-key-store key can be a general failure: message kept (redacted), documented |
| `KeyUnavailableException`, `CustomKeyStoreInvalidStateException`, `XksProxy*Exception` (connectivity/timeouts), `CloudHsmClusterNotActiveException` and siblings | Unavailable | key fine, HSM/XKS unreachable (Appendix A). Implemented for the `XksProxy*` exceptions the data plane returns (`XksProxyUriUnreachableException`, `XksProxyInvalidResponseException`); the rest are control-plane only (A10) |
| `InvalidKeyUsageException` | KeyMismatch | only reachable with `TrustCaller` or a key changed after the check |
| `ValidationException`, `ValidationError`, 413 `RequestEntityTooLargeException` | InvalidArgument | local checks run first; reaching this is a bug signal (tracing event) |
| `UnsupportedOperationException` | Unsupported | |
| `InvalidGrantTokenException` | Configuration | grant tokens are deployment config. A0: real AWS accepted an invalid token on an otherwise-allowed call, so this is rarely, if ever, seen |
| `InvalidArnException`, `NotFoundException` with message "Invalid arn …", `UnknownOperationException`, `OptInRequired`, 3xx (never followed) | Configuration | wrong endpoint/partition. A0: real AWS answers a malformed ARN with `NotFoundException` "Invalid arn …" |
| `AccessDeniedException` | PermissionDenied | |
| `UnrecognizedClientException`, `InvalidClientTokenId`, `ExpiredTokenException`, `InvalidSignatureException`, `IncompleteSignature`, `MissingAuthenticationToken`, `NotAuthorized` (401) | Unauthenticated | after the one refresh/skew retry (§4) |
| `ThrottlingException` | Throttled | `Retry-After` parsed if present (KMS documents none; backoff applies) |
| `LimitExceededException` | Backend | resource quota (grants, aliases), not a request rate; not on data-plane error lists |
| `KMSInternalException`, `DependencyTimeoutException`, `InternalFailure`, 500/502/503/504, `ServiceUnavailable`, 408 `RequestTimeoutException`, connection refused/reset, DNS failure, truncated body | Unavailable | |
| client connect/request timeout | Timeout | |
| server or client certificate rejected | Configuration | as transit |
| credential source: nothing found / malformed profile | Configuration | |
| credential source: IMDS/container/STS unreachable or 5xx | Unavailable | |
| credential source: STS `AccessDenied` / `InvalidIdentityToken` / `ExpiredTokenException` | Unauthenticated | |
| anything else | Backend | status + code + redacted message; tracing event |

## 8. KeyVersion semantics

- **Symmetric:** no version exposed (`None` everywhere; `ciphertext_version` → `None`). Automatic
  and on-demand rotation change key material inside the same ARN; ciphertexts keep decrypting.
- **Asymmetric and HMAC:** `KeyVersion` = the resolved **key ARN** from the response `KeyId` of
  `Sign` / `GenerateMac` / `GetPublicKey`. AWS has no rotation for these keys; "rotation" is a new
  key plus repointing an alias, which yields a new version and a new JWKS `kid` (§21).
- **Resolved ARN per handle:** for a key-ARN URI it is the URI's ARN; for an alias URI it is the
  target from `DescribeKey` (or, under `TrustCaller`, the first response `KeyId`). A response whose
  `KeyId` differs (alias repointed while running) replaces it and emits a tracing event; the old ARN
  stops being accepted. Implemented with one more check: for an alias URI the returned ARN must
  be in the alias's partition, region and account, else `Backend`.
- **`public_key_version(v)`:** only `v` == resolved ARN is served; any other value → `NotFound`
  before I/O (Appendix A: a `kid` must never select a key). Old keys are verified by configuring
  them as their own URIs and routing by `kid` (documented with a `CachedVerifier` example).
- **Verify / verify_mac input versions:** `None` → `InvalidArgument` (matches transit and the
  existing conformance cases); a value that is not a well-formed KMS key ARN → `InvalidArgument`;
  a well-formed ARN other than the resolved one → `VerificationFailed` before I/O (attacker-supplied
  input is a caller error, not `NotFound`'s config class; Q5). Verify always sends the resolved
  ARN as `KeyId`, never the input's version.
  Implemented as: `None` verifies with the handle's key (A1: an ARN names exactly one key, so
  absence selects nothing; the suite's `Unversioned::UsesCurrent`), a malformed version is
  `InvalidArgument`, and a well-formed ARN other than the resolved one is **`NotFound`** before
  any I/O (A3), the same as `public_key_version` (PLAN §23 Q12). Verify still always sends the
  resolved ARN.

## 9. Extension: native encryption context and grant tokens

- **Native context maps** (interop with ciphertexts from other AWS tools; Appendix A, §19). An
  extension trait implemented by `AwsAeadKey` and reachable from the opaque `AeadKey` through the
  **layered** extension mechanism (P2), so `RetryLayer` and later metrics layers apply:

  ```rust
  pub trait EncryptionContextAead {          // anykms-aws
      async fn encrypt_with_context(&self, pt: &[u8], ctx: &EncryptionContext) -> Result<Ciphertext>;
      async fn decrypt_with_context(&self, ct: &Ciphertext, ctx: &EncryptionContext) -> Result<Zeroizing<Vec<u8>>>;
      async fn rewrap_with_context(&self, ct: &Ciphertext, from: &EncryptionContext, to: &EncryptionContext) -> Result<Ciphertext>;
      async fn generate_data_key_with_context(&self, spec: DataKeySpec, ctx: &EncryptionContext) -> Result<DataKey>;
  }
  ```

  `EncryptionContext` is an ordered `BTreeMap<String, String>` newtype; it may not contain the
  reserved AAD key (`associatedData`, release plan D1; it was `anykms-aad`) (`InvalidArgument`),
  so the two modes never mix; same size check.
  Operations reuse existing `Operation` values. Raw `downcast_ref::<AwsAeadKey>()` still works but
  rustdoc steers to the layered path.
- **Grant tokens:** `OpenOptions::with_extension(GrantTokens::new([..])?)` (≤ 10 tokens, each
  1..=8192 chars, `SecretString`, never logged); copied into every request of that handle. No
  layered path needed (open-time config).

## 10. Observability and secret hygiene

- **Span per operation** (`tracing` feature), allowlisted fields: `op`, `backend`, `region`,
  `account`, `key` (key id or alias name), `key_version`, `outcome`, `error_kind`, `http_status`,
  an AWS-specific error-code field, `request_id` (on success too), `attempt` (auth retry),
  `latency`. Implemented as the shared schema (D3, shared.md §5): `anykms.aws` spans with `backend`, `op`,
  `resource` (the key URI, which carries region, account and key), `key_version`, `attempt`,
  `http_status`, `code` (the exception name), `request_id`, `latency_ms`, `error_kind`,
  `outcome`; credential fetches are `anykms.aws.token` spans (`backend`, `credential`,
  `outcome`, `error_kind`, `latency_ms`, `expires_in_s`). The hygiene test pins the field names.
- **Events:** credential source chosen/refreshed (kind + expiry, never values), auth-refresh retry,
  clock-skew correction, resolved ARN changed, fallback to `Backend`, AWS rejected an input a local
  check should have caught, TLS provider chosen.
- **Never logged or in errors:** plaintext, AAD and its encoding, encryption-context values,
  ciphertext blobs, data keys, messages/digests, grant tokens, access keys, session tokens, web
  identity tokens, `Authorization` / `X-Amz-Security-Token` headers, SigV4 signatures, request
  bodies. reqwest errors attached only URL-stripped.
- **Zeroization:** request JSON built in a pre-sized zeroizing buffer; response read into one;
  `Plaintext` decoded into `Zeroizing`; data keys boxed; SigV4 derived signing keys and secret keys
  in `Zeroizing`/`SecretString`. Same stated limits as transit (reqwest/hyper/rustls copies, the
  process environment, credential files' page cache).
- **Hygiene test:** markers for plaintext, AAD, context value, data key, access key, session token,
  grant token; capture TRACE incl. reqwest/hyper; walk `Display`/`{:#?}`/`source()`.

## 11. Testing

- **Unit:** SigV4 against the AWS SigV4 test-suite vectors (Apache-2.0, vendored under
  `tests/data/`) plus a recorded KMS request; ARN/URI grammar; endpoint derivation per partition;
  AAD wire vectors; keyinfo mapping; error-body parsing; profile INI parsing.
- **Mock (wiremock), server-free CI:** one test per §7 row from recorded bodies; request-shape
  assertions (exact parameter sets of §5: `KeyId` always on `Decrypt`/`ReEncrypt`, no
  `EncryptionContext` for empty AAD, `MessageType` values, no unknown fields); 307 never followed
  and never receives credentials; truncated/malformed JSON; slow server → `Timeout`; expired token
  → one refresh retry, then `Unauthenticated`; skew → one corrected retry; resolved-ARN change;
  every credential source (IMDSv2 token flow, container auth token file, STS web identity) incl.
  the container-host allowlist.
- **Conformance fixture (`AwsFixture`)**, one implementation, two targets:
  - *Emulator* (`conformance_localstack.rs`): endpoint from compose, admin through the crate's
    hidden admin call (`CreateKey`, `DisableKey`, `ScheduleKeyDeletion`, `RotateKeyOnDemand`,
    `Encrypt` without context for native ciphertexts).
  - *Live* (`conformance_live.rs`, gated on `ANYKMS_AWS_LIVE=1`): long-lived pooled keys tagged
    `anykms-conformance` (created by `scripts/aws/` CloudFormation, one per kind and algorithm);
    throwaway keys only for disable/deletion cases, scheduled for deletion (7 days) on teardown.
  - Declarations: `Aead`, `Rewrap`, `DataKeys`, `Mac`, `Describe`, `KeyWrap` (RSA, when shipped)
    yes; `Signing(alg)` for all ten algorithms; `RewrapWithAad` yes; `datakey_aad = Bound`;
    `ciphertext_versions = false`; `hmac_versions_listed = true`; `OversizePlaintext(4097)`;
    `NativeCiphertext` yes; `RequestCount` yes (counting provider as in transit); `Disable` yes;
    `Rotate` yes for AEAD only, n/a for signing/HMAC; `MinDecryptionVersion`, `Throttle` n/a;
    `UnauthorizedProvider` yes on live (a role with no key permissions), fixture-lacks on the
    emulator (IAM enforcement); `EmptyPlaintext` / `EmptyMessage` n/a (new features, §13);
    Ed25519 on the emulator only if A0 confirms real Ed25519 keys there.
- **New AWS cases** (in the suite where they generalize, else in `integration.rs`): 4 KiB + 1
  message for `Mac` and `MessageSigner` (Appendix A); `Decrypt` of another key's ciphertext through
  an alias repoint → `DecryptFailed` with the hint; `public_key_version(other ARN)` → `NotFound`
  with zero requests; AAD size limit → `InvalidArgument` with zero requests; native context round
  trip and interop with a plain `Encrypt` made by the fixture with the same map.
- **CI:** compose service `localstack` (profile `aws`, image pinned by tag and digest, port
  `127.0.0.1:4566`); job runs on pushes and same-repo PRs (needs `LOCALSTACK_AUTH_TOKEN`, Q3); fork
  PRs show the job as skipped with a notice. Live suite: nightly + manual `workflow_dispatch`,
  GitHub OIDC → a dedicated test-account role (`id-token: write`, never on fork PRs), region pinned.
  Exit criteria: emulator green with only *n/a* and documented *fixture lacks*; live green with only
  *n/a*. `scripts/probe-aws.sh` (from A0) re-records error bodies and behaviors for the research doc.
- **Implemented as:** the emulator target is `conformance_emulator.rs` (plus `emulator.rs`
  end-to-end tests) over the shared `tests/e2e/` fixture. CI job `aws-emulator` runs it against
  **Floci** on every PR (MIT, no token); `aws-localstack` runs the same against LocalStack only
  when `LOCALSTACK_AUTH_TOKEN` is set; `aws-live` is the nightly OIDC job. The fixture keeps one
  HMAC key per algorithm (`TestKeyKind::Hmac(alg)`), as GCP's does. `RequestCount` counts through
  the hidden `AwsProviderBuilder::__count_requests`. Floci's deviations are listed in
  `docs/research/aws-kms.md`. A0 ran on 2026-10-07; the live suite then passed on real AWS (340
  cases, 0 failed, 108 *n/a*).
- **Fuzz** (nightly matrix): `aws_uri` (ARN grammar), `aws_error` (error-body/`__type` parsing),
  `aws_success` (success-body decoding via a hidden hook, seeds from recordings), `aws_profile`
  (INI + `credential_process` JSON), `aws_credentials_json` (IMDS/container), `aws_sts` (STS
  response), `aws_context` (AAD encode/decode round trip).

## 12. Operator docs (shipped, `crates/anykms-aws/README.md` + `docs/operations.md` section)

Implemented as: [`docs/operations-aws.md`](../operations-aws.md) (D5), with an "Environment"
section, and `crates/anykms-aws/README.md`; `docs/operations.md` stays transit's and points to it.

- **Key policy snippets** per handle kind (AWS recommends key policies over IAM `Resource: "*"`):
  AEAD `kms:Encrypt`, `kms:Decrypt`, `kms:ReEncryptFrom`, `kms:ReEncryptTo`,
  `kms:GenerateDataKey` (+`WithoutPlaintext` when used), `kms:DescribeKey`; decrypt-only services
  drop the write actions; signing `kms:Sign`, `kms:Verify`, `kms:GetPublicKey`, `kms:DescribeKey`;
  verify-only `kms:Verify`/`kms:GetPublicKey`; MAC `kms:GenerateMac`, `kms:VerifyMac`,
  `kms:DescribeKey`. Never `kms:*`, `CreateKey`, `PutKeyPolicy`, `ScheduleKeyDeletion`,
  `CreateGrant` for applications. Optional hardening: `ForAllValues:StringEquals
  kms:EncryptionContextKeys ["associatedData"]` on keys used only through the portable API (and
  Tink); dedicated
  KEK keys for envelopes (§5.1 "KEK MUST be dedicated").
- **`kms:DescribeKey`** is needed for the key-type check; `TrustCaller` opt-out documented (§6).
- **CloudTrail:** the encryption context — hence the hex of the AAD — is logged in plaintext;
  AAD must not be secret (§19). Hex is an encoding, not protection.
- **Limits:** `Encrypt` ≤ 4096 B plaintext (bulk data → `EnvelopeAead`), no empty plaintext;
  `Sign` RAW / `GenerateMac` ≤ 4096 B and non-empty (→ `sign_message_hashed` / hash first);
  AAD encoded-size cap (§4). Shared request quotas (symmetric incl. HMAC 10k–100k rps per region;
  RSA, ECC 1k rps) and the shared `RetryBudget` guidance.
- **Aliases and rotation:** alias URIs follow repoints; old symmetric ciphertexts then fail with
  `IncorrectKeyException` (`DecryptFailed` + hint) → `EnvelopeKeyring` with the old key as its own
  URI; signing keys: configure old keys by ARN, route by `kid`. Multi-region keys: one replica ARN
  per region, shared logical `kek_id` (Appendix A).
- **Custom key stores / XKS:** `Unavailable` when disconnected; their own 1,800 rps quota.
- **Credentials:** supported sources and order; IRSA / Pod Identity / ECS / IMDSv2 notes; FIPS and
  dual-stack endpoints; VPC endpoints via `.endpoint`; account/region allowlists.
- **Runbook:** each `ErrorKind` with the AWS exceptions behind it and the operator action.

## 13. Dependencies on shared prerequisites (precise asks)

- **P1 conformance capability redesign (§22).** AWS needs, beyond the §22 design: (a)
  `FixtureCaps::max_plaintext` (AWS 4096) clamping `aead::roundtrip`'s 64 KiB size, and
  `Feature::EmptyPlaintext` gating its empty case (AWS `Encrypt`/`GenerateMac`/`Sign` reject empty
  input); `Feature::EmptyMessage` likewise for `Mac`/`MessageSigner` if any case uses empty input;
  (b) `FixtureCaps::max_message` + the 4 KiB + 1 cases; (c) per-kind rotation (`Rotate` covers AEAD
  only on AWS; signing/HMAC rotation n/a), e.g. `Feature::RotateSigning` / `RotateMac`; (d) the
  "non-numeric version" probes in `sign`/`mac` cases come from the fixture
  (`Fixture::malformed_version()`), plus a `foreign_version` expectation (`VerificationFailed` on
  AWS); (e) `TestKeyKind::KeyWrap` for RSA-OAEP keys; (f) `describe::aead_key`'s `KEY_WRAP` check
  passing for an AEAD key whose `key_wrap` is `from_aead`.
- **P2 layered extension handles (M5 4.3).** A way to reach a backend extension trait object
  (`dyn EncryptionContextAead`) from `AeadKey` such that applied layers wrap its futures (retry,
  observe, metrics) and the handle's resource label/backend name apply. AWS provides the trait and
  its impl; it needs no new `Operation` values.
- **P3 new handle parts.** Wrapped-only data keys: a core trait (`generate_wrapped_data_key(spec,
  aad) -> Ciphertext`), an optional `AeadKey` part with `with_*`/`supports_*`, a `Layer` method
  with default, `RetryLayer` + observe overrides, a conformance family. Native RSA `KeyWrap` needs
  **no** new part (`KeyWrapKey::new` + `with_rewrap` + `with_describe` exist); it needs only
  `TestKeyKind::KeyWrap` (P1e).
- Nothing else in core changes: `Unauthenticated`, `KeyMismatch`, `BackendDetail::{code,
  request_id}`, `OpenOptions` extensions, `with_concrete`, retry hints all exist.

## 14. Task breakdown

Sizes: S ≤ ½ day, M 1–2 days, L 3–5 days.

| # | Task | Size | Depends on |
|---|---|---|---|
| A0 | **Done 2026-10-07.** Live probe in a test account: encryption-context size limit, `GenerateMac`/`Sign`/`GetPublicKey` `KeyId` format via alias, every §7 exception body + headers, `Retry-After` presence, Ed25519 RAW limits; emulator fidelity (LocalStack, Floci) incl. real Ed25519 keys. Record in `docs/research/aws-kms.md` | M | test account (Q11) |
| A1 | Crate scaffold, features, URI/ARN parser + endpoint derivation + fuzz target | S | — |
| A2 | SigV4 signer + vectors | M | — |
| A3 | HTTP client (JSON 1.1, TLS provider selection, no redirects, zbuf, request ids, skew) | M | A2 |
| A4 | Credentials core: trait, cache/single-flight refresh, env, profile files, `credential_process` | M | A3 |
| A5 | Credentials: IMDSv2, container, STS web identity + mocks | L | A4 |
| A6 | Provider/config/`from_env`/allowlists/describe cache | M | A1, A3 |
| A7 | Error mapping + recorded-body mock tests | M | A0, A3 |
| A8 | AEAD handle: AAD encoding + vectors, encrypt/decrypt/rewrap/data keys, key-type check, keyinfo | M | A6, A7 |
| A9 | Signing (digest, Ed25519) and MAC handles, version contract §8 | M | A8 |
| A10 | Tracing spans/events, hygiene test | S | A9 |
| A11 | Facade integration (`aws` feature, default providers, docs build matrix) | S | A6 |
| A12 | Conformance fixture, emulator + live targets, pooled-key CloudFormation | M | **P1**, A9 |
| A13 | CI: compose `localstack` service, emulator job, live nightly with OIDC, MSRV/no-default checks, semver | M | A12, Q3 |
| A14 | Native encryption-context extension + grant tokens | M | **P2**, A8 |
| A15 | Wrapped-only data keys | S | **P3**, A8 |
| A16 | RSA-OAEP native `KeyWrap` | M | P1e, A8 |
| A17 | Remaining fuzz targets (A1 has `aws_uri`) | S | A5, A7 |
| A18 | Operator docs, README, runbook, PLAN Appendix A/§10 updates | M | A9, A0 |

Critical path: A2 → A3 → A6 → A8 → A9 → A12 → A13 (~3 weeks for one engineer, A5 in parallel).
A14–A16 can trail; the crate is publishable without them (additive parts) once P1 has landed and
`anykms-conformance` is published (§22).

## 15. Risks and open questions (maintainer decisions)

How they were answered (PLAN §23 and the cloud README §5): Q1 `anykms-aad` (§23 Q7;
*superseded by the release plan D1: Tink's `associatedData`, lowercase hex*); Q2 a fixed
cap of 3072 AAD bytes that may only rise (A2); Q3 LocalStack with a token, Floci on every PR
(§23 Q6); Q4 allowlists optional (§23 Q8); Q5 `NotFound` (A3, §23 Q12); Q6 no backend retry
(A4, §23 Q14); Q7 `KeyMaterialId` not used (§23 Q14); Q8 not built; Q9 ARN-only; Q10
`anykms-http` (§23 Q4); Q12 local OAEP wrap (A6); Q11 open (live account, a release gate).

- **Q1 Reserved context key name** (wire format forever). Proposal: `anykms-aad` (ASCII, no
  `aws` prefix, valid in `kms:EncryptionContext:` condition keys). Decide before A8.
  *Superseded by the release plan D1: Tink's `associatedData` with lowercase hex values meets
  the same constraints and interoperates with Tink.*
- **Q2 Encryption-context size cap.** AWS documents none; A0 measures. Proposal: cap at
  min(measured, 8192 encoded chars); confirm the cap may only ever rise. Answered: fixed caps
  (A2); A0 measured 8140 characters for one value, so the caps stay with about 2× headroom.
- **Q3 Emulator.** LocalStack's image has required `LOCALSTACK_AUTH_TOKEN` since 2026-03-23 (free
  Hobby/OSS tiers, unlimited CI) and fork PRs cannot see the secret. Recommendation: LocalStack with
  a project token for same-repo CI; Floci (MIT, no token, young) as the fallback if A0 shows equal
  fidelity; reject pinning the last community image (no security patches) and moto (no `DIGEST`
  verify). Error-mapping truth comes from the live suite and recorded mocks either way.
- **Q4 Account allowlist default.** Opt-in (proposed, documented risk) vs required
  (`allowed_accounts` or `.allow_any_account()`), which blocks a URI from routing plaintext to
  someone else's key.
- **Q5 Foreign-ARN version on verify:** `VerificationFailed` (proposed, caller-error class) vs
  `NotFound` (matches `public_key_version`).
- **Q6 Clock-skew retry** as a second once-only authentication exception to "no retries in
  backends" (the SDK does the same); the alternative is `Unauthenticated` with a "check the clock"
  message.
- **Q7 Symmetric `KeyMaterialId`.** `Decrypt`/`ReEncrypt` return a 64-hex `KeyMaterialId` and
  `DescribeKey` a `CurrentKeyMaterialId`: a real staleness signal for `decrypt_with_info`
  (`used_primary`) and possibly `key_version`. Appendix A says `None`; proposal: keep `None` in the
  first release, revisit `used_primary` additively.
- **Q8 `sdk-credentials` bridge** (higher MSRV, off by default) for SSO/role chaining: ship or not.
  (Answered 2026-10-12: shipped, [credentials-plan.md](credentials-plan.md).)
- **Q9 ARN-only URIs** (proposed) vs also accepting `key/<id>` / `alias/<name>` with a configured
  default region and account.
- **Q10 Shared HTTP plumbing.** Duplicate transit's `zbuf`, TLS-provider and redaction helpers now
  (proposed) and extract a `#[doc(hidden)]` shared crate when GCP/Azure arrive, vs extract now.
- **Q11 Live-test account:** ownership, budget (pooled keys at the KMS per-key monthly price, plus
  requests), OIDC role trust policy scoped to this repository's `main` and schedule.
- **Q12 RSA-OAEP wrap:** server-side `Encrypt` (proposed: no new crypto, CloudTrail-visible) vs
  local OAEP with the cached public key (aws-lc-rs, no request, no quota).
- **Risk: SigV4/credential code is security-critical and new.** Mitigations: official vectors,
  fuzzing, mocks for every source, the live suite, and the security review at release (M4 pattern).
- **Risk: emulator drift** hides real behavior. Mitigation: emulator only proves wiring; error and
  limit semantics are pinned from live recordings.
- **Risk: AWS adds key specs/algorithms or response fields.** Unknown fields ignored; unknown
  KeySpec → `KeyMismatch` with the verbatim spec in `AwsKeyInfo`; `probe-aws.sh` rerun on AWS API
  changelog entries for KMS.

## Sources

- AWS KMS API reference: [Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html),
  [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
  [ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html),
  [Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html),
  [Verify](https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html),
  [GenerateMac](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html),
  [VerifyMac](https://docs.aws.amazon.com/kms/latest/APIReference/API_VerifyMac.html),
  [GetPublicKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html),
  [KeyMetadata](https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html),
  [Common errors](https://docs.aws.amazon.com/kms/latest/APIReference/CommonErrors.html)
- KMS developer guide: [Encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html),
  [Request quotas](https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html),
  [Throttling](https://docs.aws.amazon.com/kms/latest/developerguide/throttling.html),
  [Endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/kms.html),
  [EdDSA announcement (2025-11-07)](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/)
- crates.io API (`/api/v1/crates/<name>/versions`) for `aws-sdk-kms`, `aws-config`, `aws-sigv4`,
  `aws-smithy-runtime`, `aws-smithy-http-client` (versions, `rust_version`, features), queried 2026-10-05;
  [MSRV bump forced by RUSTSEC-2026-0253](https://github.com/nao1215/truss/pull/574)
- Emulators: [LocalStack KMS](https://docs.localstack.cloud/aws/services/kms/),
  [LocalStack pricing/packaging change](https://blog.localstack.cloud/2026-upcoming-pricing-changes/),
  [auth token since 2026-03-23](https://github.com/testcontainers/testcontainers-rs-modules-community/issues/465),
  [moto KMS](https://docs.getmoto.org/en/latest/docs/services/kms.html),
  [Floci KMS](https://github.com/floci-io/floci/blob/main/docs/services/kms.md),
  [Floci Ed25519 fix](https://github.com/floci-io/floci/pull/2930)
