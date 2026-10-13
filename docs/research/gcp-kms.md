# Google Cloud KMS: facts anykms-gcp depends on

**Probe status.** Script: `scripts/probe-gcp.sh record` (task T1). Last run: 2026-10-12
(baseline `scripts/probe-baseline/gcp/gcp-2026-10.txt`, global location, SOFTWARE keys). Open
rows: 6 (§2.2).

Sources are those of `docs/cloud/gcp.md` ([S1]…[S22]). §2.1 records what the probe settled;
the rows still open keep the conservative assumption built into `anykms-gcp`, its mock tests
and its fake server (`crates/anykms-gcp/tests/common/fake.rs`).

## 1. API surface (REST v1, documented)

| Fact | Source | Used for |
|---|---|---|
| Data-plane calls: `cryptoKeys.encrypt`/`decrypt` (key name), `cryptoKeyVersions.asymmetricSign`/`asymmetricDecrypt`/`macSign`/`macVerify`/`getPublicKey` (version name); metadata: `cryptoKeys.get`, `cryptoKeyVersions.get`/`list` | [S3]–[S5], [S16] | `src/handles.rs` |
| Bytes are standard base64; `Int64Value` CRC32C fields are JSON strings (proto3 JSON); booleans and empty bytes are omitted when false/empty | proto3 JSON mapping | `src/wire.rs` accepts strings or numbers and treats an absent CRC as 0 |
| Request CRC fields: `plaintextCrc32c`, `additionalAuthenticatedDataCrc32c`, `ciphertextCrc32c`, `digestCrc32c`, `dataCrc32c`, `macCrc32c`; response: `ciphertextCrc32c`, `plaintextCrc32c`, `signatureCrc32c`, `macCrc32c`, `pemCrc32c`, flags `verified*Crc32c`, `verifiedSuccessIntegrity` | [S5], [S6] | checked on every call; failures are `Unavailable` |
| Responses name the version used (`name`); clients should check it | [S6] | name mismatch → `Backend` |
| `DecryptResponse.usedPrimary` | [S4] | `decrypt_with_info` |
| Ciphertexts are opaque; their format is undocumented | [S1] | `ciphertext_version` → `None` |
| Asymmetric and MAC keys have no primary version; AEAD keys do | [S2] | version rules at open |
| `EC_SIGN_ED25519` is software-only and signs `data`; Cloud EKM signing requires `data` | [S2], [S8] | EKM signing refused |
| RSA-PSS salt length = digest length | [S8] | `LocalVerifier` enforces it |
| Size limits: plaintext 64 KiB, AAD 64 KiB (HSM: 8 KiB combined); MAC data 64 KiB (HSM 16 KiB) | [S3], [S15] | local 64 KiB checks |
| Regional endpoints `cloudkms.<location>.rep.googleapis.com` | [S9] | `Endpoint::Regional` |
| Disable propagation "usually within a minute" | [S20] | public-key cache TTL 60 s, fixture settle time 150 s |
| 429 `RESOURCE_EXHAUSTED`; quotas enforced per second | [S19] | `Throttled` |
| A missing key is 404 only with permission on the parent; otherwise 403 "(or it may not exist)" | [S18] | docs, fixture IAM on the key ring |
| Version states `ENABLED`, `DISABLED`, `DESTROY_SCHEDULED`, `DESTROYED`, `PENDING_GENERATION`, `PENDING_IMPORT`, `IMPORT_FAILED`, `GENERATION_FAILED`, `PENDING_EXTERNAL_DESTRUCTION`, `EXTERNAL_DESTRUCTION_FAILED` | [S16] | `KeyState` mapping |

## 2. Probe results (T1)

### 2.1 Settled on 2026-10-12

| Question | Live behavior | Effect on anykms-gcp |
|---|---|---|
| Encrypt with an empty plaintext | accepted (200); decrypt returns it with `plaintext` omitted (proto3) | `EmptyPlaintext` declared supported (fake and live fixtures) |
| Ed25519 with an empty message | refused: `INVALID_ARGUMENT` "For algorithm EC_SIGN_ED25519 and protection level SOFTWARE, data must be set." | `EmptyMessage` declared not applicable; the fake refuses it too |
| MAC with empty input | `macSign` accepts it; `macVerify` refuses it: `INVALID_ARGUMENT` "Request field data is required." (`MISSING_REQUIRED_FIELD`) | same; an empty-input tag cannot be verified (`InvalidArgument`) |
| Size limits | plaintext, AAD, Ed25519 `data` and MAC `data`: 65 536 bytes accepted, 65 537 refused (`INVALID_ARGUMENT`, reason `INVALID_REQUEST_FIELD_SIZE`) | the local 64 KiB checks match; `max_signed_message` 64 KiB for Ed25519 |
| Checksum mismatch | `INVALID_ARGUMENT` "The checksum in field <x>_crc32c did not match the data in field <x>." (reason `INVALID_CHECKSUM`) | matched by "checksum" → `Unavailable` |
| Decrypt failure | `INVALID_ARGUMENT` "Decryption failed." (wrong AAD) and "Decryption failed: the ciphertext is invalid." (garbage) | `DecryptFailed`; "Decryption failed" pinned |
| Purpose mismatch (encrypt/decrypt/sign/macSign/getPublicKey on the wrong purpose) | `FAILED_PRECONDITION` "… has incorrect key purpose: <P>[, expected key purpose is: <Q>]" (violation `CRYPTO_SCHEME_MISMATCH`) | `KeyMismatch` |
| Digest of the wrong algorithm | `INVALID_ARGUMENT` "The digest SHA384 is not valid for CryptoKeys with algorithm EC_SIGN_P256_SHA256." | `InvalidArgument` |
| `data` instead of `digest` on a P-256 SOFTWARE key | accepted (200) | not used (anykms sends digests) |
| Disabled version: encrypt, decrypt, sign, `getPublicKey` | `FAILED_PRECONDITION` "<version> is not enabled, current state is: DISABLED." (violation `KEY_DISABLED`) | version-state mapping; `getPublicKey` refuses a disabled version too, the state lookup before it is kept (§3.1(f)) |
| Missing key | 404 "CryptoKey <name> not found." on key-level calls and on `…/publicKey`; **404 "CryptoKeyVersion <name> not found." on a version GET of a missing key** | an input version's 404 is followed by one `cryptoKeys.get` (skipped when a public key of the key is cached), so a missing key stays `NotFound` |
| Missing version | 404 "CryptoKeyVersion <name> not found." | `UnknownKeyVersion` (input) / `NotFound` |
| Missing project | 404 "Project '<name>' not found." | `NotFound` |
| Bad token | 401 `UNAUTHENTICATED` "Request had invalid authentication credentials. …" (reason `ACCESS_TOKEN_TYPE_UNSUPPORTED` for a malformed token) | `Unauthenticated` |
| Missing permission | 403 `PERMISSION_DENIED` "Permission '<p>' denied on resource '<name>' (or it may not exist)." (reason `IAM_PERMISSION_DENIED`) | `PermissionDenied` |
| `macVerify` with a wrong tag | 200 with `success` omitted (proto3 false) | `success` defaults to false → `VerificationFailed` |
| `getPublicKey` path | `GET …/cryptoKeyVersions/<n>/publicKey`; `…:getPublicKey` is refused (400, resource-name pattern) | fixed in the client, mock and fake (the probe found it) |
| Self-signed JWTs (`scope` claim, no `aud`) from a service-account key | accepted by Cloud KMS: the live conformance run authenticated this way | none |
| Disable propagation | the next encrypt was refused at once (first 15 s bucket) | settle time 150 s is generous; kept for other locations |

### 2.2 Still open

| Question | Assumption in anykms-gcp | How to settle |
|---|---|---|
| `RequestInfo` in error details; `Retry-After` or `RetryInfo` on 429 | optional; both parsed when present (none seen on the 4xx probes) | a throttled run |
| API disabled / billing disabled | 403 with `ErrorInfo.reason` `SERVICE_DISABLED`/`BILLING_DISABLED` → `Configuration` | manual, on a project without the API |
| Cloud EKM and Key Access Justifications failures | unpinned `FAILED_PRECONDITION` → `Backend` | needs an EKM setup |
| HSM limits (8 KiB plaintext+AAD, 16 KiB MAC) | documented values; the probe ran on SOFTWARE keys | a probe run with `ANYKMS_GCP_HSM` keys |
| Regional STS endpoints | accepted as an `external_account` `token_url` (documented) | a live run with a regional workload identity pool config |
| Metadata-server token refresh lead (4 min) | documented behavior | a run on GCE/GKE |

## 3. Credentials (documented)

| Fact | Source |
|---|---|
| ADC order: `GOOGLE_APPLICATION_CREDENTIALS`, the gcloud file, the metadata server | [S14] |
| Metadata server: `GET /computeMetadata/v1/instance/service-accounts/default/token`, header `Metadata-Flavor: Google` in both directions; `GCE_METADATA_HOST` overrides the host | [S14] |
| `authorized_user`: refresh-token grant at `https://oauth2.googleapis.com/token` | [S14] |
| `external_account`: RFC 8693 token exchange at `https://sts.googleapis.com/v1/token` (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `requested_token_type=…:access_token`, `scope`, `audience`, `subject_token`, `subject_token_type`), workforce pools add `options={"userProject":…}`; then optionally `generateAccessToken` at the `service_account_impersonation_url` (`lifetime`, default 3600 s) | [S14] |
| `impersonated_service_account`: `source_credentials` plus `generateAccessToken` with `delegates` | [S14] |
| `google-github-actions/auth` writes an `external_account` file with a `url` credential source (the GitHub OIDC endpoint, `Authorization` header, JSON format with field `value`) | action docs |
