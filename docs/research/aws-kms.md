# AWS KMS: documented and observed behavior

**Probe status:** script `scripts/probe-aws.sh` (A0); last run against real AWS: **2026-10-07**
(us-east-1); open rows: 2 (`Retry-After` on throttling, China dual-stack host). The operator
guide is [`../operations-aws.md`](../operations-aws.md).

Status: started 2026-10-06 with the documented facts and an emulator run. **The live probe (A0)
ran on 2026-10-07** against real AWS KMS in us-east-1 (`scripts/probe-aws.sh`); rows marked
*verified live 2026-10-07* cite the probe's response file (`<name>.json`). The raw responses
name a test account and its keys, so they are not committed; every error response is kept,
with the account and key ids rewritten to the mock fixtures and the request ids replaced, in
`crates/anykms-aws/tests/data/aws-errors-2026-10-07.json`, which the mock test
`recorded_aws_error_responses` replays. The live conformance suite then passed on real AWS:
340 cases, 0 failed, 108 *n/a*. Where a value is still unknown, the backend takes the
conservative choice listed here; raising a limit later is non-breaking, lowering it is not.

Findings that changed the backend (2026-10-07): a malformed key ARN is `NotFoundException`
"Invalid arn ..." (not `InvalidArnException`), now `Configuration` by message; AWS appends the
expected canonical request to the `InvalidSignatureException` text, so only its first paragraph
is kept verbatim; the fixed texts recorded below are pinned as known server messages. Findings
that changed the documentation: an invalid grant token is accepted (§3), and `GetPublicKey`
succeeds on a disabled key.

Sources: the AWS KMS API reference (Encrypt, Decrypt, ReEncrypt, GenerateDataKey,
GenerateDataKeyWithoutPlaintext, Sign, Verify, GenerateMac, VerifyMac, GetPublicKey,
DescribeKey, KeyMetadata, Common Errors), the KMS developer guide (encryption context, request
quotas, throttling, key states, rotation), the SigV4 documentation and test suite, and the AWS
SDKs' credential-provider documentation (IMDSv2, container credentials, web identity). See the
source list of `docs/cloud/aws.md`.

## 1. Protocol

| Fact | Value | Source | anykms |
|---|---|---|---|
| Protocol | AWS JSON 1.1: `POST /`, `Content-Type: application/x-amz-json-1.1`, `X-Amz-Target: TrentService.<Operation>` | API reference | `client.rs` |
| Signing | SigV4 (`AWS4-HMAC-SHA256`), service `kms`, region = the key ARN's region | SigV4 docs | signed headers `content-type;host;x-amz-date;x-amz-target[;x-amz-security-token]`; verified with the AWS SigV4 test suite |
| Blobs | standard base64 in JSON | API reference | |
| Timestamps (`CreationDate`, `DeletionDate`, `ValidTo`) | seconds since the epoch, a JSON number (may be fractional) | API reference; **verified live 2026-10-07**: fractional (`1791335395.506`, `describe-symmetric.json`, `schedule-deletion-sym2.json`); Floci sends integers | parsed as a number, truncated |
| Request id | `x-amzn-RequestId` response header (sent as `x-amzn-requestid`), a UUID, on every response | Common errors; **verified live 2026-10-07** (every probe file) | `BackendDetail::request_id` |
| Error shape | HTTP **400 for every exception recorded**, authentication and not-found included; body `{"__type": "<Exception>", "message": "..."}` with a bare type (no `namespace#` prefix); `AccessDeniedException` and `SerializationException` use **`Message`**; `InvalidCiphertextException`, `KMSInvalidSignatureException`, `KMSInvalidMacException`, `UnknownOperationException` and `UnsupportedOperationException` have **no message**; **no `x-amzn-ErrorType` header** and no `Retry-After` on any of the 26 error responses | **verified live 2026-10-07** (`access-denied.json`, `malformed-json.json`, `decrypt-tampered.json`, `verify-bad-signature.json` and the other error files) | both message fields read; header, prefix and suffix still handled for other servers |
| Unknown response fields | AWS adds fields over time (`KeyMaterialId`, `KeyAgreementAlgorithms`, ...) | API changelog | ignored |
| Redirects | not used by KMS | — | never followed; a 3xx is `Configuration` |

## 2. Limits

| Limit | Documented | anykms (before I/O) | Status |
|---|---|---|---|
| `Encrypt` plaintext | 1 to 4096 bytes | `InvalidArgument` outside | **verified live 2026-10-07**: empty and 4097 bytes are `ValidationException` "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: ..." (`encrypt-empty.json`, `encrypt-4097.json`); Floci agrees |
| `CiphertextBlob` | 1 to 6144 bytes | `DecryptFailed` outside | documented |
| `Sign` with `MessageType=RAW` | message ≤ 4096 bytes, min 1 | `InvalidArgument` outside 1..=4096 | **verified live 2026-10-07** on Ed25519 (`ED25519_SHA_512`): 4096 bytes signed (`sign-ed25519-raw-4096.json`); empty and 4097 are `ValidationException` "Value at 'message' ..." (`sign-ed25519-raw-empty.json`, `sign-ed25519-raw-4097.json`) |
| `GenerateMac` / `VerifyMac` message | 1 to 4096 bytes | `InvalidArgument` outside | **verified live 2026-10-07** for `GenerateMac`: empty and 4097 are `ValidationException` (`generate-mac-empty.json`, `generate-mac-4097.json`); Floci agrees |
| Encryption context size | **not documented** (the 8192 that circulates is the grant-token limit; grant constraints cap values at 384 characters, a different limit). **Measured**: the largest accepted single `anykms-aad` value is **8140 characters** (8150 bytes of key and value; 6105 AAD bytes in base64url); 8141 is `ValidationException` "Invalid EncryptionContext" | AAD ≤ **3072 bytes**; native contexts ≤ **4096 bytes** of keys and values (4054 context bytes of headroom). Since the release plan D1 the AAD is lowercase hex under `associatedData` (6144 characters, 6158 bytes with the key): if the limit counts key and value, 8136 hex characters (4068 AAD bytes) fit, 1992 characters (996 AAD bytes) of headroom, about 1.3×. The AAD cap binds only the operations that produce a ciphertext (R-50). `probe.rs` now measures under `associatedData`. The caps may only rise, and raising them is the maintainer's call (PLAN §23 Q7). Multi-entry native contexts were not measured | **verified live 2026-10-07** (`context-limit.json`, `context-over-limit.json`) |
| Grant tokens | ≤ 10 per request, each 1 to 8192 characters | `InvalidArgument` at open | documented |
| Signature blob | ≤ 6144 bytes | `VerificationFailed` outside 1..=6144 | documented |
| Request quotas | shared per account and region: symmetric operations (incl. HMAC) 10,000 to 100,000 rps depending on the region, asymmetric (RSA, ECC) about 1,000 rps, custom key stores 1,800 rps (per docs/cloud/aws.md; exact values per region on the quotas page) | `Throttled` from `ThrottlingException` | documented; operator docs |

## 3. Semantics

| Behavior | Documented / expected | anykms | Status |
|---|---|---|---|
| Empty encryption context on `Encrypt` | equivalent to no context | empty AAD sends no `EncryptionContext` | documented |
| Tink's `AwsKmsAead` context | Tink sends `{"associatedData": hex(aad)}` (Java `BinaryUtils.toHex`, Python `binascii.hexlify`, C++ `absl::BytesToHexString`, Go `hex.EncodeToString`: lowercase) | the same since the release plan D1; uppercase hex is a different context | **verified on Floci 2026-10-13** by hand with Tink Python 1.12.0: Tink's ciphertexts decrypt with a plain `Decrypt` under the lowercase context and not the uppercase one, and Tink decrypts a plain `Encrypt` under it (AAD `users/42`, bytes 0..=255, `fb ff fe 0a`); `tests/emulator.rs` checks the same context against anykms both ways |
| Wrong or missing context on `Decrypt`; tampered ciphertext | `InvalidCiphertextException` (no message) | `DecryptFailed` | **verified live 2026-10-07** (`decrypt-wrong-context.json`, `decrypt-tampered.json`); Floci agrees |
| `Decrypt` of another key's ciphertext with `KeyId` | `IncorrectKeyException` "The key ID in the request does not identify a CMK that can perform this operation." | `DecryptFailed` + hint to `EnvelopeKeyring`; the message is pinned | **verified live 2026-10-07** (`decrypt-other-key.json`); Floci agrees |
| `Decrypt` without `KeyId` (symmetric) | decrypts with the key named in the blob | **always** sends `KeyId` (PLAN Appendix A) | documented |
| `ReEncrypt` | needs `kms:ReEncryptFrom` + `kms:ReEncryptTo`; source and destination contexts | same key both sides, AAD as both contexts | documented; same-key `ReEncrypt` **verified live 2026-10-07** (`reencrypt.json`; the response adds `SourceKeyMaterialId` / `DestinationKeyMaterialId`, ignored) |
| Response `KeyId` of `Sign`, `GenerateMac`, `GetPublicKey` | the key ARN (also when called with an alias ARN) | becomes the signature/tag/public-key version; resolves aliases (an alias's key must be in its partition, region and account) | **verified live 2026-10-07**: all three return the key ARN when called with an alias ARN (`sign-via-alias.json`, `generate-mac-via-alias.json`, `get-public-key-via-alias.json`); Floci returns key ARNs |
| `GetPublicKey` on a disabled key | succeeds (returns the key); `Sign` fails with `DisabledException` | conformance declares `with_public_key_when_disabled`; operator docs warn that local verification continues (*superseded by PLAN §25.2 A3(f): the backend checks the key with `DescribeKey` first and refuses a disabled key's public key; see `docs/operations-aws.md`*) | **verified live 2026-10-07** (us-east-1) |
| `Verify` with an invalid signature | `KMSInvalidSignatureException` (400, no message) | `VerificationFailed`; `SignatureValid=false` (200) mapped the same | **verified live 2026-10-07** (`verify-bad-signature.json`); **Floci answers 200 with `SignatureValid: false`** |
| `VerifyMac` with an invalid tag | `KMSInvalidMacException` (400, no message) | `VerificationFailed`; `MacValid=false` mapped the same | **verified live 2026-10-07** (`verify-mac-bad.json`); Floci agrees |
| ECDSA signature encoding | DER | passed through (core: DER for ECDSA) | documented; Floci DER verifies locally |
| RSA-PSS salt | hash length | matches core | documented; Floci verifies locally with salt = hash length |
| Ed25519 | `ED25519_SHA_512` with `MessageType=RAW` is pure Ed25519; `ED25519_PH_SHA_512` with `DIGEST` hashes again (never used) | message signing only | documented (2025-11-07); both algorithms listed and `ED25519_PH_SHA_512` over a 64-byte digest accepted, **verified live 2026-10-07** (`describe-ed25519.json`, `ed25519-ph-digest.json`); Floci verifies locally |
| RSA `ENCRYPT_DECRYPT` | `RSAES_OAEP_SHA_1` and `RSAES_OAEP_SHA_256`; no encryption context | wraps locally with OAEP-SHA-256 over the cached public key, unwraps with `Decrypt` (`RSAES_OAEP_SHA_256`) | documented; algorithms and server-side OAEP-SHA-256 **verified live 2026-10-07** (`describe-rsa-encrypt.json`, `rsa-oaep-sha256.json`); Floci decrypts a local OpenSSL / aws-lc wrap |
| Encryption context on asymmetric/HMAC keys | rejected (`ValidationException` "EncryptionContext is not supported when encrypting/decrypting with asymmetric CMKs.") | never sent | **verified live 2026-10-07** for RSA (`rsa-with-context.json`); Floci agrees for RSA |
| Symmetric rotation (automatic, on demand) | new material under the same ARN; old ciphertexts keep decrypting | no version exposed; describe lists the ARN as the one version, no primary | documented; Floci agrees |
| Asymmetric / HMAC rotation | not supported (`UnsupportedOperationException`, no message) | new key + alias repoint; versions = key ARNs | **verified live 2026-10-07** for `RotateKeyOnDemand` on a P-256 key (`unsupported-operation.json`); Floci agrees |
| Disabled key | `DisabledException` "<key ARN> is disabled." on every data-plane call (`GetPublicKey` excepted, above) | `KeyStateInvalid`; the message names the key, so it is redacted | **verified live 2026-10-07** for `Encrypt` and Ed25519 `Sign` (`encrypt-disabled.json`, `sign-disabled.json`); **Floci still signs with a disabled key** |
| Pending deletion | `KMSInvalidStateException` "<key ARN> is pending deletion." | `KeyStateInvalid` (message redacted) | **verified live 2026-10-07** (`encrypt-pending-deletion.json`); Floci agrees |
| `KMSInvalidStateException` on custom-key-store keys | may mean the store failed | `KeyStateInvalid`, message redacted | documented |
| Key state change propagation | eventually consistent (seconds) | the live fixture allows 30 s settle time (kept) | **observed live 2026-10-07**: `DisableKey` and `ScheduleKeyDeletion` took effect for the next request in the same second (`disable.json` → `encrypt-disabled.json`, `schedule-deletion-sym2.json` → `encrypt-pending-deletion.json`); one sample each, so the documented eventual consistency still governs |
| `Retry-After` on throttling | not documented | parsed if present, else backoff | **partly verified live 2026-10-07**: none of the 26 recorded error responses carries `Retry-After`; throttling itself was not provoked, so its headers remain unrecorded |
| Clock skew | `InvalidSignatureException` (400) "Signature expired: <signed> is now earlier than <limit> (<server> - 5 min.)" beyond 5 minutes; the response has a `Date` header | records the server offset from `Date`, retryable `Unavailable` (`is_skew` matches "Signature expired") | **verified live 2026-10-07** with a request 30 minutes behind (`clock-skew-30min-behind.json`) |
| Unknown or wrong credentials | `UnrecognizedClientException` "The security token included in the request is invalid." (unknown key id), `InvalidSignatureException` (wrong secret; the fixed text followed by the expected canonical request and string to sign), `ExpiredTokenException`; all HTTP 400 | `Unauthenticated`; the first and last trigger the one refresh-and-retry; only the first paragraph of the signature message is kept | **verified live 2026-10-07** for the first two (`unrecognized-client.json`, `invalid-signature.json`); `ExpiredTokenException` not provoked |
| Access denied | `AccessDeniedException` (400) with `Message` (capital M) naming the principal, action and key ARN | `PermissionDenied`; message redacted | **verified live 2026-10-07** (`access-denied.json`) |
| Malformed key ARN | documented as `InvalidArnException` | `Configuration`; local URI parsing refuses malformed ARNs before any request | **real AWS answers `NotFoundException` "Invalid arn <arn>"**, verified live 2026-10-07 (`invalid-arn.json`); the backend maps that message to `Configuration`, other `NotFoundException`s stay `NotFound` ("Key '<arn>' does not exist", `not-found.json`) |
| Invalid grant token | documented as `InvalidGrantTokenException` | passed through unchecked beyond count and length; `InvalidGrantTokenException` stays `Configuration` if AWS ever returns it | **real AWS accepted `"not-a-grant-token"` on an `Encrypt` the key policy already allowed (200), verified live 2026-10-07** (`invalid-grant-token.json`): AWS ignores grant tokens it does not need, so an invalid token is not an error and anykms does not promise one. A token only matters when a new grant is the caller's only permission; an invalid token then presumably fails as a missing permission (`AccessDeniedException`), not probed; **Floci ignores grant tokens** too |
| Signing with a symmetric key | `InvalidKeyUsageException` "<key ARN> key usage is ENCRYPT_DECRYPT which is not valid for Sign." | `KeyMismatch` (the key-type check refuses it first) | **verified live 2026-10-07** (`invalid-key-usage.json`); **Floci answers `UnsupportedOperationException`** |
| Unknown operation | `UnknownOperationException` (no message) | `Configuration` | **verified live 2026-10-07** (`unknown-operation.json`); Floci answers `UnsupportedOperation` |
| Malformed request body | `SerializationException` "Unexpected value type in payload" (`Message`) | `Backend` (anykms never sends one) | **verified live 2026-10-07** (`malformed-json.json`) |
| Endpoints | `kms.<region>.amazonaws.com`, FIPS `kms-fips.<region>.amazonaws.com` (US, Canada, GovCloud), dual-stack `kms.<region>.api.aws` | derived from regions of the AWS region shape that belong to the partition (`s3`-like labels are refused); others configured | documented; `kms.us-east-1.amazonaws.com` used by A0; **China dual-stack host `api.amazonwebservices.com.cn` still to verify** (A0 ran in us-east-1 only) |

## 4. Credentials

| Source | Behavior | anykms |
|---|---|---|
| Environment | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | snapshot at construction |
| Shared files | `~/.aws/credentials` (`[name]`) over `~/.aws/config` (`[profile name]`, `[default]`); `AWS_PROFILE` | static keys, `credential_process`, `web_identity_token_file` + `role_arn`; SSO and role chaining refused |
| `credential_process` | JSON `{"Version": 1, AccessKeyId, SecretAccessKey, SessionToken?, Expiration?}` on stdout | 60 s timeout, output ≤ 64 KiB, stderr discarded |
| Web identity | STS `AssumeRoleWithWebIdentity` (unsigned query API, XML response); regional endpoint from `AWS_REGION`, else global | token file re-read on each fetch |
| Container | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (ECS, `169.254.170.2`), `_FULL_URI` (EKS Pod Identity `169.254.170.23` / `fd00:ec2::23`, or any HTTPS / loopback), `Authorization` from `AWS_CONTAINER_AUTHORIZATION_TOKEN[_FILE]` | the SDKs' host allowlist |
| IMDSv2 | `PUT /latest/api/token` (TTL header), then `GET /latest/meta-data/iam/security-credentials/[role]` with the token; `fd00:ec2::254` in IPv6 mode | no IMDSv1 fallback; 1 s connect / 2 s request |
| Expiry | temporary credentials carry `Expiration` (RFC 3339) | refreshed 5 minutes before (half the lifetime for short ones) |

## 5. Emulators (2026-10-06)

| | Floci 2.1.0 | LocalStack 2026.9.0 |
|---|---|---|
| License, token | MIT, none | needs `LOCALSTACK_AUTH_TOKEN` since 2026-03-23 (exits with code 55 without one) |
| Image | `floci/floci:2.1.0@sha256:f5aa8c18…ba102db`, port 4566, health `/_floci/health` | `localstack/localstack:2026.9.0@sha256:801a3dff…b792` |
| Cryptography | real: AES-GCM blobs, ECDSA P-256/384/521 (DER over the given digest), RSA PSS/PKCS#1, Ed25519, HMAC, RSA-OAEP-SHA-256 (local wraps decrypt) | not evaluated (no token) |
| SigV4 | not checked (any or no signature accepted); region from the credential scope, account `000000000000` (or a 12-digit access key id) | — |
| Deviations | no `x-amzn-ErrorType` header (type only in the body; `x-amzn-query-error` instead); invalid signature → 200 `SignatureValid: false`; signs with disabled keys; no context size limit; accepts empty / 4097-byte Ed25519 RAW messages; ignores grant tokens; `UnsupportedOperationException` for signing with a symmetric key; digest length and algorithm/curve pairing unchecked; `Enabled` stays true during pending deletion; NotFound is HTTP 404 | — |
| Use | CI on every PR: the conformance suite (`ServerErrorMessages` not applicable, IAM cases skipped) and `tests/emulator.rs` | CI when the token secret exists |

The conformance run against Floci passes every applicable case, the HMAC-SHA-384/512 MAC cases
included: the suite asks for an HMAC key per algorithm (`TestKeyKind::Hmac(alg)`), as an AWS HMAC
key supports one.
