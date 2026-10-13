# Operating anykms with AWS KMS

This guide is for whoever owns the AWS account, the KMS keys and the services that call them
through `anykms-aws` (the `aws` feature of the `anykms` facade). Behavior that the AWS
documentation does not state is tracked in `research/aws-kms.md`, verified against real AWS by
the live probe (`scripts/probe-aws.sh`, run 2026-10-07).

## Keys and URIs

Key URIs are full ARNs, never bare key ids or alias names (the region and account must be
explicit):

```text
aws-kms://arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/app-kek
```

| anykms handle | Key spec / usage | Notes |
|---|---|---|
| `aead`, `data_keys`, `key_wrap` | `SYMMETRIC_DEFAULT` / `ENCRYPT_DECRYPT` | AAD is the encryption context; plaintexts 1 to 4096 bytes |
| `key_wrap` | `RSA_2048/3072/4096` / `ENCRYPT_DECRYPT` | local RSA-OAEP-SHA-256 wrap, `Decrypt` unwrap; SHA-1 OAEP never used |
| `digest_signer`, `digest_verifier`, `public_keys` | `ECC_NIST_P256/P384/P521`, `RSA_*` / `SIGN_VERIFY` | ECDSA, RSA-PSS (salt = hash length), RSA PKCS#1 v1.5 |
| `message_signer`, `message_verifier`, `public_keys` | `ECC_NIST_EDWARDS25519` / `SIGN_VERIFY` | pure Ed25519 over 1 to 4096-byte messages |
| `mac` | `HMAC_256/384/512` / `GENERATE_VERIFY_MAC` | the key's spec fixes the algorithm |

The region must have the AWS region shape (`eu-west-1`, `us-gov-west-1`, `ap-southeast-7`) and
belong to the ARN's partition (`cn-*` only in `aws-cn`, `us-gov-*` only in `aws-us-gov`, the ISO
and European Sovereign Cloud prefixes only in theirs); other labels are `InvalidArgument`, so a
derived endpoint is always `kms.<region>.<partition suffix>`.

Not supported: AWS managed keys (`alias/aws/...`), `ECC_SECG_P256K1`, `HMAC_224`, `SM2`,
ML-DSA, key agreement, `ED25519_PH_SHA_512`.

## Key policies

AWS recommends granting KMS access in the key policy, scoped to the principals that use the key,
rather than IAM policies with `"Resource": "*"`. Grant only the actions each service uses:

| Use | Actions |
|---|---|
| AEAD and envelope KEK (read and write) | `kms:Encrypt`, `kms:Decrypt`, `kms:ReEncryptFrom`, `kms:ReEncryptTo`, `kms:GenerateDataKey`, `kms:GenerateDataKeyWithoutPlaintext` (wrapped-only data keys), `kms:DescribeKey` |
| Decrypt-only service | `kms:Decrypt`, `kms:DescribeKey` |
| RSA KEK | writers `kms:GetPublicKey`, `kms:DescribeKey`; readers `kms:Decrypt`; rewrap `kms:ReEncryptFrom`, `kms:ReEncryptTo`. The writer permissions only fetch the public key: **every holder of the public key** can write envelopes (see below) |
| Signing | `kms:Sign`, `kms:Verify`, `kms:GetPublicKey`, `kms:DescribeKey` |
| Verify-only | `kms:Verify`, `kms:GetPublicKey`, `kms:DescribeKey` |
| Public keys only (JWKS, `CachedVerifier`) | `kms:GetPublicKey`, `kms:DescribeKey` (required: see below) |
| MAC | `kms:GenerateMac`, `kms:VerifyMac`, `kms:DescribeKey` |

```json
{
  "Sid": "AppDataPlane",
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"},
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
  "Resource": "*",
  "Condition": {"ForAllValues:StringEquals": {"kms:EncryptionContextKeys": ["associatedData"]}}
}
```

- Never grant applications `kms:*`, `kms:CreateKey`, `kms:PutKeyPolicy`,
  `kms:ScheduleKeyDeletion` or `kms:CreateGrant`. Key lifecycle belongs to infrastructure as code.
- `kms:DescribeKey` serves the key-type check: each handle reads the key's metadata once (cached
  per provider for about 10 minutes; concurrent first operations share one `DescribeKey`) before
  its first operation and refuses a mismatched key with `KeyMismatch`. The cached metadata is
  dropped when a request for the handle's own key fails with `NotFound`, `KeyMismatch`,
  `Unsupported` or `KeyStateInvalid`; never by a version taken from input (a signature's or tag's
  version, `public_key_version`), so forged `kid`s cannot force a `DescribeKey` per request. Opt
  out per handle with `KeyTypeCheck::TrustCaller`; AWS still rejects wrong usages
  (`InvalidKeyUsageException`), but alias URIs then resolve from the first response.
- `kms:DescribeKey` is **required** for public keys, also with `KeyTypeCheck::TrustCaller`:
  `public_key` and `public_key_version` send an uncached `DescribeKey` before every
  `GetPublicKey` (two requests per call) to refuse a key that is not enabled (see below).
  Without the permission they fail with `PermissionDenied` (fail closed).
- The `kms:EncryptionContextKeys` condition above pins a key to the portable API (every anykms
  ciphertext with AAD uses the one reserved context key `associatedData`; empty AAD sends no
  context). This is Tink's key, so the pin admits Tink's `AwsKmsAead` too: the two read each
  other's ciphertexts. Drop it for keys that also serve native contexts
  (`EncryptionContextAead`). The AAD itself is the condition key
  `kms:EncryptionContext:associatedData`, in lowercase hex: for example
  `{"StringLike": {"kms:EncryptionContext:associatedData": "75736572732f*"}}` admits only AAD
  that starts with `users/`.
- **Envelope KEKs must be dedicated** to envelopes: data keys are wrapped with empty AAD, so any
  other code path that decrypts with empty AAD under the same key could unwrap them.
- **An RSA KEK does not limit who writes.** Wrapping is local with the public key, so anyone who
  holds it (a public key is not secret and stays usable once copied) can write an envelope that
  decrypts as genuine, for any AAD: the envelope gives confidentiality only, and the AAD does not
  authenticate the writer. The key policy limits readers, not writers. Where writers must be
  limited, use a symmetric KEK, and do not keep an RSA KEK in an `EnvelopeKeyring` with a
  symmetric primary: the ring still accepts envelopes wrapped under it.
- Account and region allowlists (`AwsProviderBuilder::allowed_accounts` / `allowed_regions`, or
  `ANYKMS_AWS_ALLOWED_ACCOUNTS` / `_REGIONS`): set them whenever key URIs can come from
  configuration that others edit, or are stored next to ciphertexts. Without an allowlist a URI
  could name someone else's key, which would then receive plaintext on `encrypt`, or a region
  you do not use. Entries must be region names (`eu-west-1`). An empty list (or an empty
  variable) is a `Configuration` error at `build()`: omit it to allow every account or region.

## CloudTrail and the encryption context

CloudTrail logs every KMS request with its **encryption context in clear text**. anykms sends the
AAD as `{"associatedData": lowercase_hex(aad)}` (Tink's mapping): hex is an encoding, not
protection, so **AAD must not be secret** (use identifiers such as `users/42/ssn`, never the data
itself). Plaintexts,
data keys, signatures' messages and grant tokens are not logged by CloudTrail.

## Limits

- `Encrypt` takes 1 to 4096 bytes: AWS rejects empty plaintexts. Encrypt bulk data with
  `EnvelopeAead` (one KMS call per data key, any size).
- `Sign` (Ed25519, raw) and `GenerateMac` take 1 to 4096 bytes: hash longer messages first, or
  use the digest signers.
- AAD is capped at 3072 bytes (6144 hex characters) and native contexts at 4096 bytes of keys and
  values (AWS documents no limit; the caps are conservative and may only rise). Checked before
  any request. The AAD cap binds the operations that produce a ciphertext (`Encrypt`,
  `GenerateDataKey*`, `ReEncrypt`), never `Decrypt`, so a ciphertext written after a raise still
  decrypts with an older release. Real AWS accepted 8150 bytes for a one-entry context (measured
  2026-10-07): 4068 AAD bytes under `associatedData`, about 1.3 times the AAD cap and twice the
  native one.
- Request quotas are shared per account and region (symmetric operations, including HMAC, in the
  10,000 to 100,000 requests per second range by region; asymmetric operations around 1,000;
  custom key stores 1,800): a burst in one service throttles the others. Use a `RetryBudget`
  shared by the process and `EnvelopeAead` (one KMS call per data key) to stay well below
  them. `ThrottlingException` is `Throttled`.

## Aliases, rotation and versions

- **Symmetric keys:** automatic or on-demand rotation keeps the ARN and old ciphertexts keep
  decrypting; anykms exposes no versions (`ciphertext_version` is `None`; `describe` lists the
  key ARN as its one version).
- **Alias URIs follow repoints.** After `UpdateAlias`, ciphertexts made under the old key fail
  with `DecryptFailed` and the hint "alias repointed? route old ciphertexts with
  EnvelopeKeyring" (`IncorrectKeyException`): open the old key by its own ARN and route old
  envelopes to it with `EnvelopeKeyring`.
- **Signing and HMAC keys cannot rotate.** Rotation is a new key plus an alias repoint. Their
  signatures, tags and public keys carry the **key ARN** as the version, so the new key gets a
  new JWKS `kid`. A handle verifies only its own key: a signature or tag labeled with another ARN
  is `VerificationFailed` before any request (a `kid` from a token must never select a key), as
  `public_key_version` argument `UnknownKeyVersion`; a malformed version is `InvalidArgument`, and a signature or tag **without** a version verifies with the
  handle's own key (an AWS key has exactly one version, so absence selects nothing; GCP and
  Azure refuse unversioned input instead). To keep verifying old tokens, configure each old key
  by ARN and route by `kid` (for example a `CachedVerifier` per key, keyed by the version). An
  alias handle's JWKS holds only the key the alias points to, so publish the old and the new
  key's JWKS together (both opened by ARN) from before the repoint until the old tokens expire
  (the `anykms_recipes::jose` docs, "Publishing the JWKS and rotating", merge them).
- **Kids and tags carry the key ARN.** A JWT `kid` (`anykms_recipes::jose`) is
  `<key name>.<key ARN>`, and the storage encoding of signatures and tags (`to_base64`, the
  `AKS`/`AKT` format) embeds the ARN as the version, so the account ID, region and key ID appear in
  every token, JWKS and stored tag (an HMAC API token is about 100 characters longer than on
  transit). For a compact tag, store only the MAC bytes and verify an unversioned tag, which an
  AWS handle verifies with its own key:

  ```rust
  let tag = mac.mac(token_id).await?;
  let stored = tag.as_bytes().to_vec(); // no algorithm, no ARN
  // Later: the handle's algorithm, no version.
  let tag = Tag::from_parts(mac.mac_algorithm(), None, stored);
  mac.verify_mac(token_id, &tag).await?;
  ```

  Such a tag no longer names its key: after a rotation (a new key behind the alias), verify old
  tags with the old key's handle.
- For alias URIs, every key ARN AWS returns (`DescribeKey`, `Sign`, `GenerateMac`,
  `GetPublicKey`) must be in the alias's partition, region and account; otherwise the response
  is refused as `Backend`.
- **Multi-Region keys:** configure one replica ARN per region under a shared logical `kek_id`
  (anykms does not match MRK replicas to each other).
- **Grant tokens** (`GrantTokens` extension) are passed through as given: anykms checks only
  their count (1 to 10) and length (1 to 8192 printable ASCII characters). AWS ignores grant
  tokens it does not need, so an invalid or stale token is **not an error** when the key policy
  or IAM already allows the call (an `Encrypt` with `"not-a-grant-token"` succeeded, verified
  2026-10-07). anykms does not promise that a bad token is detected; use grant tokens only to
  bridge the eventual consistency of a new grant, and drop them once the grant is effective. If
  AWS ever answers `InvalidGrantTokenException`, it is `Configuration`.
- **Custom key stores and XKS:** a disconnected store answers `KeyUnavailableException` /
  `CustomKeyStoreInvalidStateException` and friends, which anykms reports as `Unavailable`
  (retryable); they have their own 1,800 rps quota.

## Credentials

Resolved on the first operation (building the provider does no network I/O), cached, and
refreshed 5 minutes before they expire by the first request that finds them due; other requests
keep using the current credentials meanwhile. Concurrent requests with no usable credentials
share one fetch and its result; when that fetch fails, requests get its error for the next 5 s
without fetching again. The default chain takes the first configured source:

1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (/ `AWS_SESSION_TOKEN`);
2. the shared files' profile (`AWS_PROFILE`, else `default`; `AWS_CONFIG_FILE`,
   `AWS_SHARED_CREDENTIALS_FILE`): static keys only;
3. web identity: `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` (+ `AWS_ROLE_SESSION_NAME`):
   EKS IRSA, GitHub Actions OIDC; STS regional endpoint from `AWS_REGION`;
4. the container endpoint: ECS task roles (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) and EKS Pod
   Identity (`AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`);
5. EC2 instance metadata, IMDSv2 only (set the instance's hop limit to 2 for containers on EC2),
   unless `AWS_EC2_METADATA_DISABLED=true`.

A configured source that fails is reported; the chain does not fall through to the next one.
Token files (`AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`) are re-read
on every fetch: a missing file is `Unavailable` (a rotation race, retried by `Retry`); any other
failure (permissions, a directory, too large, empty, not UTF-8) is `Configuration`, and the error
names the file.

Not built in: IAM Identity Center (SSO), role chaining (a profile with `role_arn`), MFA and
`credential_process`. A profile that uses them is `Configuration`, naming the replacement: the
AWS SDK's own chain through the `sdk-credentials` feature (`aws-sdk-credentials` in the facade):

```rust
let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
let provider = AwsProvider::builder()
    .credentials(anykms_aws::credentials::SdkCredentials::new(
        sdk.credentials_provider().expect("credentials"),
    ))
    .build()?;
```

Only the credentials come from the SDK: KMS calls stay on anykms's client, and the provider
caches what the SDK returns until shortly before it expires. The SDK fetches with its own HTTP
client, TLS provider and retries; `aws_config::ConfigLoader::retry_config(RetryConfig::disabled())`
leaves retrying to your `Retry` layer. Any other source: implement `CredentialSource` and pass it
to `AwsProviderBuilder::credentials`.

When AWS rejects credentials as expired or unknown (`ExpiredTokenException`,
`UnrecognizedClientException`), they are refetched and the request is sent once more if they
changed; no other retry happens in the backend. A clock-skew rejection ("Signature expired")
records the server's clock offset from the response's `Date`, so the next attempt of your
`Retry` signs with the corrected clock; keep hosts on NTP anyway.

## Environment

`AwsProvider::from_env()` (and the facade's `with_default_providers()`) reads a snapshot of:

| Variable | Effect |
|---|---|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`, `AWS_ROLE_SESSION_NAME`, `AWS_REGION`, `AWS_CONTAINER_CREDENTIALS_*`, `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, `AWS_EC2_METADATA_DISABLED` | the credential chain (see Credentials) |
| `AWS_USE_FIPS_ENDPOINT`, `AWS_USE_DUALSTACK_ENDPOINT` | `true`/`false`: FIPS or dual-stack derived endpoints |
| `AWS_ENDPOINT_URL_KMS`, else `AWS_ENDPOINT_URL` | one endpoint for every region |
| `AWS_CA_BUNDLE` | a PEM file that replaces the system roots (read by `from_env`) |
| `ANYKMS_AWS_ALLOWED_ACCOUNTS`, `ANYKMS_AWS_ALLOWED_REGIONS` | comma-separated allowlists |
| `ANYKMS_AWS_ALLOW_LOOPBACK_HTTP` | `1`/`true`: `http://` endpoints on literal loopback IPs (emulators) |

No variable is required: the region comes from each key ARN. A malformed value is a
`Configuration` error from `from_env`.

`AwsProvider::from_env_with(lookup)` (and `AwsProviderBuilder::from_env_with`, and the facade's
`with_default_providers_from`) reads the same variables from a lookup function instead of the
process environment; the credential chain takes its variables from that lookup too.

## Endpoints, TLS and network

- Endpoints are derived from the ARN's partition and region: `kms.<region>.amazonaws.com`
  (`.com.cn` in China), FIPS `kms-fips.<region>.amazonaws.com` (`fips(true)` /
  `AWS_USE_FIPS_ENDPOINT=true`), dual-stack `kms.<region>.api.aws` (`dual_stack(true)` /
  `AWS_USE_DUALSTACK_ENDPOINT=true`).
- VPC interface endpoints: `.endpoint("eu-west-1", "https://vpce-…")` per region, or
  `AWS_ENDPOINT_URL_KMS` for all. Requests are signed for the ARN's region either way.
- TLS uses rustls with the system roots (or `AWS_CA_BUNDLE` / `ca_pem`); verification cannot be
  disabled. The KMS client is built by `build()`, so missing roots, a bad `ca_pem` or no crypto
  provider are `Configuration` errors there, not on the first request. Plain `http://` is accepted only for literal loopback IPs with
  `allow_loopback_http()` (`ANYKMS_AWS_ALLOW_LOOPBACK_HTTP=1`), for emulators.
- No proxy unless configured (`Proxy::Url`); proxy environment variables are ignored. Redirects
  are never followed. Timeouts: 2 s connect, 10 s per request (`connect_timeout`,
  `request_timeout`). Responses are capped at 256 KiB (`max_response_bytes`, at least 64 KiB).
  `Debug` output of the configuration prints URLs (proxy, endpoints) as `scheme://host:port`
  only.

## Runbook: `ErrorKind` → AWS cause → action

| ErrorKind | AWS exceptions | Action |
|---|---|---|
| `NotFound` | `NotFoundException` ("Key '…' does not exist") | Check the ARN, region and account |
| `UnknownKeyVersion` | `public_key_version` with another key's ARN (caller class; verifying such a signature or tag is `VerificationFailed`) | Invalid input; for legitimate tokens, the `kid` routing |
| `DecryptFailed` | `InvalidCiphertextException` (wrong AAD/context, tampered), `IncorrectKeyException` (another key's ciphertext) | Check the AAD; after an alias repoint, route old ciphertexts to the old key |
| `VerificationFailed` | `KMSInvalidSignatureException`, `KMSInvalidMacException`, `SignatureValid=false` | Invalid input; do not retry |
| `KeyStateInvalid` | `DisabledException`, `KMSInvalidStateException` (pending deletion or import, failed custom key store); public keys of a key whose `DescribeKey` state is not `Enabled` | Enable the key or cancel its deletion |
| `Unavailable` | `KeyUnavailableException`, public keys of a key in state `Creating`, `Updating` or `Unavailable`, custom-key-store / XKS / CloudHSM exceptions, `KMSInternalException`, `DependencyTimeoutException`, 5xx, clock skew, unreachable credential endpoints | Retried by `Retry`; persistent: check the key store, network, NTP |
| `Timeout` | client connect or request timeout | Network path, VPC endpoint, `request_timeout` |
| `Throttled` | `ThrottlingException` | Back off (`Retry`); reduce request rates; request a quota increase |
| `Unauthenticated` | `UnrecognizedClientException`, `InvalidClientTokenId`, `ExpiredTokenException`, `InvalidSignatureException`, STS `InvalidIdentityToken` / `AccessDenied` | Check the credential source, the role trust policy, the clock |
| `PermissionDenied` | `AccessDeniedException` | Grant the action in the key policy (see above) |
| `KeyMismatch` | `InvalidKeyUsageException`; the key-type check | Open the key with the handle that matches its spec and usage |
| `InvalidArgument` | local checks (sizes, versions, contexts); `ValidationException` | Fix the input; a `ValidationException` means a local check missed it: report it |
| `Unsupported` | `UnsupportedOperationException`; a feature not available for the key | Use another key type or recipe |
| `Configuration` | a malformed key URI (`Operation::ParseUri`), no credentials found, malformed profile, `InvalidGrantTokenException`, `InvalidArnException` or `NotFoundException` "Invalid arn …" (AWS's actual answer to a malformed ARN), `UnknownOperationException`, `OptInRequired`, a redirect, a rejected TLS certificate, an allowlist refusal | Fix the configuration |
| `Backend` | `LimitExceededException` (resource quota), an unknown exception, an undecodable response, a response naming another key | Look at `BackendDetail` (`code`, `request_id`) and open an issue if it persists |

**A disabled key's public key is refused.** AWS serves `GetPublicKey` for a disabled key (only
`Sign` and `Verify` fail, verified on 2026-10-07), so anykms describes the same key first
(uncached; for alias URIs, the key the alias resolves to) and refuses `public_key` and
`public_key_version` with `KeyStateInvalid` unless its state is `Enabled` (`Unavailable`,
retryable, while it is `Creating`, `Updating` or `Unavailable`). A `CachedVerifier` therefore
stops accepting the key's signatures once its cache expires, like server-side verification.
Public keys already handed out (a published JWKS, a `LocalVerifier`) are not recalled: remove
the key from those too.

**An RSA key-wrap key is checked before every wrap.** RSA KEKs wrap locally under the key's
public key, so no AWS request would refuse a disabled key: anykms checks the key state in its
cached `DescribeKey` metadata before each wrap and refuses one that is not `Enabled`
(`KeyStateInvalid`; `Unavailable` while it is `Creating`, `Updating` or `Unavailable`). That
metadata is cached for up to about 11 minutes (10 minutes ±10% jitter), so a key disabled or
scheduled for deletion can keep wrapping in that window; `describe` or `preflight` on the handle
refreshes the cache at once. Disable a KEK, wait out that window, and only then schedule its
deletion, so that no data key is wrapped to a key that is about to be deleted.
`preflight` on every AWS handle sends a fresh `DescribeKey` and refuses a key that is not
enabled, even under `KeyTypeCheck::TrustCaller`.

Every error has the backend name `aws`, names the key (`Error::resource`, the key URI) and
carries the AWS exception name
(`BackendDetail::code`), the request id (`x-amzn-RequestId`) and the HTTP status (400 for every
KMS exception, authentication and not-found included). Server messages are kept only when they
are fixed AWS texts (for example the validation and `IncorrectKeyException` texts, or the first
paragraph of a signature mismatch); others, such as messages naming a key ARN or principal,
appear as a length and a keyed fingerprint.

## Tracing

With the `tracing` feature, each request is a `debug` span `anykms.aws` with the fields every
anykms HTTP backend uses:

| Field | Value |
|---|---|
| `backend` | `aws` |
| `op` | the anykms operation (`encrypt`, `sign`, ...) |
| `resource` | the key URI (`aws-kms://arn:...`: partition, region, account and key or alias) |
| `key_version` | the resolved key ARN, on `Sign`, `Verify`, `GenerateMac`, `VerifyMac` and `GetPublicKey` requests once known |
| `attempt` | 1, or 2 for the refresh-once retry (not the retry layer's count: its `anykms retry` event has an `attempt` of its own, and each retried call is a new span; see [`operations.md`](operations.md#tracing)) |
| `http_status`, `code`, `request_id` | the response status, the AWS exception name, `x-amzn-RequestId` |
| `latency_ms`, `error_kind`, `outcome` | duration, the anykms `ErrorKind`, `ok` / `error` / `cancelled` (the call was dropped before it finished) |

Credential fetches are `debug` spans `anykms.aws.token` with `backend`, `credential` (the source's
stable snake_case label: `environment`, `profile`, `web_identity`, `container`, `imds`, ...),
`outcome`, `error_kind`, `latency_ms` and `expires_in_s`. A successful refresh is a `debug`
event; a failed one is a `warn` event with `credential`, `error_kind` and the error
(which names the token file when one failed). Other events: the credential source chosen (kind,
never values), the refresh-once retry, clock-skew
corrections, an alias resolving to another key, unclassified errors. Plaintexts, AAD and
context values, data keys, messages, signatures, grant tokens and credentials never appear (a
TRACE hygiene test checks it, and pins the span fields). Cap `reqwest`, `hyper` and `rustls` at
`info` in production.
