# Operating anykms with Azure Key Vault and Managed HSM

This guide is for whoever runs the key vaults (or Managed HSM pools) and the services that call
them through `anykms-azure` (facade feature `azure`): how to set up keys, permissions and
credentials, and what the errors mean. The design is in [`cloud/azure.md`](cloud/azure.md); facts
about the service and what is still to be confirmed by the live probe are in
[`research/azure-kv.md`](research/azure-kv.md); the ciphertext frame is in
[`azure-ciphertext.md`](azure-ciphertext.md).

## Keys and URIs

| Need | Key | Open with |
|---|---|---|
| Envelope encryption (KEK) | `RSA` / `RSA-HSM` 2048+ with `key_ops` `wrapKey`, `unwrapKey` | `registry.key_wrap(uri)` + `EnvelopeAead` |
| Data keys without AAD | the same KEK | `registry.data_keys(uri)` (unwrap with `key_wrap` on the same key) |
| JWT / document signing | `EC` P-256/384/521 or `RSA` 2048+, `key_ops` `sign`, `verify` | `registry.digest_signer(uri, alg)`, or `AzureProvider::digest_signing_key` |
| Verifying many signatures (JWKS consumers) | the signing key | `CachedVerifier` over `registry.public_keys(uri, alg)` |
| AES-GCM with AAD, AAD-bound data keys | Managed HSM `oct-HSM` AES-256, `key_ops` `encrypt`, `decrypt` | `registry.aead(uri)` |
| HMAC | Managed HSM `oct-HSM`, `key_ops` `sign`, `verify` | `registry.mac(uri, alg)`, experimental feature `mhsm-hmac` |

Standard and Premium vaults have no AES keys for anykms: Premium-vault `oct-HSM` keys are a
preview and are not opened (`Unsupported`). AES-GCM and HMAC need a Managed HSM.

**An RSA KEK does not limit who writes envelopes.** `wrapKey` permission is not needed to wrap:
anyone with the public key (`keys/read`, or a copy of it) can wrap a data key offline and frame
it (`anykms_azure::framing`), so every holder of the public key can write envelopes that decrypt
as genuine, for any AAD. Such envelopes give confidentiality only; the AAD does not authenticate
the writer, and roles limit only who unwraps. Where writers must be limited, use a Managed HSM
`A256KW` KEK, and do not keep an RSA KEK in an `EnvelopeKeyring` with a symmetric primary.

Key URIs:

```text
azure-kv://<vault>.vault.azure.net/keys/<name>[/<version>]
azure-kv://<pool>.managedhsm.azure.net/keys/<name>[/<version>]
```

Without a version a handle follows the key's current version; with one it is pinned (see
[Rotation and versions](#rotation-and-versions)). `AzureKeyRef::from_key_id` converts a Key Vault
key identifier (`https://<vault>.vault.azure.net/keys/<name>/<version>`).

A bearer token only ever goes to an allowlisted host: a vault or pool name under the Key Vault and
Managed HSM suffixes of the public, China and US Government clouds (`AzureProviderBuilder::cloud`
narrows them), and with `allowed_vaults` / `ANYKMS_AZURE_ALLOWED_VAULTS` only the hosts listed.
Use that list when key URIs come from shared configuration. Another host is `Configuration` at
open, with no I/O. The token scope comes from the host suffix, never from a 401 challenge.

## Keys

- **`key_ops` should list only what the application uses.** The key-type check reads them: a KEK
  should have `wrapKey`, `unwrapKey` and nothing else, a signing key `sign`, `verify`. A KEK must
  be dedicated to wrapping; do not sign with it.
- **RSA-OAEP-256 only.** anykms wraps with `RSA-OAEP-256`. Keys are not tied to a padding in
  Azure, but data wrapped by other tools with `RSA-OAEP` (SHA-1) or `RSA1_5` cannot be unwrapped
  through anykms.
- **Key size.** RSA under 2048 bits and EC `P-256K` are refused (`KeyMismatch`). For Managed HSM
  AES keys use 256 bits: Azure does not report an `oct-HSM` key's size, so a 128- or 192-bit key
  cannot be refused before use.
- **Soft delete and purge protection on.** A deleted key is `NotFound` until recovered (see the
  runbook); with purge protection it cannot be destroyed by mistake.
- **The key-type check** reads the key (`GET /keys/<name>`) before a handle's first operation
  and caches it per provider (`key_cache_ttl`, default 10 minutes ±10%); concurrent first
  operations on a key share one read. The cached bundle is
  dropped when a request for the handle's own key or version fails with `NotFound`,
  `KeyMismatch`, `Unsupported`, `KeyStateInvalid` or `PermissionDenied`; never by a version taken
  from input (a signature's or frame's version, `public_key_version`), so forged versions cannot
  force a key read per request. It needs `keys/read`;
  `KeyTypeCheck::TrustCaller` skips it (Managed HSM wrapping and data keys still read the key to
  pick the algorithm).
- **Framed output.** Wrapped keys and AES-GCM ciphertexts carry the key version and algorithm in
  a small frame ([`azure-ciphertext.md`](azure-ciphertext.md)), so other Azure tools need the
  frame stripped (`anykms_azure::framing::parse`).

## Permissions

### Key vaults with Azure RBAC (recommended; the default for new vaults)

| Workload | Role, scoped to the key (`.../vaults/<vault>/keys/<name>`) |
|---|---|
| Envelope encryption, data keys | `Key Vault Crypto Service Encryption User` (read, wrap, unwrap): least privilege |
| Signing and verifying, or several purposes | `Key Vault Crypto User` (read, sign, verify, wrap, unwrap, encrypt, decrypt; also update and backup) |
| Verify only | a custom role with `Microsoft.KeyVault/vaults/keys/read` and `.../keys/verify/action`; or only `keys/read` with `CachedVerifier` / `AzureOptions::local_verify` |

Never give applications `Key Vault Crypto Officer` (it creates, deletes and purges keys). The
key-type check and `describe` need `keys/read`, which every role above includes; without it, open
handles with `KeyTypeCheck::TrustCaller`. Role assignments take a few minutes to apply (managed
identities: up to a day for tokens issued before the change).

### Key vaults with access policies (legacy)

Grant `get` plus the operations used: `wrapKey`, `unwrapKey` for KEKs; `sign`, `verify` for
signing keys. Never `create`, `delete`, `update`, `purge`.

### Managed HSM (local RBAC)

`Managed HSM Crypto Service Encryption User` (read, wrap, unwrap) for KEKs. For AES-GCM, HMAC and
signing, `Managed HSM Crypto User` also grants create, delete and import: prefer a custom role with
`keys/read/action`, `encrypt/action`, `decrypt/action`, `wrap/action`, `unwrap/action`,
`sign/action`, `verify/action`, assigned at `/keys/<name>`.

### Network

A 403 with inner code `ForbiddenByFirewall` is a network rule (vault firewall, private endpoint),
not RBAC: the error says "network rule". Private endpoints keep the public host name, so no extra
host needs allowing.

## Credentials

`AzureProvider::from_env()` (and `anykms::with_default_providers()`) pick one credential by
environment, never by probing the network:

| Set | Credential |
|---|---|
| `ANYKMS_AZURE_CREDENTIAL=workload\|managed\|secret\|none` | that one (`none` disables Azure: `from_env` is then `Configuration`, and the facade skips the provider) |
| `AZURE_FEDERATED_TOKEN_FILE` (+ `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`) | workload identity (AKS) |
| `AZURE_CLIENT_SECRET` (+ `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`) | client secret |
| `IDENTITY_ENDPOINT` (+ `IDENTITY_HEADER`), or `ANYKMS_AZURE_MANAGED_IDENTITY=1` | managed identity (App Service/Functions, or IMDS); `AZURE_CLIENT_ID` picks a user-assigned identity |
| nothing of the above | no credential: the provider still builds, and its first operation is `Configuration` naming these variables |

Credentials are lazy: nothing is read or fetched before the first operation. A malformed
selection (an unknown `ANYKMS_AZURE_CREDENTIAL`, a selected credential missing its settings, an
`AZURE_AUTHORITY_HOST` that is not `https://`) is a `Configuration` error from `from_env`.
`AzureProvider::from_env_with(lookup)` (and `AzureProviderBuilder::from_env_with`,
`credential_from_env_with`, `env_credential_kind_with`, and the facade's
`with_default_providers_from`) reads the same variables, `AZURE_*` and `IDENTITY_*` included, from
a lookup function instead of the process environment. Plain
IMDS needs the explicit opt-in: off Azure it would wait for its connect timeout on every
operation.

Not built in: the Azure CLI, certificates, Azure Pipelines, Azure Arc and the other
`azure_identity` credentials (`ANYKMS_AZURE_CREDENTIAL=cli` is `Configuration`, naming the
replacement). Use the Azure SDK's through the `azure-identity` feature (`azure-identity` in the
facade too):

```rust
let cli = azure_identity::AzureCliCredential::new(None)?;
let provider = AzureProviderBuilder::default()
    .credential(anykms_azure::AzureIdentity::new(cli))
    .build()?;
```

Only tokens come from the SDK: Key Vault calls stay on anykms's client, and the provider caches
each token until shortly before the expiry the SDK reports. The SDK fetches with its own HTTP
client, TLS provider and retries (its credential options turn the retries off).

A source of your own implements `anykms_azure::AzureCredential` (`token`, and optionally
`invalidate`, `kind` and `tenant_id`) and goes in through `AzureProviderBuilder::credential`. It
is anykms's trait, not the SDK's `azure_core::credentials::TokenCredential`, which goes in
through `AzureIdentity` as above.

- **AKS workload identity:** label the pod `azure.workload.identity/use: "true"` and annotate its
  service account with the identity's client id; the webhook sets the variables. The token file
  is read at each token exchange (Kubernetes rotates it). A missing file is `Unavailable` (a
  rotation race, retried by `Retry`); any other failure (permissions, a directory, larger than
  64 KiB, empty or not a token) is `Configuration`, and the error names the file.
- **Guests and multi-tenant setups:** set `AZURE_TENANT_ID` to the vault's tenant. A 401 whose
  challenge names another tenant says so in the error.
- **Tokens** are cached per scope and refreshed 5 minutes before they expire, by the first
  request that finds the token due while the others keep using it. Concurrent requests without
  a usable token share one fetch and its result; a failed fetch is returned to every request for
  5 s before the next attempt. A 401 refreshes once and retries the request once.
- **One provider per cloud:** a credential mints tokens of its own cloud only. Set
  `AZURE_AUTHORITY_HOST` for a sovereign cloud and narrow the provider with
  `AzureProviderBuilder::cloud`.

## Environment

| Variable | Effect |
|---|---|
| `ANYKMS_AZURE_CREDENTIAL` | forces a credential (`workload`, `managed`, `secret`) or disables Azure (`none`) |
| `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | Entra ID credentials (see above) |
| `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `ANYKMS_AZURE_MANAGED_IDENTITY=1` | managed identity |
| `AZURE_AUTHORITY_HOST` | the Entra ID authority (sovereign clouds); `https://` only |
| `ANYKMS_AZURE_ALLOWED_VAULTS` | comma-separated exact hosts tokens may go to (`contoso-prod.vault.azure.net`) |

There is no environment variable for test hosts, custom CAs or a proxy: those are builder calls
(`test_host`, `ca_pem`, `proxy`), so production configuration cannot be redirected by the
environment. Proxy variables (`HTTPS_PROXY`) are ignored. Redirects are never followed (a 3xx is
`Configuration`). `Debug` output prints a proxy URL as `scheme://host:port` only.

## Limits

| What | Limit |
|---|---|
| RSA-OAEP-256 wrap input | modulus bytes − 66 (190 bytes for RSA-2048), checked before the request when the key size is known |
| `A256KW` wrap input (Managed HSM) | a multiple of 8 bytes, at least 16 |
| AES-GCM plaintext (Managed HSM) | not documented by Azure (to verify with T13) |
| Signing | digest only (`DigestSigner`): Azure signs digests; there are no Ed25519 keys |
| HMAC input (`mhsm-hmac`) | 64 KiB, refused before the request (an anykms limit until T13 pins Azure's) |
| Data-key AAD on a vault | none: non-empty AAD is `Unsupported` before any I/O (bind context with `EnvelopeAead`) |
| Responses | 1 MiB (`max_response_bytes`, at least 64 KiB); version lists stop after 10 pages (`versions_truncated`) |
| Frame versions | 32 hex characters (every Key Vault and Managed HSM version today) |

Vault throttling is per 10 seconds per vault (software RSA-2048: 4000 operations; RSA-3072 1000;
RSA-4096 500; EC 4000; HSM-protected keys about half), and 5x that per subscription. Managed HSM is
not throttled but has fixed capacity. A `429` is `Throttled`, with `retry_after()` when Azure
sends `Retry-After`. anykms never retries by itself: use `RetryLayer` with one `RetryBudget` per
vault. Keep requests down with `EnvelopeAead` (one wrap per data key, not per record),
`CachingKeyWrap`, and local verification (`CachedVerifier`, or `AzureOptions::local_verify()`
through `AzureProvider::digest_signing_key_with`, which verifies with the version's public key).
`local_verify()` trusts a version's public key for `key_cache_ttl` (±10%), counted from its
fetch: a disabled or deleted version keeps verifying for at most that long, and when the re-read
fails (vault unreachable, version disabled) verification fails with that error instead of using
the stale key. Versions that came back unknown are remembered for the same time (at most 64),
so a forged signature version costs at most one key read per `key_cache_ttl`. Local RSA
verification needs the `rsa-aws-lc-rs` (default) or `rsa-rustcrypto` feature.

## Rotation and versions

- **Rotate** with a rotation policy or `az keyvault key rotate`. Old data names its version
  (signatures carry it, wrapped keys and ciphertexts have it in their frame), so it stays readable
  while that version is enabled. Move envelopes to the new version with
  `EnvelopeAead::rewrap_local` (Azure has no server-side rewrap).
- **Unversioned URIs** follow the current version for new signatures, wraps and encryptions: the
  request is versionless and the version is read back from the response `kid` (which must name
  the same key on the same host, else `Backend`). Real Azure accepts versionless operations
  (probe T3: `sign` and `wrapkey`). A server that refuses them with `405` (Lowkey Vault does) is
  remembered per host: writes on its unversioned URIs then name the current version from the
  cached key bundle, so they follow a rotation within `key_cache_ttl` (10 minutes by default).
  When that version is gone or refused, the key is read again once.
- **Pinned URIs** (`.../keys/<name>/<version>`) use that version for everything: inputs naming
  another version fail (`VerificationFailed`, `DecryptFailed`), and `public_key_version` serves
  only the pinned version (`UnknownKeyVersion` for any other, before any request). To publish every
  version's public key (a JWKS), open the unversioned URI.
- **`describe`** reports the key's current version as the primary version (what an unversioned
  write uses), also for a pinned URI (`AzureKeyInfo::current` names it when it differs from the
  pinned one); the state is that of the version the handle uses: the pinned version for a pinned
  URI, else the current one. Every version from `/versions` is listed with its own state.
- **`preflight`** reads the key bundle afresh and refuses, with `Operation::Describe`, a key that
  does not fit the handle (`KeyMismatch`, also under `KeyTypeCheck::TrustCaller`; a KEK needs
  `wrapKey` and `unwrapKey` in `key_ops`) or whose version in use is disabled, not yet valid or
  expired (`KeyStateInvalid`). `oct-HSM` keys report
  the MAC capability (with `mhsm-hmac`) but no MAC algorithm: an HMAC key is not bound to one
  `HS*` algorithm.
- **Disabling a version** stops everything that names it: decrypting old data, verifying old
  signatures (server-side), serving its public key.

## Runbook: `ErrorKind` → cause → action

| ErrorKind | Likely cause | Action |
|---|---|---|
| `Configuration` | a malformed key URI (`Operation::ParseUri`); host not allowlisted (`allowed_vaults`, test host); no credential in the environment (first use); a malformed credential environment; a redirect (proxy in front of the vault); TLS certificate rejected | fix the URI or configuration; check proxies |
| `Unauthenticated` | expired or wrong credential; token for another tenant ("vault belongs to tenant ...") or cloud; Entra ID rejected the app (`BackendDetail::code` = `invalid_client/AADSTS...`) | check `AZURE_TENANT_ID`, the app's secret or federated credential, the identity |
| `PermissionDenied` | missing role or access policy (`code` = `ForbiddenByRbac`, `ForbiddenByPolicy`); firewall (`ForbiddenByFirewall`) | check the role at key scope and the network rules |
| `NotFound` | wrong name; deleted key (soft-deleted keys are not visible); wrong version in a pinned URI | recover a deleted key (`az keyvault key recover`) or fix the URI |
| `UnknownKeyVersion` | `public_key_version` of a version this key does not have, or of a version other than the pinned one (caller class) | check the `kid` routing; expected for forged input |
| `KeyMismatch` | key type, curve, size or `key_ops` does not fit the handle (EC opened as RSA, a KEK without `wrapKey`, P-256K, RSA-1024); the vault refused the operation for the key's `key_ops` (`code` = `KeyOperationForbidden`) | open the right key or fix its `key_ops` |
| `KeyStateInvalid` | key being deleted or recovered (409); the current or pinned version is disabled, not yet valid or expired (`code` = `KeyDisabled`, `KeyNotYetValid`, `KeyExpired`) | wait, enable the version, or fix its `nbf`/`exp` |
| `KeyVersionUnusable` | a version named by the input (a signature's, a wrapped key's) is disabled, not yet valid or expired | enable the version or stop using it |
| `DecryptFailed` | damaged or foreign wrapped key/ciphertext; wrong AAD; a version this key does not have | check the data and the key it belongs to |
| `VerificationFailed` | bad signature; a version this key does not have | expected for forgeries |
| `InvalidArgument` | input too large (RSA-OAEP: modulus bytes − 66), digest of the wrong hash, unversioned signature, malformed version; a malformed key identifier or version given to `AzureKeyRef::from_key_id` / `with_version` (`Operation::Construct`); a 400 the vault gave for a write | fix the input |
| `Throttled` | vault limit (see [Limits](#limits)); `retry_after()` when Azure sent `Retry-After` | retry with backoff; reduce request volume |
| `Unavailable` | 5xx, connection refused or reset, DNS, IMDS unreachable; an `AzureIdentity` credential that could not reach its endpoint (a connection or I/O error, 429 or 5xx) | retry; check Azure status |
| `Timeout` | slow vault or network | retry; check `request_timeout` |
| `Backend` | an unexpected response (logged with the `tracing` feature, body never logged) | report it with `request_id` (`x-ms-request-id`) |

**Key states.** Azure answers an operation on a disabled, not-yet-valid or expired version with
`403 Forbidden` and an inner code (`KeyDisabled`, `KeyNotYetValid`, `KeyExpired`), which anykms
uses: `KeyStateInvalid` (config class) when the handle chose the version, `KeyVersionUnusable`
(caller class) when the input did. Key Vault has no key-level flag: "disabling a key" means
disabling its versions, so a signature of a disabled one-version key fails to verify with
`KeyVersionUnusable`. An expired key still unwraps (`exp` only stops `wrapkey` and `sign`).

Every error from a key handle names the key (`Error::resource`, the `azure-kv://` URI), and
carries `BackendDetail::code` (the innermost Azure error code, e.g. `ForbiddenByRbac` for
`Forbidden` / `ForbiddenByRbac`), `request_id` (`x-ms-request-id`, for Azure support; dropped
unless it is at most 128 visible ASCII characters) and `http_status`. Server messages are reduced
to a fingerprint: they can contain client IPs and object ids.

## Tracing

With the `tracing` feature, `anykms-azure` emits an `anykms.azure` debug span per request with
the fields every HTTP backend uses: `backend`, `op`, `resource` (the key URI), `key_version` (the
version the request names, or for a versionless write the one the response names), `attempt`
(1, or 2 after the one 401 token refresh; not the retry layer's count, see
[`operations.md`](operations.md#tracing)), `http_status`, `code` (the innermost Azure error
code), `request_id` (filtered as above), `latency_ms`, `error_kind` and `outcome` (`ok`,
`error`, or `cancelled` for a call dropped before it finished). Each token
fetch gets an `anykms.azure.token` span (`backend`, `credential`, `outcome`, `error_kind`,
`latency_ms`, `expires_in_s`). `credential` is a stable snake_case label: `workload_identity`,
`client_secret`, `managed_identity`, `azure_identity`, `static`, `unconfigured` (nothing in the
environment), or a custom credential's own (`custom` by default); it does not repeat the `ANYKMS_AZURE_CREDENTIAL` values. A successful
fetch is a DEBUG event, a failed one a WARN event with `credential`, `error_kind` and the error
(which names the token file when one failed). Warnings are also logged for unclassified errors, unusable responses, a tenant mismatch in a 401 challenge, a
version-list `nextLink` to another host, and opening a key on a test host; an INFO event records
the credential chosen from the environment and a host's refusal of versionless operations.
Tokens, secrets, plaintext, AAD, request and response bodies and query strings never appear
(`tests/hygiene.rs` checks this at TRACE, and checks the span fields). Cap `reqwest`, `hyper` and
`rustls` at INFO.

## Testing against Lowkey Vault

[Lowkey Vault](https://github.com/nagyesta/lowkey-vault) emulates a standard vault:
`docker compose --profile azure up -d lowkey-vault`, then
`cargo test -p anykms-azure --all-features --test lowkey --test conformance_lowkey`. It accepts any
token and refuses versionless operations (the 405 fallback above); its error messages differ
from Azure's, so do not rely on it for error handling. Managed HSM has no emulator.
