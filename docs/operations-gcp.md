# Operating anykms with Google Cloud KMS

This guide is for whoever runs the Google Cloud project and the services that call Cloud KMS
through `anykms-gcp` (facade feature `gcp`). The design is in `cloud/gcp.md`; facts about the
service and what is still to be confirmed by the live probe are in `research/gcp-kms.md`.

## Keys and URIs

Key URIs are Cloud KMS resource names under the `gcp-kms` scheme (Tink's spelling):

```text
gcp-kms://projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>[/cryptoKeyVersions/<n>]
```

| Handle | URI | Cloud KMS key |
|---|---|---|
| `aead`, `key_wrap` (envelope KEK) | **without** a version | `ENCRYPT_DECRYPT`, `GOOGLE_SYMMETRIC_ENCRYPTION` (any protection level) or `EXTERNAL_SYMMETRIC_ENCRYPTION` |
| `key_wrap` (RSA KEK; typed: `GcpProvider::key_wrap_key` → `GcpKeyWrapKey`) | **with** a version | `ASYMMETRIC_DECRYPT`, `RSA_DECRYPT_OAEP_{2048,3072,4096}_SHA256`; another algorithm (OAEP with SHA-1 or SHA-512) is `KeyMismatch` on wrap and, before any `asymmetricDecrypt`, on unwrap |
| digest signer/verifier, `public_keys` | **with** a version | `EC_SIGN_P256_SHA256`, `EC_SIGN_P384_SHA384`, `RSA_SIGN_PSS_*`, `RSA_SIGN_PKCS1_*` (SHA-256, or SHA-512 at 4096 bits) |
| message signer/verifier | **with** a version | `EC_SIGN_ED25519` (software keys) |
| `mac` | **with** a version | `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512` |
| `describe` | either | any |

A URI of the wrong shape fails to open with `KeyMismatch` and a hint. Cloud KMS asymmetric and
MAC keys have no primary version, so a signing configuration pins one; AEAD keys never name one
(encrypt uses the primary, decrypt finds the version itself).

Not supported: `RAW_ENCRYPT_DECRYPT` keys, secp256k1 and `HMAC_SHA224` (until anykms has the
algorithms), `HMAC_SHA1`, raw PKCS#1 signing, post-quantum keys, RSA-OAEP with SHA-1 or SHA-512,
and signing with Cloud EKM (`EXTERNAL`, `EXTERNAL_VPC`) keys (EKM signs data, not digests). All
of these fail with `KeyMismatch`.

## IAM

Grant roles **on the key or the key ring, never the project**.

| Use | Role |
|---|---|
| AEAD and envelope KEKs | `roles/cloudkms.cryptoKeyEncrypterDecrypter`; split into `cryptoKeyEncrypter` / `cryptoKeyDecrypter` for write-only or read-only services |
| RSA KEKs | `roles/cloudkms.publicKeyViewer` (wrap is local, with the public key; unwrap's key-type check reads it too) plus `roles/cloudkms.cryptoKeyDecrypter` or `cryptoKeyEncrypterDecrypter` (unwrap), plus `cloudkms.cryptoKeyVersions.get` (see below). IAM limits readers only: **every holder of the public key** can write envelopes that decrypt as genuine, so they give confidentiality only and the AAD does not authenticate the writer. Use an `ENCRYPT_DECRYPT` KEK where writers must be limited, and do not keep an RSA KEK in an `EnvelopeKeyring` with a symmetric primary |
| Signing | `roles/cloudkms.signerVerifier`. It includes `viewPublicKey`, which the key-type check and local verification need; `roles/cloudkms.signer` alone works only with `KeyTypeCheck::TrustCaller` and no verification. Plus `cloudkms.cryptoKeyVersions.get` (see below) |
| MAC | `roles/cloudkms.signerVerifier` (`useToSign` for `macSign`, `useToVerify` for `macVerify`) |
| Verify-only services, JWKS publishers | `roles/cloudkms.publicKeyViewer`, plus `cloudkms.cryptoKeyVersions.get` (see below) |
| Every public-key read (signing's key-type check, local verification, `PublicKeys`, RSA wrap and its key-type check) | `cloudkms.cryptoKeyVersions.get`, through `roles/cloudkms.viewer` on the key or a custom role. Before each `getPublicKey` the backend checks that the version is `ENABLED`, so the public key of a disabled version is never handed out (Cloud KMS may serve it). Without the permission public keys **fail closed** with `PermissionDenied`. Whether `publicKeyViewer` grants it is **not verified** (probe T1 does not check it), so grant it explicitly |
| `describe()` and the AEAD/MAC key-type check | `cloudkms.cryptoKeys.get`, `cloudkms.cryptoKeyVersions.get` and `cloudkms.cryptoKeyVersions.list`, through `roles/cloudkms.viewer` on the key or a custom role (the operational roles carry no metadata permissions) |
| Never for applications | `roles/cloudkms.admin`, `cloudkms.cryptoKeyVersions.destroy`, `roles/cloudkms.cryptoOperator` (too broad) |

Without the metadata permissions, open handles with `KeyTypeCheck::TrustCaller`
(`OpenOptions::with_key_type_check`) and give up the PSS-vs-PKCS#1 and purpose checks (the server
still enforces purpose and digest algorithm).

**403 or 404.** A missing key answers `NOT_FOUND` only when the caller may read the key ring;
otherwise Cloud KMS answers 403 "Permission … denied on resource … (or it may not exist)", which
is `PermissionDenied`. Grant the metadata role on the key ring if you want missing keys to be
reported as `NotFound`. VPC Service Controls denials ("Request is prohibited by organization's
policy") are `PermissionDenied` too.

**Allowlists.** Set `GcpProviderBuilder::allowed_projects` (and `allowed_locations`), or
`ANYKMS_GCP_ALLOWED_PROJECTS`. Without them, a key URI injected through configuration could name
an attacker-owned key that grants everyone encrypt rights, and your data would be encrypted under
it. An empty allowlist (an empty list in code, or the variable set to an empty value) is
`Configuration` at `build()`: omit it to allow everything.

## Credentials

`Credentials::adc()` (the default, and what `GcpProvider::from_env()` and
`anykms::with_default_providers()` use) follows Application Default Credentials:

1. the JSON file named by `GOOGLE_APPLICATION_CREDENTIALS`;
2. the gcloud ADC file (`$CLOUDSDK_CONFIG/application_default_credentials.json`, by default
   `~/.config/gcloud/…`), written by `gcloud auth application-default login`;
3. the metadata server (GCE, GKE Workload Identity, Cloud Run, Cloud Functions) at
   `GCE_METADATA_HOST` or `169.254.169.254`, probed with a 1 s connect timeout.

`GcpProvider::from_env_with(lookup)` (and `GcpProviderBuilder::from_env_with`, and the facade's
`with_default_providers_from`) reads every variable from a lookup function instead of the process
environment, including the ones ADC reads on first use (`GOOGLE_APPLICATION_CREDENTIALS`,
`CLOUDSDK_CONFIG`, `HOME`/`APPDATA`, `GCE_METADATA_HOST`).

Prefer, in this order: the metadata server (GKE Workload Identity, an attached service account),
workload identity federation (`external_account` files: GitHub Actions through
`google-github-actions/auth`, AKS/EKS/on-premises Kubernetes projected tokens), impersonation
(`Credentials::impersonated`, `impersonated_service_account` files). Service-account key files
work (feature `service-account-key`, self-signed JWTs) but Google recommends against them.
`authorized_user` files (a developer's gcloud login) need a quota project: set
`GcpProviderBuilder::quota_project`, `ANYKMS_GCP_QUOTA_PROJECT` or `GOOGLE_CLOUD_QUOTA_PROJECT`,
or `quota_project_id` in the file.

Not built in (`Configuration` naming the type): `external_account` with an AWS or executable
credential source, `external_account_authorized_user`, `gdch_service_account`, universe domains
other than `googleapis.com`. Google's own auth library covers the first four, through the
`google-cloud-auth` feature (`gcp-google-cloud-auth` in the facade):

```rust
let creds = google_cloud_auth::credentials::Builder::default().build_access_token_credentials()?;
let provider = GcpProvider::builder()
    .credentials(Credentials::google_cloud_auth(creds))
    .build()?;
```

Only access tokens come from the library: Cloud KMS calls stay on anykms's client. The library
caches and refreshes tokens itself (they are not cached again here) and fetches them with its own
HTTP client: anykms-gcp depends on it with default features off, so either install a process-wide
rustls provider (`rustls::crypto::CryptoProvider::install_default`) or enable the library's
`default-rustls-provider` feature yourself. Build its credentials inside a tokio runtime (it
spawns a refresh task).

**Planted credential files.** A URL a credential file names must be exactly the fixed URL for
its field, with no query or fragment:

| Field | Allowed |
|---|---|
| `token_uri` (`authorized_user`) | `https://oauth2.googleapis.com/token` (the legacy `https://accounts.google.com/o/oauth2/token` and `https://www.googleapis.com/oauth2/v4/token` are sent there instead) |
| `token_url` (`external_account`) | `https://sts.googleapis.com/v1/token` or `https://sts.<location>.rep.googleapis.com/v1/token` |
| `service_account_impersonation_url` | `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>:generateAccessToken` |

Anything else (another Google API host such as a storage upload URL, a query string, a port) is
`Configuration` before a request is sent, so a credential file from an untrusted source cannot
send refresh or subject tokens anywhere else. `credential_source.url` (the local subject-token
endpoint, e.g. a sidecar) is not restricted; what it returns only ever goes to the STS endpoint.
Treat credential files as trusted configuration all the same. With `AuthEndpoints::custom`
(tests and emulators only; a plain `http://` origin also needs `allow_loopback_http()`), the
same paths on the custom origin are the only ones allowed.

**Laziness.** Building a provider and opening keys do no I/O; credentials are resolved on the
first operation. Call `preflight()` on each handle (typed or from a registry) at
startup to fail fast on credentials, IAM and key types. Tokens are cached and refreshed 4 minutes
before they expire (the metadata server hands out its cached token until about 5 minutes are
left, so a longer lead would refetch the same token). The first operation that finds a token due
refreshes it while the others keep using it; concurrent operations without a usable token share
one fetch and its result. A failed fetch with no usable token (`Unavailable` when the metadata
server is down) is returned to every operation for 5 s, then retried. Custom sources
(`Credentials::custom`) are cached the same way, using the token's `expires_at` (a token without
one is kept until Cloud KMS rejects it), so they need no cache of their own. After a 401 the
request is retried once if the credential source yields a new token.

**Subject token files** (`external_account` with a `file` source) are re-read at every token
exchange. A missing file is `Unavailable` (a projected token being rotated); any other failure
(unreadable, over 64 KiB, not UTF-8, not JSON, no subject token field, empty) is `Configuration`,
naming the path.

## Environment

| Variable | Effect |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`, `GCE_METADATA_HOST` | ADC (read on first use) |
| `ANYKMS_GCP_ENDPOINT` | `global` (default), `regional`, or an `https://` URL (Private Service Connect, a restricted VIP) |
| `ANYKMS_GCP_QUOTA_PROJECT`, else `GOOGLE_CLOUD_QUOTA_PROJECT` | the `x-goog-user-project` header |
| `ANYKMS_GCP_ALLOWED_PROJECTS`, `ANYKMS_GCP_ALLOWED_LOCATIONS` | comma-separated allowlists (set but empty: `Configuration` at `build()`) |

`Endpoint::Regional` sends each request to `cloudkms.<location>.rep.googleapis.com` (data
residency), derived from the key's location, never from caller text; a key in `global` is refused
at open. A location without a regional endpoint fails with `Unavailable` "DNS lookup failed":
check Google's list of regional endpoints. Every request (Cloud KMS, the token endpoints, the
metadata server) goes through one HTTP transport (`GcpProviderBuilder::http_transport`, or a
default `ReqwestTransport`), which owns TLS trust, the crypto provider, proxying and timeouts.
Proxy variables (`HTTPS_PROXY`) are ignored unless a proxy is configured on the transport
(`ReqwestTransportBuilder::proxy`); the metadata server, a link-local host, is always reached
directly and with a 3 s per-request timeout. Redirects are never followed.

## Limits and quotas

- Encrypt: plaintext and AAD up to 64 KiB each (HSM keys: 8 KiB combined). MAC input up to
  64 KiB (HSM: 16 KiB). Ed25519 messages: anykms sends up to 64 KiB; Cloud KMS's limit is
  undocumented (see `research/gcp-kms.md`). Over 64 KiB is `InvalidArgument` before any request;
  lower HSM limits come back from the server as `InvalidArgument`. Encrypt bulk data with
  `EnvelopeAead`.
- Quotas are per calling project for cryptographic requests, and per region in the key's project
  for HSM (symmetric 500 QPS, asymmetric 50 QPS) and Cloud EKM (100 QPS). Exceeding one is
  `Throttled` (retryable; `retry_after` when the response says). Quotas are enforced per second,
  so bursts trip them even when the per-minute graph looks fine. Share one `RetryBudget` per
  project across handles (see the transit guide's retry budgets).

## Rotation

- **AEAD and envelope KEKs.** Automatic rotation (`rotationPeriod`) is fine: decrypt finds the
  version. Cloud KMS ciphertexts do not reveal their version (`ciphertext_version` is `None`);
  `decrypt_with_info().used_primary()` tells whether data is on the primary, the only staleness
  signal. Rotate envelopes with `EnvelopeAead::rewrap_local` (the data key is briefly in memory).
  Cloud KMS has no server-side rewrap: `rewrap` and `generate_data_key` on a GCP `AeadKey` are
  `Unsupported` before any request; use `ClientRewrap` (the plaintext passes through the client)
  and `EmulatedDataKeys` from `anykms-recipes` explicitly.
- **Signing and MAC keys.** Create a version, publish its public key
  (`jose::jwks_from_versions`), switch the URI's version, keep the old version `ENABLED` until
  its signatures or tags expire, then disable it. Signatures and tags carry their version, and
  verification uses that version of the same key (never another key). A mode that follows the
  newest enabled version is planned.

## Disabling and destroying versions

Disabling a version takes effect in Cloud KMS "usually within a minute". Local signature
verification caches public keys for `public_key_ttl` (default 60 s, ±10 % jitter, counted from
the fetch, not from the last use), so a disabled version stops verifying at most about two
minutes after the disable; a re-fetch that fails does not extend the cached key (verification
fails with the re-fetch's error). Every fetch first reads the version's state
(`cryptoKeyVersions.get`) and refuses a version that is not `ENABLED`, so a disabled version's
public key is never handed out, also if Cloud KMS would serve it; that lookup fails closed
without `cloudkms.cryptoKeyVersions.get`. A signature or `public_key_version` naming a version
that does not exist (`UnknownKeyVersion`; verifying with it is `VerificationFailed`) or that is
disabled or destroyed (`KeyVersionUnusable`) is remembered for the same TTL (up to 64 versions),
so forged versions cost at most one lookup each per TTL, and they never make the handle re-run
its key-type check. A pending version (with its retry hint) is not remembered.
`public_key_ttl(Duration::ZERO)` disables both caches. Destroying a version loses its data after
`destroyScheduledDuration` (24 h by default); restore it while it is `DESTROY_SCHEDULED`.

A disabled, destroyed or scheduled-for-destruction version fails differently by who chose it:

- **The version the handle chose** (the URI's pinned version for signing, MAC and RSA KEKs, or
  the primary version encrypt uses): `KeyStateInvalid`, a config error, for every operation,
  `public_key()` included. Re-enable the version or move the URI (or the primary) to an enabled
  one.
- **A version taken from the input** (the ciphertext's version on decrypt, a signature's or
  tag's version, `public_key_version`): `KeyVersionUnusable`, a caller error. Rewrap or re-sign
  old data before disabling.

## Protection levels

`SOFTWARE`, `HSM`, `EXTERNAL` and `EXTERNAL_VPC` AEAD keys all work. HSM keys have lower size
limits and their own quotas. Cloud EKM (`EXTERNAL*`) availability depends on the external key
manager; its failures currently surface as `Backend` (the messages are not pinned yet) or
`Unavailable`.

## Integrity

Every request carries CRC32C checksums of its inputs, and every response's checksums and
`verified*` flags are checked, as Google's data-integrity guidance requires. A mismatch discards
the response and is `Unavailable`, so a `Retry` layer retries it a bounded number of times. A
response naming another key is `Backend`.

## Runbook: `ErrorKind` → cause → action

Every GCP error names its key as `Error::resource()` (`gcp-kms://projects/…`), carries the HTTP
status and the canonical status (`BackendDetail::code`, e.g. `FAILED_PRECONDITION`), and the
request id when Cloud KMS sends one. Server messages are kept only when pinned; others are reduced
to a keyed fingerprint.

| ErrorKind | Class | Likely cause | Action |
|---|---|---|---|
| `NotFound` | config | the key, or the URI's version, does not exist (and the caller may read the key ring) | check the URI |
| `PermissionDenied` | config | missing role; key missing and the key ring not readable ("or it may not exist"); VPC Service Controls; a token endpoint denied impersonation (`iam.serviceAccountTokenCreator`); public keys without `cloudkms.cryptoKeyVersions.get` (the version-state lookup fails closed) | compare the IAM bindings with the table above |
| `Unauthenticated` | config | the token was refused after one refresh; a revoked refresh token (`invalid_grant`); a bad subject token | check the credential source, the workload identity pool and provider |
| `KeyMismatch` | config | the key's purpose or algorithm does not fit the handle (an HMAC key opened as AEAD, a P-256 key as P-384, PSS as PKCS#1, an EKM key for signing, a `RAW_ENCRYPT_DECRYPT` key, an RSA KEK version that is not OAEP-SHA-256); the server's `FAILED_PRECONDITION` "incorrect key purpose"; a URI with or without a version where the other is required | fix the URI or the algorithm in the configuration |
| `Unsupported` | config | `rewrap` or data keys on a GCP key (not native); the server answered `UNIMPLEMENTED` | use the recipes |
| `Configuration` | config | a malformed key URI (`Error::operation()` is `ParseUri`); no credentials found; an unsupported or malformed credential file (the error names the path); an unusable subject token file (unreadable, empty, malformed); an empty allowlist; `max_response_bytes` under 64 KiB; a credential file naming a token URL other than the fixed one for its field; Cloud KMS API or billing disabled, or a token without the `cloud-platform` scope (`SERVICE_DISABLED`, `BILLING_DISABLED`, `ACCESS_TOKEN_SCOPE_INSUFFICIENT`); a project or location outside the allowlists; plain-`http://` custom endpoints without `allow_loopback_http()`; a redirect; a refused TLS certificate; `Provider::pin` with a malformed version or a URI that names another version (`Error::operation()` is `Open`) | fix the environment, project setup or configured key version |
| `KeyStateInvalid` | config | the version the handle chose (its pinned version, or the primary version for encrypt) is `DISABLED`, `DESTROYED` or `DESTROY_SCHEDULED`, for every operation including `public_key()`; `PENDING_GENERATION`/`PENDING_IMPORT` (with a 2 s retry hint) | re-enable or restore the version, or move the URI (or the primary) to an enabled one |
| `KeyVersionUnusable` | caller | a version taken from the input (the ciphertext's, a signature's or tag's, `public_key_version`) is `DISABLED`, `DESTROYED`, `DESTROY_SCHEDULED` or pending (with a 2 s retry hint) | rewrap or re-sign old data before disabling |
| `UnknownKeyVersion` | caller | `public_key_version` names a version this key does not have (a forged or stale `kid`); on an RSA KEK, any version other than the pinned one (refused before any request: the handle unwraps with its pinned version only) | expected for forged input; to wrap offline to another version, open a KEK on that version |
| `DecryptFailed` | caller | wrong key or AAD; tampered or truncated ciphertext | check the AAD scheme and the key URI |
| `VerificationFailed` | caller | the signature or tag does not match, names a version of another algorithm, or names a version this key does not have | expected for forged input |
| `InvalidArgument` | caller | input over 64 KiB or over an HSM limit; a digest of the wrong algorithm; an unversioned or non-numeric signature or tag version | use `EnvelopeAead`; fix the calling code |
| `Throttled` | retryable | a quota | back off; raise the quota; spread HSM load across regions |
| `Unavailable` | retryable | `UNAVAILABLE`/`ABORTED`, a front end's 5xx, connection refused or reset, DNS; a CRC32C or integrity-flag failure; a token endpoint or the metadata server unreachable or failing; a missing subject token file | retry; check network egress to `*.googleapis.com` (or the metadata server) |
| `Timeout` | retryable | `DEADLINE_EXCEEDED`; the client's connect or request timeout | check latency; tune the transport's `connect_timeout`/`request_timeout` |
| `Backend` | config | an unclassified response (`INTERNAL`, an unpinned `FAILED_PRECONDITION` such as Cloud EKM or Key Access Justifications); an undecodable or oversized response; a response for another key | look at the fingerprint and request id; report it so the mapping can be pinned |

## Tracing

With the `tracing` feature, `anykms-gcp` emits an `anykms.gcp` span per request with the
fields every anykms HTTP backend uses: `backend` (`gcp`), `op`, `resource` (the key URI as
opened), `key_version` (the version named in the request, or for encrypt the primary that
answered), `attempt` (2 after the one 401 retry; not the retry layer's count, see
[`operations.md`](operations.md#tracing)), `http_status`, `code` (the `google.rpc.Status`
name, e.g. `FAILED_PRECONDITION`), `request_id` (`RequestInfo.requestId` of an error),
`latency_ms`, `error_kind` and `outcome` (`ok`/`error`, or `cancelled` for a call dropped
before it finished). Each token fetch gets an
`anykms.gcp.token` span (`backend`, `credential` = the credential type as a stable snake_case
label: `metadata`, `service_account`, `authorized_user`, `external_account`,
`impersonated_service_account`, `google_cloud_auth`, or `custom` for `Credentials::custom`;
`outcome`, `error_kind`, `latency_ms`, `expires_in_s`), with a `debug`
event on success and a `warn` event on failure (the error kind and the error, which names a
failed file's path). Events cover the credential source
chosen, token refreshes and failures, the 401 retry, integrity failures (field names only),
unusable responses, unclassified errors and allowlist refusals. Plaintext, AAD, tokens, keys and
bodies never appear (`tests/hygiene.rs` checks this at TRACE). Cap `reqwest` and `hyper` at INFO.

## Testing against an emulator

No official emulator exists. Community emulators can be used for a development loop with
`Endpoint::custom("http://127.0.0.1:<port>")`, `allow_loopback_http()` and
`Credentials::none()`; their error texts and checksums differ from the real service, so do not
rely on them for error handling.
