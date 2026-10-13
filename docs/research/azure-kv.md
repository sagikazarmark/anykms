# Azure Key Vault and Managed HSM: verified behavior and open facts

**Probe status:** script `scripts/probe-azure.sh` (T3: key vault; T13: Managed HSM). T3 ran
against a real key vault on 2026-10-12 (baseline `scripts/probe-baseline-azure/vault.txt`, API
`2025-07-01`, westeurope); T13 has not run. Open rows: `Retry-After` on 429, the rows marked
*T13*, and all of §4 (Managed HSM). The operator guide is [`../operations-azure.md`](../operations-azure.md).

Date: 2026-10-06. API version `2025-07-01`. Sources: the REST reference and docs listed in
`docs/cloud/azure.md` §15, and runs against Lowkey Vault `7.3.112`
(`compose.yaml`, profile `azure`), and the T3 probe against real Azure (marked **T3**). Rows marked
**T13** (Managed HSM) are pinned by `scripts/probe-azure.sh record <url> --mhsm`.

Legend: **doc** = stated by Microsoft's documentation; **lowkey** = observed on Lowkey Vault (an
emulator: its behavior is not evidence about Azure); **impl** = what anykms-azure does.

## 1. Requests and responses

| Fact | Source | anykms-azure |
|---|---|---|
| Operations are `POST /keys/<name>/<version>/<op>?api-version=…`, JSON, base64url without padding | doc | as documented; decodes padded or unpadded |
| Versionless operations (`POST /keys/<name>/sign`) | swagger marks `{version}` required; auth docs show versionless calls; **T3: accepted** (200 for `sign` and `wrapkey`). lowkey: `405 Method Not Allowed` | tries versionless; after a 405 from a host, names the current version from the cached key bundle (`key_cache_ttl`) for that host's writes, reading the key again once when that version is gone or refused |
| Response `kid` is the versioned key id | doc, lowkey | must name the same host and key (case-insensitive) and, when the request named one, the same version; else `Backend` |
| Key versions are 32 lowercase hex characters | doc ("system-generated, 32 character string"; hex not stated), lowkey | parser accepts 32 hex (case-insensitive, normalized); the frame length-prefixes the version |
| ECDSA signatures are raw `r ‖ s` (64/96/132 bytes) | doc (JWS), lowkey (64 for ES256) | converted to DER; any other size is `Backend` |
| PS* salt length equals the hash length (RFC 7518) | doc implies; **T3: confirmed** (the live run verifies PS256/384/512 signatures with `LocalVerifier`, which enforces it); lowkey: verified locally | `LocalVerifier` in tests |
| `verify` returns `{"value": bool}`; a malformed signature | lowkey: `200 {"value": false}`; **T3: 200** for a valid (`true`), a wrong (`false`) and a malformed signature (body not recorded) | `false` and a 400 on verify are `VerificationFailed` |
| Server-side `verify` is not deprecated (kept "as a convenience") | doc (2025-07-01) | default; `AzureOptions::local_verify` |
| RSA-OAEP-256 input limit: modulus bytes − 66 | RFC 8017; lowkey accepts 190 bytes on RSA-2048 | checked locally (`InvalidArgument`) |
| `wrapkey` RSA-OAEP-256 output is the modulus size | doc, lowkey (342 base64url chars = 256 bytes) | checked |
| Lowkey wraps only with keys that also list `encrypt` (`does not have ENCRYPT operation assigned`) | lowkey | the Lowkey fixture creates KEKs with `encrypt`/`decrypt` too |
| `key_size` of `oct-HSM` keys is not reported by GA API versions | doc (preview only); **to verify with T13** | AES-128/192 cannot be refused before use (documented) |
| `GET /keys/<name>/versions` pages with `nextLink` (`$skiptoken`, `maxresults`) | doc, lowkey (with `maxresults`) | follows same scheme/host/path only, at most 10 pages; the link's `api-version` is replaced with the pinned one |
| Envelope v1 wrapped-key slot fits a 4096-bit RSA frame (6 + 32 + 512 = 550 bytes) | impl (u16 slot) | tested with RSA-3072 on Lowkey |

## 2. Errors

| Situation | Azure (doc / expected) | Lowkey | anykms-azure today |
|---|---|---|---|
| no or invalid token | 401 + `WWW-Authenticate: Bearer authorization="https://login…/<tenant>", resource="https://vault.azure.net"` | 401, challenge names itself (`resource="https://localhost:8443"`) | refresh once, retry once; `Unauthenticated` with a tenant hint only for Entra hosts |
| RBAC denial | 403 `Forbidden`, inner `ForbiddenByRbac` (doc) | n/a (accepts any token) | `PermissionDenied`, code chain in `BackendDetail::code` |
| firewall | 403 `Forbidden`, inner `ForbiddenByFirewall`, message with the client IP (doc) | n/a | `PermissionDenied` "network rule"; IP never kept |
| missing key | 404 `KeyNotFound` (doc) | 404 `…NotFoundException` | `NotFound` |
| missing version on verify/unwrap/decrypt | **T3:** 404 `KeyNotFound` | 404 | `VerificationFailed` / `DecryptFailed` once the key-type check saw the key; `NotFound` under `TrustCaller` |
| disabled key or version | **T3:** `GET` of the key and of the version: **200** (`attributes.enabled: false`); `sign`, `verify`: 403 `Forbidden`, inner `KeyDisabled`, "Operation sign is not allowed on a disabled key." | `GET`: 404 "Operation get is not allowed on a disabled entity"; operations: **500** `IllegalStateException` "… is not enabled" | inner `KeyDisabled`: `KeyStateInvalid` (the handle's version), `KeyVersionUnusable` (an input version); describe and preflight read the disabled key and report its state |
| key outside `nbf`/`exp` | **T3:** `GET` 200; `sign`, `wrapkey`: 403, inner `KeyNotYetValid` / `KeyExpired`; **`unwrapkey` of an expired key succeeds** | not probed | same as `KeyDisabled` |
| operation not in `key_ops` | **T3:** 403, inner `KeyOperationForbidden`, "Operation sign is not permitted on this key." | 500 `IllegalStateException` "does not have SIGN operation assigned" | caught earlier by the key-type check; the server's answer is `KeyMismatch` |
| damaged RSA-OAEP / GCM input | **T3:** 400 `BadParameter` "The parameter is incorrect." for RSA-OAEP (GCM: **T13**) | **500** `…CryptoException` "Cannot decrypt message." | 400 on unwrap/decrypt is `DecryptFailed`; Lowkey's `CryptoException` code too |
| wrong algorithm for the key (RS256 on EC, A256KW on RSA) | **T3:** 400 `BadParameter` "Key and signing algorithm are incompatible. …" / "Invalid algorithm: A256KW" (no inner code) | 400 (empty Spring body) / 500 | `InvalidArgument` (only the message would tell; messages are not used) |
| RSA-OAEP-256 input over the limit (191 bytes on RSA-2048) | **T3:** 400 `BadParameter` "The parameter is incorrect." | accepted up to 190 | refused locally first (`InvalidArgument`) |
| key being deleted/recovered | 409 `Conflict` (doc) | not probed | `KeyStateInvalid` |
| throttled | 429 `Throttled`; the live conformance run hit "Request was not processed because too many requests were received. Reason: VaultRequestTypeLimitReached" on parallel key creation; `Retry-After` **not documented** and still unverified (docs advise 1/2/4/8/16 s backoff) | n/a | `Throttled`, `retry_after()` when sent |
| 5xx | 500/503 (doc) | 500 for many emulator errors | `Unavailable` |
| redirects | none expected | none | never followed: `Configuration` |

Server messages are never kept verbatim (only a length and a keyed fingerprint). Classification
uses status and codes; no row depends on message text.

## 3. Credentials and hosts

| Fact | Source | anykms-azure |
|---|---|---|
| Token scope is `https://<suffix>/.default` (`vault.azure.net`, `managedhsm.azure.net`, sovereign suffixes) | doc; MHSM China/US Gov suffixes **unverified** | scope from the allowlisted host suffix only |
| China authority host `login.partner.microsoftonline.cn` (`login.chinacloudapi.cn` legacy) | doc | `AzureCloud::China` |
| Germany cloud retired | doc | not listed |
| IMDS: `GET 169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=…`, `Metadata: true`, `expires_on` as a string | doc | as documented; no proxy; 1 s connect timeout |
| App Service: `IDENTITY_ENDPOINT`, `X-IDENTITY-HEADER`, api `2019-08-01`, `mi_res_id` | doc | as documented |
| Workload identity: client-credentials grant with `client_assertion` from `AZURE_FEDERATED_TOKEN_FILE` | doc | file read at each exchange |
| Azure CLI `expires_on` (POSIX) since 2.54 | doc | required; without it the token counts as valid for 5 minutes |
| Lowkey accepts any bearer token; its certificate is self-signed for `localhost`, `127.0.0.1`, `*.localhost` (SAN), no CA flag; rustls accepts it as its own trust anchor | lowkey | tests trust it on first use |

## 4. Managed HSM (release B): all **to verify with T13**

| Fact | Expected | anykms-azure |
|---|---|---|
| `A256GCM` encrypt: the service generates the IV (a client IV is rejected) | doc | no IV sent |
| IV 12 bytes, tag 16 bytes | doc examples | other sizes are `Backend` |
| AAD (`aad`) optional | doc | omitted when empty |
| GCM plaintext limit | undocumented | none enforced; conformance `OversizePlaintext` n/a until measured |
| empty plaintext | unknown | allowed by the frame; conformance `EmptyPlaintext` n/a |
| `A256KW` wrap of 32 bytes yields 40 | RFC 3394 | checked |
| `HS256/384/512` `sign` input: the message, or a digest? (Q4) | unknown | `Mac` behind the experimental `mhsm-hmac` feature, sending the message; `probe-azure.sh --mhsm` imports a known HMAC key and compares with a local HMAC of the message and of its SHA-256 |
| HMAC vs AES `oct-HSM` keys told apart by `key_ops` | assumed | key-type check reads `key_ops` |
| Importing an `oct-HSM` key with a plaintext JWK `k` | assumed (probe) | used only by the probe |
| MHSM error bodies and token scope | doc for the scope | same classification as vaults |
