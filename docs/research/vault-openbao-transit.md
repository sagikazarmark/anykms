# Vault vs. OpenBao transit: verified behavior and client-crate evaluation

Date: 2026-10-03. Servers: `hashicorp/vault:2.1.1` and `openbao/openbao:2.7.1`
(dev mode, `compose.yaml`). Earlier runs on Vault 1.20.4 / OpenBao 2.4.4 noted
where they differ. Reproduce with `scripts/probe-transit.sh http://127.0.0.1:8200`
(Vault) and `... 8300` (OpenBao).

## 1. Transit semantics (raw HTTP)

| Behavior | Vault 2.1.1 | OpenBao 2.7.1 | Consequence for anykms |
|---|---|---|---|
| `encrypt`/`decrypt` with `associated_data` (aes256-gcm96, chacha20-poly1305) | ✅ enforced | ✅ enforced | Native `Aead` on both. |
| Wrong / missing AAD, tampered ciphertext | `400 ["cipher: message authentication failed"]` | same | Map to `DecryptFailed`. Must classify by message string; status alone is ambiguous. |
| `datakey/plaintext` with `associated_data` | **ignored**: warning `Endpoint ignored these unrecognized parameters: [associated_data]`, ciphertext *not* bound to AAD | **honored** (since 2.5): ciphertext bound, decrypt without AAD fails | AAD on `DataKeys` is flavor-dependent. Vault must not silently drop it: **any "ignored parameters" warning is a hard error**. |
| `datakey/wrapped` | ✅ | ✅ | Use `wrapped` when caller only needs ciphertext. |
| Encrypt to a nonexistent key | **auto-creates the key (upsert)**, 200 | same | Footgun. Document `disable_upsert` (`transit/config/keys`, works on both) and not granting `create` capability. |
| Decrypt with nonexistent key | `400 ["encryption key not found"]` | same | `NotFound` (but 400, not 404). |
| Decrypt version below `min_decryption_version` | `400 ["ciphertext or signature version is disallowed by policy (too old)"]` | same | `KeyStateInvalid` (version-level). |
| Ciphertext garbage / unknown version | `400 ["invalid ciphertext: no prefix"]` / `["invalid ciphertext: version is too new"]` | same | Both `DecryptFailed`. Ciphertext does **not** identify the key: decrypting key A's ciphertext with key B yields "version is too new" or an auth failure. |
| Disabled / soft-deleted key | no such state; `soft-delete` path is `404 unsupported path` | `DELETE keys/:name/soft-delete` → ops fail with `400 ["refusing to use soft-deleted key"]`; `soft-delete-restore` | `KeyStateInvalid` is reachable only on OpenBao; conformance test is capability-gated. |
| Rotation, decrypt old versions | ✅ `vault:vN:` prefix carries version | same | Native versioned ciphertext. |
| Encrypt with explicit old `key_version` | ✅ | ✅ | Not exposed in v1. |
| Derived keys without `context` | `400 missing 'context'` | same | v1 refuses derived keys (detected via `describe`). |
| Large plaintext (2 MB → ~2.7 MB base64) | **500** `JSON string value exceeds allowed length` | 200 | Size limits differ; recommend `EnvelopeAead` for anything non-trivial. Map 500-with-this-message to `InvalidArgument`. |
| ECDSA sign `prehashed=true` + `hash_algorithm` | ✅ (ASN.1 DER default; `marshaling_algorithm=jws` gives raw r‖s) | same | Sign a digest. Signature encoding must be explicit. |
| ECDSA P-256 with `hash_algorithm=sha2-384` but 32-byte input | **accepted** | **accepted** | Server does not validate digest length; anykms must validate `Digest` locally. |
| RSA sign `pss` / `pkcs1v15` prehashed | ✅ | ✅ | Padding must be part of the algorithm id. |
| Ed25519 `prehashed=true` | **rejected**: `only Pure Ed25519 signatures supported` | **silently ignored**: produces a pure Ed25519 signature over the given bytes | Ed25519 is message-signing only. anykms must never send `prehashed` for Ed25519 and must not offer a digest-signing path for it. |
| Verify | ✅ `{"valid":bool}` (200 even when invalid) | same | Invalid signature is `Ok(false)` from the server, mapped to `Err(VerificationFailed)`. |
| HMAC + verify | ✅ (any key with symmetric material, incl. AES keys); Vault 2.x requires `key_size` when creating `hmac` keys | same | `Mac` only on `hmac` keys. |
| CMAC | 404 (Enterprise) | 404 | Not supported. |
| Random bytes (`transit/random`, `sys/tools/random`) | ✅ | ✅ | `Random` capability on the backend, not on a key. |
| Public key | `GET transit/keys/:name` → `keys.N.public_key`: PEM SPKI for ECDSA/RSA, but **raw base64 (32 bytes) for Ed25519**; Vault 2.x adds `hybrid_public_key`; `export/public-key/:name` | same minus `hybrid_public_key` | Parse PEM SPKI; wrap Ed25519 raw keys in SPKI. |
| ML-DSA / PQC | Enterprise only | unknown key type | Out of scope. |
| Rate-limit quota | 429 `rate limit quota exceeded`. `Retry-After` only if `sys/quotas/config enable_rate_limit_response_headers=true`; then Vault sends `1` | same, but OpenBao sends **`Retry-After: 0`** | `Throttled`, retryable. Treat `Retry-After` as a minimum, clamped to [base backoff, cap]. |
| Sealed server | `503 ["Vault is sealed"]` | same | `Unavailable`. |
| `X-Vault-Namespace` on a CE server | **silently ignored**: request served from the root namespace | `404 ["namespace not found"]` for unknown namespaces | Namespace comes from trusted config. "namespace not found" → configuration error, not `NotFound`. |
| `rewrap` with `associated_data` | **ignored without a warning**: AAD-bound ciphertexts fail with `cipher: message authentication failed` | same | Server-side rewrap only works for AAD-less ciphertexts. `EnvelopeAead` wraps DEKs with **empty** AAD so they can be rewrapped. |
| `context` on a non-derived key | ignored, no warning | same | Warning-based fail-closed detection only catches *unknown* field names. Send only the parameters each operation needs. |
| Empty `associated_data` | same as omitting it, both ways | same | Existing AAD-less Vault ciphertexts decrypt through `Aead` with `aad = b""`. |
| RSA-PSS `salt_length` | default/`auto` signs with the **maximum** salt (222 B for RSA-2048/SHA-256); `hash` signs with the hash length; verify with `auto` accepts any salt | same | Always send `salt_length=hash` on sign and verify. |
| Mismatched key type on `sign` | a P-384 key signs a "P-256/SHA-256" request; an ECDSA key ignores `signature_algorithm=pss`; no warning | same | Handles check the key type against the asserted algorithm (cached `describe`). |
| `encrypt`/`datakey` on an RSA key | succeeds with empty AAD (RSA-OAEP); non-empty AAD fails `provided for non-AEAD cipher suite` | same | `Aead` only on aes128/256-gcm96 and chacha20-poly1305 keys. |
| HMAC algorithm | chosen per request (`hmac/:name/:alg`): sha1, sha2-*, sha3-*. Not tied to the key; full-length tags only | same | `Mac::algorithm()` on transit is caller-asserted. |
| `sign` response | `signature` + `key_version` | same | `Signature` carries the key version; transit adds or strips the `vault:vN:` prefix. |
| Encrypt to a missing key with only `update` capability (no `create`) | 403, **even with `disable_upsert=true`** (the existence check demands `create` before the handler runs) | same | `PermissionDenied`. The 400 "encryption key not found" only reaches tokens that hold `create`. anykms's default key-type check reads `keys/<name>` first, so callers see `NotFound`. |
| Redirects | standby nodes can answer 307 without `X-Vault-Forward` | | The client never follows redirects; 3xx → `Unavailable`. |
| Bad token | 403 (`permission denied` / `invalid token`) | 403 | `PermissionDenied`. |
| Server flavor | `/sys/health`: `version`, `enterprise` field, `build_date` in seal-status | `version`, no `enterprise`, `commit_date` | **Version numbers collide** (Vault 2.1.1 vs OpenBao 2.1.1). Never infer features from version alone; flavor comes from config (URI scheme). |

## 2. Client crates

Prototype: one binary running the same operations through each crate against
both servers.

### `vaultrs` 0.8.0 (MIT, ~12M downloads, last release 2026-03)

- Works against **both** Vault 2.1.1 and OpenBao 2.7.1 for every op tested.
- Errors keep status and server messages
  (`APIError { code: 400, errors: ["cipher: message authentication failed"] }`).
- Plaintext types are plain `String` (decrypt response, datakey response), so no
  zeroization control.
- Response `warnings` are **logged and discarded**, so the ignored-`associated_data`
  case cannot be detected through its API.
- Pulls `rustify`, `rustify_derive`, `derive_builder`, `async-trait`; MIT-only.
- Has auth helpers (AppRole, Kubernetes, cert, OIDC, userpass, AWS).

### `openbao` 2.2.2 (MIT/Apache, ~2.7k downloads, first release 2026, many releases per month)

- Refuses plain HTTP unless the `sensitive-http-test-only(-acknowledged)` features
  are enabled.
- **Drops server error messages** (`Api { status: 400, errors: [] }`), so AAD
  failure vs. missing key are indistinguishable.
- **`read_key` fails to decode asymmetric keys** on both servers
  (`Decode("OpenBao response did not match expected schema")`), which breaks
  `describe` and `public_key`.
- Version-based compatibility checks "verify" Vault 2.1.1 as OpenBao 2.1.1 (version
  collision) and reject Vault 1.20.4.
- ~93k lines, very large feature matrix, fast churn; MSRV 1.90.
- Nice ideas worth copying: secret-aware request/response types, HTTPS-by-default.

### Decision

Neither crate is a good dependency for the transit data plane. `openbao` is
disqualified (no error messages, broken asymmetric `read_key`). `vaultrs` works
but hides warnings and cannot keep plaintext out of plain `String`s.

The transit data plane anykms needs is about ten endpoints with a stable JSON
shape shared by both servers. **anykms-vault implements its own thin client**
on `reqwest` (rustls) + `serde_json`, which gives:

- fail-closed handling of `warnings`,
- full error bodies for classification,
- `Zeroizing` buffers for request/response plaintext (best effort; see the plan),
- no extra HTTP stack beyond `reqwest`.

Authentication is behind a `TokenSource` trait. Static token and token file
(Vault/Bao Agent sink) ship first. Login methods come later and may use
`vaultrs::auth` behind an optional feature if that proves cheaper than writing
them.
