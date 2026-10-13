# What differs between backends

anykms does not hide what a KMS does differently. This page lists the differences and how
anykms shows each one: a typed error, a check before any I/O, or a documented recipe.

## Vault and OpenBao transit

| Behavior | Vault transit | OpenBao transit | anykms |
|---|---|---|---|
| Data keys bound to AAD | ignored by the server | bound (≥ 2.5) | Vault: `Unsupported` before any I/O; use `EmulatedDataKeys` |
| Rewrap with AAD | ignored by the server | ignored by the server | `Unsupported`; envelopes wrap with empty AAD so rewrap works |
| Ed25519 `prehashed` | rejected | silently signs the digest as a message | Ed25519 is `MessageSigner` only |
| Disabled / soft-deleted keys | none | soft-delete | `KeyStateInvalid` |
| Data below `min_decryption_version` | refused | refused | `KeyVersionUnusable` (a caller error: the data is old, the key is fine) |
| Wrong key type for an operation | not detected | not detected | key-type check before first use |
| RSA-PSS salt | max by default | max by default | always `salt_length=hash` |
| Request size | 2 MB of plaintext already fails (JSON string length limit) | `max_request_size` (32 MiB by default; 33 MiB fails) | `InvalidArgument`; use `EnvelopeAead` for bulk data |
| Encrypt to a missing key | creates it (upsert) | creates it (upsert) | docs: set `disable_upsert`, never grant `create` |

## Cloud backends

| Behavior | AWS KMS | Google Cloud KMS | Azure Key Vault / Managed HSM |
|---|---|---|---|
| `Aead` | symmetric keys; AAD becomes Tink's encryption context `{"associatedData": hex}` | `ENCRYPT_DECRYPT` keys; `decrypt_with_info` reports `used_primary` | Managed HSM AES-256-GCM only; standard vaults have no `Aead` |
| Envelope KEKs (`key_wrap`) | symmetric keys; RSA-OAEP-SHA-256 keys wrap locally | AEAD keys; RSA-OAEP-SHA-256 `asymmetricDecrypt` versions wrap locally | RSA-OAEP-256; Managed HSM `A256KW` |
| `Rewrap` | native (`ReEncrypt`) | `Unsupported` (client-side recipe) | `Unsupported` |
| Data keys | native, also wrapped-only | `Unsupported`; use `EmulatedDataKeys` | standard vaults: `KeyWrapDataKeys` through `Provider::data_keys` (no AAD) |
| Signature verification | by the server | locally (`LocalVerifier`, no verify API) | by the server; local optional |
| Key versions | the key ARN | `1`, `2`, ...; signing and MAC URIs must name one | 32 hex characters |
| Unversioned signature or tag | verifies with the handle's key | `InvalidArgument` | `InvalidArgument` |
| Response integrity | TLS | TLS plus CRC32C on every request and response | TLS |
| HMAC | native | native (`macVerify` on the server) | Managed HSM only, experimental (`mhsm-hmac`) |
| Disabled key's public key | refused (checked with `DescribeKey`) | refused (version state) | refused |
| Public key of a KEK (`KeyWrapKey::public_key`) | RSA KEKs | RSA KEKs | RSA KEKs (offline wraps must be framed, `anykms_azure::framing`) |

## Reading the differences in code

Code does not have to hard-code these tables: every handle reports what it does where backends
differ through `semantics()` (`KeySemantics`: version model and shape, whether ciphertexts reveal
their version, server or local verification and its revocation lag, data-key source and AAD
binding, size limits). For example, `EnvelopeAead` users can read `max_plaintext()`, and a
verifier can check `verification()` before relying on revocation. `preflight()` runs the
backend's own key-type and state check at startup and returns the key's metadata, with the
backend's own struct attached (`info.backend_info::<AwsKeyInfo>()`).

Custom layers (metrics, auth, audit) implement `Around` once and decorate every part with
`part.wrap_around(cx, around)`: each operation arrives as a `Call` with its part, operation and
method name.

## Emulated behavior

Emulated behavior is always explicit: [`EnvelopeAead`](../crates/anykms-recipes/src/envelope.rs)
(local payload encryption with key commitment; the KMS wraps only the data key),
[`EmulatedDataKeys`](../crates/anykms-recipes/src/datakeys.rs) (locally generated data keys),
[`LocalVerifier`/`CachedVerifier`](../crates/anykms-recipes/src/verify.rs) (local verification,
pinned to one algorithm) and [`jose`](../crates/anykms-recipes/src/jose.rs) (JWK, JWKS, JWS and JWT
formats; the KMS still signs).
