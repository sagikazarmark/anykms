> **Note.** These are the original design notes that `docs/PLAN.md` started from. The committed
> copy was truncated mid-sentence in several places; this version reconstructs the missing words
> from context and from how the plan interpreted them, without adding new design. Where the two
> differ, `docs/PLAN.md` (and the code) are authoritative: for example, the plan splits `Signer`
> into `DigestSigner`/`MessageSigner`, uses server aliases as the URI authority, renames
> `kms-envelope`/`kms-vault` to `anykms-recipes`/`anykms-transit`, and never reframes native
> ciphertexts.

I'd structure it as a set of capability traits on a key handle, with portable recipes in a
separate layer, a conformance test suite, and the data plane separated from key management. The
main risk is the lowest-common-denominator trap: the four providers differ more than their
marketing suggests, so the abstraction has to make those differences visible rather than hide
them.

## What the providers actually share

This table is from memory, so verify each cell before building on it.

| Operation | AWS KMS | GCP KMS | Azure Key Vault | Vault transit |
|---|---|---|---|---|
| Symmetric encrypt/decrypt with AAD | ✅ | ✅ | ⚠️ AES on Managed HSM only, otherwise RSA | ✅ |
| Generate data key | ✅ | ❌ | ❌ | ✅ (no AAD) |
| Asymmetric sign | ✅ | ✅ | ✅ | ✅ |
| Verify | ✅ | ❌ local check with the public key | ✅ | ✅ |
| MAC | ✅ | ✅ | ❌ (as far as I know) | ✅ |
| Get public key | ✅ | ✅ | ✅ | ✅ |
| Random bytes | ✅ | ✅ | Managed HSM only | ✅ |

So encrypt/decrypt, data keys, sign/verify and MAC are each missing somewhere. That rules out a
single fat `Kms` trait.

## Design

### 1. Capability traits on a key handle

Not one trait for the whole service, but small traits on a handle for one key. You get a handle
for one key, and it implements only the operations that key supports:

```rust
pub trait Aead {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext>;
    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}
pub trait DataKeys   { async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey>; }
pub trait Signer     { fn algorithm(&self) -> SignatureAlgorithm; async fn sign(&self, digest: &Digest) -> Result<Signature>; }
pub trait Verifier   { async fn verify(&self, digest: &Digest, sig: &Signature) -> Result<()>; }
pub trait Mac        { async fn mac(&self, data: &[u8]) -> Result<Tag>; async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()>; }
pub trait PublicKeys { async fn public_key(&self) -> Result<PublicKey>; }
pub trait Describe   { async fn describe(&self) -> Result<KeyInfo>; } // spec, state, versions
```

With a provider known at compile time, a missing capability is a compile error. For keys
selected from config, there's a dynamic handle that either returns `Error::Unsupported`, or
offers a capability query such as `as_signer() -> Option<&dyn Signer>`.

### 2. Precise provider-level semantics in the core, portable recipes in a layer above

This is the key decision. The core exposes only what the provider natively does. Uniform behavior
across providers lives in a separate recipes crate, and each recipe's docs say what it emulates:

- `EnvelopeAead` (as in Tink's `KmsEnvelopeAead`): generate a data key locally, encrypt locally
  with AAD, have the KMS wrap only the key. It works on every provider with no size limits, and
  enforces AAD even where the KMS cannot.
- `DataKeys` emulation: local random bytes plus `Aead::encrypt`, for GCP and Azure.
- `Verifier` from `PublicKeys`: local verification. GCP needs this, and it's cheaper everywhere.

Without this split, emulated behavior gets mistaken for KMS-enforced behavior.

### 3. Sign a digest, not a message

AWS accepts either, GCP and Azure want a digest, and AWS caps raw messages at 4 KiB. So hash
locally, and pass a `Digest { alg, bytes }`.

### 4. Address keys by URI

Use URIs in the style of Tink and gocloud.dev: `aws-kms://arn:…`,
`gcp-kms://projects/…/cryptoKeys/…`, `azure-kv://….vault.azure.net/keys/…`,
`hashivault://transit/keys/…`. A registry gated by cargo features resolves the URI to a provider,
so deployments choose the provider through configuration, not code.

### 5. Decryption must work from the ciphertext alone

AWS, GCP and Vault (`vault:vN:`) record the key version inside their ciphertext. Azure returns it
separately, so the Azure provider must frame the version into the ciphertext itself. That is a
deliberate interop cost: other Azure tools won't read those blobs directly. Document it.

### 6. One error taxonomy with retryability

`NotFound`, `PermissionDenied`, `KeyStateInvalid` (disabled or pending deletion),
`DecryptFailed` (wrong key, wrong ciphertext or AAD, with no detail leaked), `InvalidArgument`,
`Throttled`, `Unavailable`, `Unsupported`, plus `Provider(source)`. Add `is_retryable()`:
retry behavior is the first thing production callers run into.

### 7. Treat secret values properly

Plaintext goes in as `&[u8]` and comes out as `Zeroizing`/`SecretBox`. Data-key plaintext is
zeroized on drop, and secrets in errors are redacted.

### 8. Async, runtime-agnostic, using native async traits

Async fn in traits isn't dyn-compatible. Use `trait_variant` for `Send` bounds, plus a
boxed-future erased layer for the registry. The core shouldn't depend on tokio; providers will
pull it in through their SDKs anyway.

### 9. Cross-cutting concerns as wrappers

Retries with backoff, timeouts, tracing and metrics, and caching (public keys, optionally) go in
decorator types that implement the same traits. `tower` is possible, but heavy for this.

### 10. Data plane first, key management minimal or never

Applications need encrypt, sign and describe. Creating keys, policies and grants is
infrastructure-as-code territory (Terraform), and access-control models don't map across
providers at all. I'd ship the data plane plus read-only describe, maybe add a small
`KeyLifecycle` trait (rotate, enable, disable, schedule_deletion, cancel_deletion) behind its own
permission-scoped handle, and leave everything else to IaC.

### 11. A conformance suite is what makes it real

It's one shared set of tests that every provider crate runs:

- AAD mismatch fails;
- decrypt after rotation works;
- a disabled key gives `KeyStateInvalid`;
- throttled calls report as retryable.

Run it against LocalStack (AWS), a Vault dev server, and real accounts for GCP and Azure, which
have no official emulators. Also ship a software provider that passes the same suite, for tests
and development. The suite is the abstraction's real value; the trait definitions are the easy
part.

## Crate layout

```text
kms-core         traits, types, errors, URI, registry      (no SDK deps)
kms-envelope     portable recipes: EnvelopeAead, data-key emulation, local verify
kms-local        software keys
kms-aws | kms-gcp | kms-azure | kms-vault        one per SDK
kms-conformance  shared test suite (dev-dependency of each provider)
kms              facade: re-exports + feature-gated registry
```

## How CryptBox would use it

`cryptbox-kms` would depend only on `kms-core` (and possibly `kms-envelope`). The `Kek` trait from
the earlier design disappears: it becomes `Aead` with AAD, and `EnvelopeAead` is the two-level
wrapping. The dependency points one way, and the CryptBox core never sees it.

## Be honest about the cost

You'd be taking on four SDKs' churn. GCP's and Azure's Rust SDKs are younger and move faster than
AWS's. If you build it, keep the trait set small (`Aead`, `DataKeys`, `Signer`/`Verifier`,
`PublicKeys` and `Describe`), ship AWS, Vault and local first, and write the conformance suite
before the second provider. If the only consumer is CryptBox, ~100 lines per provider inside
`cryptbox-kms` is far cheaper, and you could extract it later if other uses appear.
