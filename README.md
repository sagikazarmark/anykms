# anykms

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sagikazarmark/anykms/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/anykms/actions/workflows/ci.yaml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/anykms/badge?style=flat-square)](https://securityscorecards.dev/viewer/?uri=github.com/sagikazarmark/anykms)
[![crates.io](https://img.shields.io/crates/v/anykms?style=flat-square)](https://crates.io/crates/anykms)
[![docs.rs](https://img.shields.io/docsrs/anykms?style=flat-square)](https://docs.rs/anykms)

**One Rust interface for key-management services that keeps their differences visible.**

> [!WARNING]
> anykms has not been independently audited, and its API may change before 1.0. The envelope
> format (v1) is frozen, but its external review is pending, so it is not yet recommended for
> long-lived data. See [Guarantees and limits](https://github.com/sagikazarmark/anykms/blob/main/docs/guarantees.md).

## Features

- 🔌 **One API, many backends.** HashiCorp Vault and OpenBao transit, AWS KMS, Google Cloud KMS,
  Azure Key Vault and Managed HSM, and in-memory keys for tests.
- 🧩 **Capabilities are types.** A key handle implements exactly what its key supports, so a
  missing capability is a compile error, or a typed error before any I/O for config-driven code.
- 🔍 **Differences stay visible.** No lowest common denominator: emulation lives in explicit
  recipes, and every handle reports how its backend behaves.
- ✉️ **Envelope encryption.** Encrypt data locally under a KMS-wrapped data key, and rewrap it
  after a key rotation without touching the payload.
- ✍️ **Signing, MACs and JWTs.** Sign with KMS keys, publish a JWKS, and verify locally with the
  algorithm pinned.
- 🛡️ **Fails closed.** anykms checks what servers don't (digest lengths, key types, algorithms),
  keeps secrets out of errors and zeroizes the buffers it owns.
- 🚦 **Typed errors and retries.** One error taxonomy for every backend, with retryable, config
  and caller classes, and a retry layer with a shared budget.
- ✅ **Conformance-tested.** Every backend, third-party ones included, runs the same suite.
- 🧪 **Testable.** In-memory keys with rotation and fault injection.

| Backend | Feature | Key URI |
|---|---|---|
| Vault and OpenBao transit | `transit` | `hashivault:///transit/keys/app-kek` |
| AWS KMS | `aws` | `aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/app-kek` |
| Google Cloud KMS | `gcp` | `gcp-kms://projects/p/locations/global/keyRings/r/cryptoKeys/k` |
| Azure Key Vault and Managed HSM | `azure` | `azure-kv://my-vault.vault.azure.net/keys/app-kek` |
| In-memory keys (tests only) | `local` | `local://default/app-kek` |

The full key URI syntax is in the [guide](https://github.com/sagikazarmark/anykms/blob/main/docs/guide.md#key-uris).

## Quick start

Start without a server, on in-memory keys:

```toml
[dependencies]
anykms = { version = "0.1", features = ["local"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use anykms::local::{LocalKeyset, LocalProvider};
use anykms::prelude::*;
use anykms::recipes::EnvelopeAead;
use anykms::Registry;

#[tokio::main]
async fn main() -> anykms::Result<()> {
    // In-memory keys that vanish with the process: development and tests only.
    let keyset = LocalKeyset::builder().aead("app-kek").build();
    let registry = Registry::builder()
        .provider(LocalProvider::new(keyset).allow_ephemeral_local_keys()) // explicit opt-in
        .build()?;

    let kek = registry.key_wrap("local://default/app-kek")?; // the envelope's key-wrapping key
    let envelope = EnvelopeAead::new("app-kek", kek)?;
    let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
    assert_eq!(&*envelope.decrypt(&ct, b"users/42/ssn").await?, b"123-45-6789");
    Ok(())
}
```

Moving to a real KMS changes only how the registry is built and which URI is opened; code that
uses the key stays the same.

### With Vault or OpenBao

```toml
[dependencies]
anykms = { version = "0.1", features = ["transit"] }
```

```rust
use anykms::prelude::*;
use anykms::recipes::EnvelopeAead;

// VAULT_ADDR, VAULT_TOKEN / VAULT_TOKEN_FILE / ~/.vault-token, VAULT_NAMESPACE, VAULT_CACERT or
// VAULT_CAPATH, ... (or the BAO_* equivalents). A missing token source is an error. In
// Kubernetes, ANYKMS_TRANSIT_AUTH=kubernetes and ANYKMS_TRANSIT_AUTH_ROLE=<role> log in and
// renew the token.
let registry = anykms::with_default_providers()?
    .layer(anykms::retry_layer()) // every handle retries transient failures
    .build()?;
// A key-wrapping key: transit AEAD keys wrap data keys by encrypting them with empty AAD.
let kek = registry.key_wrap("hashivault:///transit-envelope/keys/app-kek")?;

// Field encryption: the KMS wraps a per-message data key; the payload never leaves the process.
let envelope = EnvelopeAead::new("app-kek", kek)?;
let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
let pt = envelope.decrypt(&ct, b"users/42/ssn").await?;

// After rotating the KEK: move the data key to the new version, payload untouched.
let ct = envelope.rewrap(&ct).await?;
```

Retries, startup checks, typed handles and the rest are in the [guide](https://github.com/sagikazarmark/anykms/blob/main/docs/guide.md).

### With a cloud KMS

```toml
[dependencies]
anykms = { version = "0.1", features = ["aws", "gcp", "azure"] } # any subset
```

```rust
use anykms::prelude::*;
use anykms::recipes::EnvelopeAead;
use anykms::SignatureAlgorithm;

// Every cloud provider whose feature is on is registered; credentials are resolved from the
// environment on the first operation (AWS credential chain, Application Default Credentials,
// Entra ID workload or managed identity).
let registry = anykms::with_default_providers()?.layer(anykms::retry_layer()).build()?;

let kek = registry.key_wrap("aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/app-kek")?;
let envelope = EnvelopeAead::new("app-kek", kek)?;

// GCP signing keys name their version; Azure keys are addressed by vault host.
let alg = SignatureAlgorithm::EcdsaP256Sha256;
let signer = registry.digest_signer(
    "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/jwt/cryptoKeyVersions/1",
    alg,
)?;
let azure_kek = registry.key_wrap("azure-kv://my-vault.vault.azure.net/keys/app-kek")?;
```

Permissions, credentials, environment variables, limits and a runbook per cloud are in the
operator guides: [AWS](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-aws.md), [GCP](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-gcp.md),
[Azure](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-azure.md).

### Examples

Runnable examples on local keys (add `--features local,transit` and set `VAULT_ADDR` and
`ANYKMS_*_URI` to use Vault):

```sh
cargo run -p anykms --features local --example field_encryption  # envelope encryption of fields
cargo run -p anykms --features local --example jwt_signing       # JWTs and a JWKS
cargo run -p anykms --features local --example jwt_signing_jwt_simple
cargo run -p anykms --features local --example hmac_tokens       # HMAC tokens
# against Vault only (VAULT_ADDR, VAULT_TOKEN): the built-in client under a tower concurrency limit
cargo run -p anykms --features transit,tower --example tower_transport
```

## Documentation

- [Guide](https://github.com/sagikazarmark/anykms/blob/main/docs/guide.md): registries and providers, retries, typed handles, startup checks, key
  URIs, synchronous code, ciphertexts as text, JWTs and signatures, generic code.
- [Errors](https://github.com/sagikazarmark/anykms/blob/main/docs/errors.md): the error taxonomy and classes, and mapping errors to HTTP responses.
- [Testing your application](https://github.com/sagikazarmark/anykms/blob/main/docs/testing.md): in-memory keys, fault injection, hand-written fakes.
- [What differs between backends](https://github.com/sagikazarmark/anykms/blob/main/docs/backends.md): per-backend behavior and how anykms shows it.
- [Crates and Cargo features](https://github.com/sagikazarmark/anykms/blob/main/docs/features.md): the crates, features, build requirements and
  public dependencies.
- [Guarantees and limits](https://github.com/sagikazarmark/anykms/blob/main/docs/guarantees.md): zeroization, transport, FIPS scope, size limits,
  MSRV, runtimes.
- Operator guides: [Vault and OpenBao](https://github.com/sagikazarmark/anykms/blob/main/docs/operations.md), [AWS](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-aws.md),
  [GCP](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-gcp.md), [Azure](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-azure.md). Policies, credentials, TLS,
  quotas, and a runbook mapping each error to a cause and an action.
- Formats: [envelope](https://github.com/sagikazarmark/anykms/blob/main/docs/envelope-format.md), [Azure ciphertext frame](https://github.com/sagikazarmark/anykms/blob/main/docs/azure-ciphertext.md).
- [Glossary](https://github.com/sagikazarmark/anykms/blob/main/docs/glossary.md), [API reference](https://docs.rs/anykms).
- Design: [plan, decisions and review history](https://github.com/sagikazarmark/anykms/blob/main/docs/PLAN.md),
  [verified transit server behavior](https://github.com/sagikazarmark/anykms/blob/main/docs/research/vault-openbao-transit.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/sagikazarmark/anykms/blob/main/LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/sagikazarmark/anykms/blob/main/LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
