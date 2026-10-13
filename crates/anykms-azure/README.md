# anykms-azure

[![crates.io](https://img.shields.io/crates/v/anykms-azure?style=flat-square)](https://crates.io/crates/anykms-azure)
[![docs.rs](https://img.shields.io/docsrs/anykms-azure?style=flat-square)](https://docs.rs/anykms-azure)

The Azure Key Vault and Managed HSM backend: an in-house REST client on `reqwest` and rustls
(ring or aws-lc-rs); Key Vault calls use no Azure SDK. RSA and EC keys (digest signing, server-side or
local verification, public keys), RSA-OAEP-256 key wrapping for envelope KEKs and data keys over
it, and on Managed HSM `oct-HSM` keys AES-GCM `Aead` and `A256KW` wrapping (HMAC behind the
experimental `mhsm-hmac` feature). Bearer tokens go only to an allowlisted vault host. Credentials
are resolved lazily: workload identity, managed identity, client secret, any `azure_identity`
credential (the Azure CLI, certificates, ...) through the `azure-identity` feature, or your own
`AzureCredential`.

```rust
use anykms_core::prelude::*;

let azure = anykms_azure::AzureProvider::from_env()?; // no I/O; credentials on first use
let kek = azure.key_wrap_key("azure-kv://contoso-prod.vault.azure.net/keys/app-kek")?;
let wrapped = kek.wrap_key(&[7u8; 32]).await?; // RSA-OAEP-256, framed with the key version
```

See [docs/operations-azure.md](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-azure.md)
for keys, RBAC roles, credentials, limits, rotation and versions and the error runbook, and
[docs/azure-ciphertext.md](https://github.com/sagikazarmark/anykms/blob/main/docs/azure-ciphertext.md)
for the ciphertext frame.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management
services that keeps their differences visible. Most applications depend on the
[`anykms`](https://crates.io/crates/anykms) facade crate (feature `azure`) instead of this one.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
