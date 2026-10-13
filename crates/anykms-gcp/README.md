# anykms-gcp

[![crates.io](https://img.shields.io/crates/v/anykms-gcp?style=flat-square)](https://crates.io/crates/anykms-gcp)
[![docs.rs](https://img.shields.io/docsrs/anykms-gcp?style=flat-square)](https://docs.rs/anykms-gcp)

The Google Cloud KMS backend: an in-house REST client on `reqwest` and rustls (ring or aws-lc-rs)
with in-house Application Default Credentials (metadata server, service-account keys,
authorized-user, workload identity federation, impersonation). AEAD, envelope KEKs, ECDSA/RSA/Ed25519
signing with local verification, HMAC, RSA-OAEP key wrapping, public keys and describe; CRC32C
integrity checks on every request and response. Other credential types (AWS- or executable-sourced
federation, ...) come from Google's `google-cloud-auth` through the `google-cloud-auth` feature.

```rust
use anykms_core::prelude::*;

let gcp = anykms_gcp::GcpProvider::from_env()?; // no I/O; credentials on first use
let kek = gcp.aead_key("gcp-kms://projects/my-project/locations/global/keyRings/app/cryptoKeys/kek")?;
let ct = kek.encrypt(b"secret", b"users/42").await?;
```

See [docs/operations-gcp.md](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-gcp.md)
for IAM roles, credentials, limits, rotation and the error runbook.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management
services that keeps their differences visible. Most applications depend on the
[`anykms`](https://crates.io/crates/anykms) facade crate (feature `gcp`) instead of this one.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
