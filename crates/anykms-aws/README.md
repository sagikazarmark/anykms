# anykms-aws

[![crates.io](https://img.shields.io/crates/v/anykms-aws?style=flat-square)](https://crates.io/crates/anykms-aws)
[![docs.rs](https://img.shields.io/docsrs/anykms-aws?style=flat-square)](https://docs.rs/anykms-aws)

The AWS KMS backend: an in-house SigV4 client on `reqwest` and rustls (ring or aws-lc-rs); KMS
calls use no AWS SDK (it retries internally and brings its own HTTP and TLS stack). Symmetric
keys (`Aead`, `Rewrap`, data keys, envelope KEKs), ECDSA and RSA signing keys, Ed25519, HMAC,
RSA-OAEP key wrapping, native encryption contexts and grant tokens. Built-in credentials, resolved
lazily: the environment, static keys in shared profiles, web identity (EKS IRSA, GitHub OIDC),
ECS / EKS Pod Identity container endpoints and EC2 IMDSv2. SSO, role chaining and
`credential_process` come from the AWS SDK through the `sdk-credentials` feature.

```rust
use anykms_core::prelude::*;

let aws = anykms_aws::AwsProvider::from_env()?; // no I/O; credentials on first use
let kek = aws.aead_key("aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/app-kek")?;
let ct = kek.encrypt(b"secret", b"users/42").await?; // AAD → encryption context
```

See [docs/operations-aws.md](https://github.com/sagikazarmark/anykms/blob/main/docs/operations-aws.md)
for key policies, CloudTrail, limits, aliases and rotation, credentials and the error runbook.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management
services that keeps their differences visible. Most applications depend on the
[`anykms`](https://crates.io/crates/anykms) facade crate (feature `aws`) instead of this one.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
