# anykms-transit

[![crates.io](https://img.shields.io/crates/v/anykms-transit?style=flat-square)](https://crates.io/crates/anykms-transit)
[![docs.rs](https://img.shields.io/docsrs/anykms-transit?style=flat-square)](https://docs.rs/anykms-transit)

The HashiCorp Vault and OpenBao transit backend: an in-house client over the `HttpTransport` seam (built in: `reqwest` and rustls, ring or
aws-lc-rs), with token, Kubernetes and JWT auth. See
[docs/operations.md](https://github.com/sagikazarmark/anykms/blob/main/docs/operations.md) for policies, TLS, tokens and the error
runbook.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management services that keeps their
differences visible. Most applications depend on the [`anykms`](https://crates.io/crates/anykms)
facade crate instead of this one.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
