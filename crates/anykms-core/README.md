# anykms-core

[![crates.io](https://img.shields.io/crates/v/anykms-core?style=flat-square)](https://crates.io/crates/anykms-core)
[![docs.rs](https://img.shields.io/docsrs/anykms-core?style=flat-square)](https://docs.rs/anykms-core)

Core traits and types: the capability traits key handles implement (`Aead`, `Rewrap`,
`DataKeys`, `DigestSigner`, `MessageSigner`, `DigestVerifier`, `MessageVerifier`, `Mac`,
`PublicKeys`, `Describe`, `KeyWrap`), errors, `KeyUri`, `Provider`/`Registry` and `Retry`.
No HTTP and no async runtime. Depend on it directly to write a backend.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management services that keeps their
differences visible. Most applications depend on the [`anykms`](https://crates.io/crates/anykms)
facade crate instead of this one.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
