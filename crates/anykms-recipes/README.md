# anykms-recipes

[![crates.io](https://img.shields.io/crates/v/anykms-recipes?style=flat-square)](https://crates.io/crates/anykms-recipes)
[![docs.rs](https://img.shields.io/docsrs/anykms-recipes?style=flat-square)](https://docs.rs/anykms-recipes)

Portable recipes over anykms key handles: envelope encryption (`EnvelopeAead`,
`EnvelopeKeyring`), emulated data keys, local signature verification (`LocalVerifier`,
`CachedVerifier`) and JOSE signing and JWKS. Each recipe documents what the KMS enforces and
what runs in this process. The envelope format is specified in
[docs/envelope-format.md](https://github.com/sagikazarmark/anykms/blob/main/docs/envelope-format.md).

**Envelope status:** format v1 is frozen and always decrypts; its external review is pending, so
it is not yet recommended for long-lived data. The release that completes the review announces
the promotion in its release notes.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management services that keeps their
differences visible. Most applications depend on the [`anykms`](https://crates.io/crates/anykms)
facade crate instead of this one.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
