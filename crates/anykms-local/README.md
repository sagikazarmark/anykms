# anykms-local

[![crates.io](https://img.shields.io/crates/v/anykms-local?style=flat-square)](https://crates.io/crates/anykms-local)
[![docs.rs](https://img.shields.io/docsrs/anykms-local?style=flat-square)](https://docs.rs/anykms-local)

An in-process software backend with in-memory keys, rotation and fault injection. **For tests and
development only**: keys vanish with the process, and opening them through a provider needs an
explicit opt-in.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management services that keeps their
differences visible. Most applications depend on the [`anykms`](https://crates.io/crates/anykms)
facade crate instead of this one.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
