# anykms-http

[![crates.io](https://img.shields.io/crates/v/anykms-http?style=flat-square)](https://crates.io/crates/anykms-http)
[![docs.rs](https://img.shields.io/docsrs/anykms-http?style=flat-square)](https://docs.rs/anykms-http)

HTTP plumbing shared by the anykms backends (transit and the cloud backends): rustls crypto
provider selection, a no-redirect reqwest client with timeouts, zeroizing request and response
buffers, `Retry-After` parsing, transport-error classification, a single-flight credential
cache and single flight for metadata caches.

**Its API is for anykms backends only.** It is versioned in lockstep with the other anykms crates
and follows the same semver rules, which CI checks: a breaking change comes only in a `0.(x+1)`
release, never a patch, but it can come in any such release without further notice. Applications
depend on the [`anykms`](https://crates.io/crates/anykms) facade or a backend crate instead.

Part of [anykms](https://github.com/sagikazarmark/anykms): one Rust interface for key-management
services that keeps their differences visible.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
