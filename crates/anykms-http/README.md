# anykms-http

[![crates.io](https://img.shields.io/crates/v/anykms-http?style=flat-square)](https://crates.io/crates/anykms-http)
[![docs.rs](https://img.shields.io/docsrs/anykms-http?style=flat-square)](https://docs.rs/anykms-http)

HTTP plumbing shared by the anykms backends (transit and the cloud backends): the
`HttpTransport` seam every backend sends through (an object-safe trait over `http` types, with
bounded zeroizing bodies and a fixed set of failure classes), the built-in `ReqwestTransport`
(feature `reqwest`: reqwest over rustls, no redirects, with TLS trust, client certificates, the
crypto provider, proxying, timeouts and the HTTP version as its settings), `TowerTransport`
(feature `tower`: any tower `Service` as a transport, for a tower stack around the built-in client
or a `fetch`-based service on Cloudflare Workers), rustls crypto provider selection,
`Retry-After` parsing, a single-flight credential cache and single flight for metadata caches.

**An application touches this crate only to build a `ReqwestTransport` or a `TowerTransport`, or
to bring its own `HttpTransport`; the rest of the API is for anykms backends.** It is versioned in
lockstep with the other anykms crates
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
