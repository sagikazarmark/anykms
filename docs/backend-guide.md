# Writing a backend

How to implement an anykms backend for a key-management service, in this repository or in a crate
of your own, and prove it with the conformance suite. The complete, runnable template is
[`examples/minimal_backend.rs`](../crates/anykms-conformance/examples/minimal_backend.rs) in
`anykms-conformance`: a toy in-memory KMS with AES-256-GCM keys, its typed handle, its `Provider`
and a fixture, about 250 lines, run by CI. The code blocks below are excerpts from it and from the
Azure-shaped fixture in
[`crates/anykms-local/tests/shaped/azure.rs`](../crates/anykms-local/tests/shaped/azure.rs),
which shows a native key-wrapping key without server-side rewrap. The rules a backend must meet
are in the rustdoc of the `Provider` trait ("Errors") and of each capability trait; this page is
the map.

A backend has three pieces:

- **typed handles**: one type per key family, implementing the capability traits its keys
  natively support (`Aead`, `KeyWrap`, `DigestSigner`, `Mac`, ...) and declaring its
  `KeySemantics`;
- a **provider**: parses the backend's key URIs without I/O and opens them as typed handles and,
  through the `Provider` trait, as the opaque handles the `Registry` hands out;
- a **fixture**: creates and rotates keys for the conformance suite, outside the anykms API, and
  declares in `probe()` what the backend supports and what it lacks by design.

The conformance run is the one assurance this project offers for any backend: the same cases
every built-in backend passes, on both the typed and the registry path. For a crate outside this
repository, running it and showing the result is the crate's job.

## Typed handles

Implement exactly what the service does. A backend never emulates: an AEAD key whose service has
no server-side rewrap does not implement `Rewrap`; a key-wrapping key whose service cannot rewrap
leaves the part out and `EnvelopeAead::rewrap_current` falls back to the local rewrap. Portable
behavior over a handle lives in `anykms-recipes` and says what it emulates; a backend may depend
on the recipes to provide what its service lacks natively (`KeyWrapDataKeys` over a `KeyWrap`,
`EmulatedDataKeys` over an `Aead`), as the Azure backend does, as long as the recipe's "Emulates /
Enforced by" box stays true.

**Semantics.** Every handle implements `Semantics` (in the prelude) and returns `Some`: a handle
that declares none fails the suite. `KeySemantics` says where this backend legitimately differs
from others, so that generic code and the suite adapt: the version model and shape, whether a
ciphertext reveals its version, whether `describe` reports a primary version, how data-key AAD
behaves, input limits. Declare only what is true; the suite checks the declaration against the
handle's behavior (`capabilities::semantics_match_caps`).

```rust,ignore
// minimal_backend.rs: one `KeySemantics` per key family, built once.
semantics: KeySemantics::new(VersionModel::Floating, VersionShape::Numeric)
    .with_ciphertext_reveals_version(true),
```

**Describe.** `KeyInfo` carries the key type's name as the service calls it, its `Capabilities`,
state, primary version and versions. The capabilities must agree with the handles the provider
opens for the key (`capabilities::handles_match_declaration`): an AEAD key that also serves as a
KEK reports `AEAD | KEY_WRAP`; a native key-wrapping key without server-side rewrap reports
`KEY_WRAP` without `REWRAP`.

**Provided methods.** Implement the provided methods your service can answer better than the
default: `Aead::ciphertext_version` and `KeyWrap::wrapped_key_version` where the ciphertext
carries its version (parsed locally, never with I/O); `Preflight` where the key's state can be
read, so that startup checks and the `describe::preflight*` cases find a disabled key before the
first operation. The opaque handles forward them.

**Hygiene.** `Debug` prints identifiers, never material or credentials (`"<redacted>"`, or
`finish_non_exhaustive`). Key material, plaintexts and data keys live in `Zeroizing` buffers.
Handles never retry internally (one retry after refreshing expired credentials is part of
authenticating, not a retry): retrying is the caller's choice, made once with a `RetryLayer`.
Surface the server's `Retry-After` with `Error::with_retry_after` instead of sleeping on it.

## The provider

A `Provider` owns one or more URI schemes and opens keys from URIs. Opening does no I/O: it
fails only on what the URI, the algorithm and the provider's configuration show, and a key that
does not exist fails with `NotFound` on its first operation, as on every backend. Key URIs come
from configuration, so a URI the grammar refuses is `Configuration` with `Operation::ParseUri`,
naming the URI, never `InvalidArgument`. Applications that take URIs from users recognize parse
errors by that operation, which is why the suite pins it (`errors::parse_uri_is_configuration::*`).
Name the key in every error with `uri.without_query()`, never `uri.to_string()`: a query string
may carry options that must not reach logs, and core labels its own errors the same way.

```rust,ignore
// minimal_backend.rs: the typed constructor. `KeyUri` splits `scheme:rest`; `rest` is the
// provider's to parse.
fn aead_key(&self, uri: impl IntoKeyUri) -> Result<ToyAeadKey> {
    let uri = uri.into_key_uri()?;
    let name = (uri.scheme() == BACKEND)
        .then_some(uri.rest())
        .and_then(|rest| rest.strip_prefix("//"))
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::ParseUri,
                "expected toykms://<name>, the name made of ASCII letters, digits and '-'",
            )
            .with_resource(uri.without_query())
        })?;
    // ...
}
```

The `Provider` methods wrap the typed handle into the opaque handle of its family (`AeadKey`,
`KeyWrapKey`, `DigestSignerKey`, `MacKey`, ...): the required part, then every optional part the
typed handle implements, its semantics, and the typed handle itself as the concrete key so that
`downcast_ref` reaches it. Every open method defaults to `Unsupported`, so implement only the
purposes the backend has.

```rust,ignore
// minimal_backend.rs: an AEAD key, also opened as a KEK (wrapping with empty AAD).
fn aead(&self, uri: &KeyUri, _: &OpenOptions) -> Result<AeadKey> {
    let k = Arc::new(self.aead_key(uri)?);
    let s = k.semantics.clone();
    Ok(AeadKey::new(BACKEND, k.clone())
        .with_describe(k.clone())
        .with_concrete(k)
        .with_semantics(s))
}

fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
    self.aead(uri, opts).map(KeyWrapKey::from_aead)
}
```

```rust,ignore
// shaped/azure.rs: a native key-wrapping key (RSA-OAEP, AES-KW) without server-side rewrap.
fn key_wrap(&self, uri: &KeyUri, _: &OpenOptions) -> Result<KeyWrapKey> {
    let k = Arc::new(self.key_wrap_key(uri)?);
    Ok(KeyWrapKey::new(BACKEND, k.clone())
        .with_describe(k.clone())
        .with_semantics(key_wrap_semantics().clone())
        .with_concrete(k))
}
```

**Schemes.** Choose a scheme of your own. The built-in ones are `hashivault`, `openbao`,
`aws-kms`, `gcp-kms`, `azure-kv` and `local`. A registry refuses two providers claiming one
scheme (`Configuration` at `build`). A `Registry::builder()` you fill yourself has no built-in
backends, so any scheme is free there. `anykms::with_default_providers()` registers the built-in
backends and leaves the ones it skips as placeholders that explain why they are missing; a
provider you add takes precedence over a placeholder, so a third-party provider can serve a
built-in scheme next to the defaults only while that backend is skipped, and collides with it
otherwise. When a backend is skipped is `with_default_providers`' contract (its rustdoc, and
`SkipCause` at run time): in short, its feature off, transit without a server address, Azure
opted out, or no transport it can build. Missing credentials never skip a cloud provider: AWS and
GCP register with their feature on and a usable transport and resolve credentials on the first
operation, so an unset environment does not free their schemes. That is a migration aid, not a
design to rely on.

**Registering.** An application registers a backend with `Registry::builder().provider(..)`, or
next to the defaults with `anykms::with_default_providers()?.provider(..)`. The `anykms` facade
forwards workspace crates as modules behind its features; a crate outside the workspace is
depended on directly and registered that way.

## Errors

The contract is in the `Provider` rustdoc under "Errors", with the conformance case that checks
each rule, and each capability trait lists the kinds of its own operations. The points backend
authors most often get wrong:

- **Class follows kind, never operation.** Config-class kinds (`Configuration`, `NotFound`,
  `PermissionDenied`, `KeyStateInvalid`, `KeyMismatch`, `Unsupported`, `Backend`, ...) need an
  operator; caller-class kinds (`InvalidArgument`, `DecryptFailed`, `VerificationFailed`,
  `KeyVersionUnusable`, `UnknownKeyVersion`) depend on the input of one request and page nobody.
  Anything computed from the bytes of a ciphertext is caller-class: a version it names that the
  key does not have, a key identifier in its prefix that does not match, a failed tag.
- **Every unwrap or decrypt authentication failure is `DecryptFailed`**, deliberately
  indistinguishable: another key's ciphertext, a tampered or truncated one, bytes that are no
  ciphertext at all, a prefix naming material the key does not have. The prefix only selects what
  to try. A version the key has but may not use (disabled, destroyed, below the minimum
  decryption version) is `KeyVersionUnusable`. `aead::authentication_failures` and
  `keywrap::authentication_failures` pin this.
- **Distinguish within a kind with `BackendDetail::code`**, a stable identifier (an AWS
  exception name, a gRPC status, your own `KeyIdMismatch`), and with the message. Applications
  branch on the code; operators read the message. Never change the kind to carry a diagnosis.
- **Errors carry no secrets**: no plaintext, AAD, key material, request bodies, credentials or
  URL query strings, in the message, the detail or the source. The hygiene cases render every
  error of a failing operation and search it for the inputs (`hygiene::*`). Key names, URIs,
  versions and key identifiers are fine, and every operation error names its key
  (`Error::with_resource`).
- **Map the service's errors once**, in one module, from its status codes and stable error codes,
  never from free-form message text where a code exists. A server error nothing recognizes is
  `Backend`; a response that cannot be used (a checksum mismatch, a missing field) is
  `Unavailable` or `Backend` as the operation's documentation says.

## Running the conformance suite

Depend on `anykms-conformance` as a dev-dependency with the same `0.x` as the anykms crates the
backend uses, with its `fixture-helpers` feature for `RunId`, `KeySpecTable`, `FreshKeys` and the
`typed_handles!` macro. Wire the suite up as a `harness = false` test target:

```toml
[dev-dependencies]
anykms-conformance = { version = "0.2", features = ["fixture-helpers"] }

[[test]]
name = "conformance"
harness = false
```

```rust,ignore
// tests/conformance.rs
fn main() -> std::process::ExitCode {
    anykms_conformance::run(async || MyFixture::new().await)
}
```

`run_or_skip` is for fixtures that need a server which may be absent (then every case is ignored
with the reason, never passed); `ANYKMS_REQUIRE_FIXTURE=1` makes that a failure, as CI should.

**The fixture** implements `Fixture`: `create_key` and `rotate` (and `disable`,
`set_min_decryption_version`, `throttle`, ... where the service has them) manage keys outside the
anykms API, as IaC would; `provider()` returns the backend's `Provider`; `typed()` returns its
typed handles bridged for the suite; `missing_key_uri` names a key that does not exist;
`secret_markers` lists fixture-held secrets (a token, a credential) the hygiene cases must not find
in any error.

**Declare every feature.** `probe()` returns the `Feature`s the backend supports, those it lacks
by design (`not_applicable`, with the reason), and those the fixture cannot provide in this
environment (`lacks`). A case whose features are all supported runs; one needing a feature
declared not applicable or lacking is ignored; one needing a feature the fixture did not declare
**fails**, and the `conformance::declarations` trial lists every such feature. New features and
cases land only in a `0.(x+1)` release, so upgrading the dev-dependency is when a fixture catches
up, never a patch release.

```rust,ignore
// shaped/azure.rs: a key-wrapping key without server-side rewrap declares the gap, with the
// reason, instead of stubbing `Rewrap` with `Unsupported`.
.supports_all(&[KeyWrap, DataKeys, Describe, RotateSigning, Disable, PreflightState])
.not_applicable(KeyWrapRewrap, "Azure has no server-side rewrap")
```

**Both paths.** Most cases run twice: `typed::` through the backend's typed handles, bridged into
the dyn layer by `TypedHandles` (`AeadKeyHandles::bridge(k).with_rewrap(k).with_semantics(s)
.with_preflight(k)`, and the same for `KeyWrapKeyHandles`, `DigestKeyHandles`,
`MessageKeyHandles` and `MacKeyHandles`), and `registry::` through a `Registry` holding the
fixture's provider. Carry the typed handles' semantics and preflight through the bridges, or the
typed cases that read them fail.

Run with `ANYKMS_FAIL_ON_SKIP=1` in CI, so that a feature the fixture lacks in that environment
fails instead of being ignored; only features declared not applicable stay ignored. The first run
of a new fixture usually fails on the declarations trial with the list of features to declare;
the second on a handful of error kinds; the messages name the case and the expected kind.

**What the suite does not check.** The fidelity of your service mapping beyond what the fixture
exercises (run it against the real service, or an emulator whose error codes you have verified,
not only against mocks), the formats the backend defines itself, and the operational guidance
you owe your users (permissions, quotas, a runbook mapping each error to a cause and an action,
as the built-in [operator guides](operations.md) do).

## Formats the backend defines

A backend that frames ciphertexts (a version prefix, a nonce and tag layout) or wrapped keys
(a magic, a key identifier) defines a wire format that outlives the code: every ciphertext
written with it must decrypt forever. Specify it before the first persisted ciphertext, in the
style of [the envelope format](envelope-format.md) and
[the Azure ciphertext frame](azure-ciphertext.md): a layout table, what is authenticated and what
is a selector, which fields are wire-fixed and which limits are policy, test vectors built by an
independent implementation and checked for byte-exact reproducibility, and the security notes
(what the format does not provide). A fuzz target for every parser. Changing the format later
means a new version marker and a reader that accepts both, never a reinterpretation.

## Publishing a community backend

A backend outside this repository is a crate of its own: depend on `anykms-core` (and the recipes,
if used) at one `0.x`, run the suite in your own CI with `ANYKMS_FAIL_ON_SKIP=1`, and ship the
operator documentation above. Name the crate for the service or the key custody it provides; the
`anykms-` prefix names the workspace crates, which release in lockstep and are maintained here.
The suite is the only assurance this project offers for a community backend, and it is the
crate's to run and to show in its CI; this project does not review or maintain the crate, and a
user of one checks that CI, not this repository.
