# Testing your application

Write application code against the traits, [`AeadKey`] or the [`Registry`], not against
`TransitAeadKey`. Tests can then use in-memory keys from the `local` feature:

```toml
[dev-dependencies]
anykms = { version = "0.1", features = ["local"] }
```

```rust
use anykms::local::{Fault, LocalKeyset, LocalProvider};
use anykms::{ErrorKind, Operation};

let ks = LocalKeyset::builder().aead("kek").hmac("tokens").build();
let registry = anykms::Registry::builder()
    .provider(LocalProvider::new(ks.clone()).allow_ephemeral_local_keys()) // explicit opt-in
    .build()?;
ks.rotate("kek")?;                                        // exercise rotation
ks.inject(Fault::throttled(2));                           // exercise retries
ks.inject_for_key("tokens", Fault::permission_denied(1)); // exercise error mapping
ks.inject_on(Operation::Decrypt, Fault::of_kind(ErrorKind::DecryptFailed, 1)); // one operation
```

A fault injects any `ErrorKind` (`Fault::of_kind`); `ks.inject_error(error, times)` injects a
fully formed error, with a `Retry-After` or a retry hint.

For a hand-written fake, implement the static traits with plain `async fn` on your own type and
wrap it in the matching handle (`AeadKey::new`, `MacKey::new`, `DigestSignerKey::new`, ...).
Retry with `RetryPolicy::immediate()` so tests retry without waiting (or, with the facade's
tokio retries, use `#[tokio::test(start_paused = true)]`: `retry_layer()` sleeps and measures its
deadline on tokio's clock; `start_paused` needs tokio's `test-util` feature in your
dev-dependencies, `tokio = { version = "1", features = ["macros", "rt", "test-util"] }`):

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anykms::prelude::*;
use anykms::{
    AeadKey, Ciphertext, Error, ErrorKind, Result, RetryLayer, RetryPolicy, Zeroizing, instant_sleep,
};

/// Throttled twice, then "encrypts" by prefixing the AAD. Never use outside tests.
struct FakeKek {
    calls: AtomicU32,
}

impl Aead for FakeKek {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        if self.calls.fetch_add(1, Ordering::Relaxed) < 2 {
            return Err(Error::app(ErrorKind::Throttled, "fake throttling"));
        }
        Ok(Ciphertext::from_bytes([aad, plaintext].concat()))
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match ct.as_bytes().strip_prefix(aad) {
            Some(pt) => Ok(Zeroizing::new(pt.to_vec())),
            None => Err(Error::app(ErrorKind::DecryptFailed, "fake: wrong AAD")),
        }
    }
}

// Code under test takes an `AeadKey` (or `impl Aead`), so the fake slots in.
let retry = RetryLayer::new(instant_sleep()).with_policy(RetryPolicy::immediate());
let kek = AeadKey::new("fake", Arc::new(FakeKek { calls: AtomicU32::new(0) })).layer(&retry);
let ct = kek.encrypt(b"123-45-6789", b"users/42/ssn").await?; // two retries, then success
assert_eq!(&*kek.decrypt(&ct, b"users/42/ssn").await?, b"123-45-6789");
```

## Running the conformance suite

Backends prove themselves with the conformance suite:

```sh
scripts/dev-up.sh --sealed --tls                     # Vault + OpenBao dev servers (docker compose)
cargo test --workspace --all-features                # unit, mock, conformance, integration
ANYKMS_REQUIRE_FIXTURE=1 cargo test -p anykms-transit  # fail instead of skip without servers
```

[`AeadKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.AeadKey.html
[`Registry`]: https://docs.rs/anykms-core/latest/anykms_core/struct.Registry.html
