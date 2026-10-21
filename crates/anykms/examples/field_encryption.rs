//! Envelope-encrypt a database field, rotate the KEK, and rewrap without touching the payload.
//!
//!     cargo run -p anykms --features local --example field_encryption
//!     # against Vault (scripts/dev-up.sh; create the key first):
//!     VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ANYKMS_KEK_URI=hashivault:///transit/keys/app-kek \
//!       cargo run -p anykms --features local,transit --example field_encryption
//!
//! With local keys the example rotates the KEK itself. Rotating a transit key is an admin
//! operation outside the data-plane API, so against Vault/OpenBao run
//! `vault write -f transit/keys/app-kek/rotate` (between runs, or before the rewrap step) to see
//! the version change; the rewrap is the same call either way.

#[path = "common/mod.rs"]
mod common;

use anykms::prelude::*;
use anykms::recipes::{Envelope, EnvelopeAead};

#[tokio::main]
async fn main() -> anykms::Result<()> {
    let (registry, keyset) = common::registry_with_keyset()?;
    let uri = common::uri("ANYKMS_KEK_URI", "local://default/kek")?;
    // A key-wrapping key: the AEAD key wraps data keys by encrypting them with empty AAD. The
    // registry's retry layer retries transient failures (throttling, failover) with bounded
    // backoff; the handle is still a `KeyWrapKey` with exactly the parts the backend offers.
    let kek = registry.key_wrap(&uri)?;
    let server_side_rewrap = kek.supports_rewrap();
    let envelope = EnvelopeAead::new("app-kek", kek)?;

    let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
    let v1 = envelope.ciphertext_version(&ct)?;
    println!("stored {} bytes (kek version {v1:?})", ct.len());
    let pt = envelope.decrypt(&ct, b"users/42/ssn").await?;
    assert_eq!(&*pt, b"123-45-6789");

    // The same ciphertext under another row's AAD does not decrypt.
    assert!(envelope.decrypt(&ct, b"users/43/ssn").await.is_err());

    // Rotate the KEK: new envelopes and rewraps use the new primary version.
    let rotated = if let Ok((_, name)) = anykms::local::parse_local_uri(&uri) {
        keyset.rotate(name)?;
        println!("rotated local KEK {name:?}");
        true
    } else {
        println!(
            "not rotating {uri}: transit rotation needs an admin token \
             (vault write -f transit/keys/<name>/rotate)"
        );
        false
    };

    // Move the data key to the KEK's primary version; the payload is untouched. `rewrap_current`
    // rewraps inside the KMS where the KEK can (the data key never leaves it), and otherwise
    // unwraps and wraps locally (`rewrap_local`).
    let rewrapped = envelope.rewrap_current(&ct).await?;
    assert_eq!(
        Envelope::parse(rewrapped.as_bytes())?.payload(),
        Envelope::parse(ct.as_bytes())?.payload()
    );
    let v2 = envelope.ciphertext_version(&rewrapped)?;
    if rotated {
        assert_ne!(v1, v2, "rewrap moves the data key to the new KEK version");
    }
    println!(
        "rewrapped ({}) from kek version {v1:?} to {v2:?}; plaintext still {:?}",
        if server_side_rewrap {
            "server-side"
        } else {
            "local"
        },
        String::from_utf8_lossy(&envelope.decrypt(&rewrapped, b"users/42/ssn").await?)
    );
    Ok(())
}
