//! Issue and check HMAC-authenticated tokens; tags keep their key version, so they still verify
//! after a key rotation.
//!
//!     cargo run -p anykms --features local --example hmac_tokens

#[path = "common/mod.rs"]
mod common;

use anykms::prelude::*;
use anykms::{MacAlgorithm, Tag};

#[tokio::main]
async fn main() -> anykms::Result<()> {
    let registry = common::registry()?;
    let uri = common::uri("ANYKMS_MAC_URI", "local://default/tokens")?;
    let mac = registry.mac(&uri, MacAlgorithm::HmacSha256)?;

    let token_id = b"session-7f3a";
    let tag = mac.mac(token_id).await?;
    // Store the canonical encoding (URL-safe base64): algorithm and key version travel with
    // the tag.
    let stored = tag.to_base64_url()?;
    println!("stored tag: {stored} (version {:?})", tag.key_version());

    mac.verify_mac(token_id, &Tag::from_base64_url(&stored)?)
        .await?;
    println!("token verified");
    assert!(
        mac.verify_mac(b"session-forged", &Tag::from_base64_url(&stored)?)
            .await
            .is_err()
    );
    // A corrupt stored tag fails like a forged one.
    let e = Tag::from_base64_url("not a tag").unwrap_err();
    assert_eq!(e.kind(), anykms::ErrorKind::VerificationFailed);
    Ok(())
}
