//! The transport-free anykms crates on a JS host (Node under wasm-bindgen-test): every place that
//! read `std::time` now reads the JS clock, and `getrandom` reaches `crypto.getRandomValues`.
//! Each of these would panic on `wasm32-unknown-unknown` without the `js` features.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use std::time::Duration;

use anykms_core::time::{Instant, unix_now};
use anykms_core::{Aead, AeadKeyWrap, Describe, KeyWrap, Zeroizing};
use anykms_local::LocalKeyset;
use anykms_recipes::CachingKeyWrap;
use anykms_recipes::jose::{JwtOptions, JwtSigner};
use base64::Engine as _;
use wasm_bindgen_test::wasm_bindgen_test;

fn date_now_secs() -> u64 {
    // `Date.now()` is milliseconds as f64; truncation to whole seconds is intended.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let s = (js_sys::Date::now() / 1000.0) as u64;
    s
}

/// `Instant` (`performance.now()`) and `unix_now` (`Date.now()`) read the host without panicking;
/// the wall clock agrees with the host's and the monotonic clock behaves like `std`'s.
#[wasm_bindgen_test]
fn core_clocks_read_the_js_host() {
    let a = Instant::now();
    let b = Instant::now();
    assert!(b >= a);
    assert_eq!(a.duration_since(b), Duration::ZERO);
    assert_eq!((a + Duration::from_secs(1)) - a, Duration::from_secs(1));

    let ours = unix_now().as_secs();
    let host = date_now_secs();
    assert!(
        ours.abs_diff(host) <= 1,
        "unix_now {ours} vs Date.now {host}"
    );
}

/// `Retry`'s default clock is the JS monotonic clock.
#[wasm_bindgen_test]
fn retry_std_clock_is_usable() {
    let clock = anykms_core::retry::std_clock();
    let t0 = clock();
    let t1 = clock();
    assert!(t1 >= t0);
}

/// `anykms-local`: key generation needs `getrandom` (the JS backend), and version metadata
/// stamps `Date.now()`.
#[wasm_bindgen_test]
async fn local_keyset_generates_keys_and_stamps_versions() {
    let before = date_now_secs();
    let ks = LocalKeyset::builder().aead("k").build();
    let key = ks.aead_key("k");
    let info = key.describe().await.expect("describe");
    let created = info.versions()[0].created_at().expect("created_at");
    let after = date_now_secs();
    assert!(
        (before..=after).contains(&created),
        "created_at {created} outside [{before}, {after}]"
    );

    let ct = key.encrypt(b"hello", b"aad").await.expect("encrypt");
    let pt = key.decrypt(&ct, b"aad").await.expect("decrypt");
    assert_eq!(&*pt, b"hello");
}

/// `anykms-recipes`: the DEK cache keys its TTL on the monotonic clock, and JWT signing stamps
/// `iat`/`exp` from the wall clock when no `with_now` is given.
#[wasm_bindgen_test]
async fn recipes_dek_cache_and_jwt_clocks_work() {
    let ks = LocalKeyset::builder().aead("kek").ed25519("sig").build();

    let kek =
        CachingKeyWrap::new(AeadKeyWrap::new(ks.aead_key("kek"))).with_ttl(Duration::from_secs(60));
    let dek = Zeroizing::new(vec![7u8; 32]);
    let wrapped = kek.wrap_key(&dek).await.expect("wrap");
    assert_eq!(kek.len(), 0);
    let u1 = kek.unwrap_key(&wrapped).await.expect("unwrap");
    assert_eq!(kek.len(), 1, "a miss populates the cache");
    let u2 = kek.unwrap_key(&wrapped).await.expect("unwrap (cached)");
    assert_eq!(&*u1, &*dek);
    assert_eq!(&*u2, &*dek);

    let signer = JwtSigner::new(ks.ed25519_key("sig"), "sig");
    let before = date_now_secs();
    let token = signer
        .sign_message(
            &serde_json::json!({ "sub": "wasm" }),
            &JwtOptions::new().with_ttl(Duration::from_secs(300)),
        )
        .await
        .expect("sign");
    let after = date_now_secs();
    let payload = token.split('.').nth(1).expect("payload");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("json");
    let iat = claims["iat"].as_u64().expect("iat");
    let exp = claims["exp"].as_u64().expect("exp");
    assert!(
        (before..=after).contains(&iat),
        "iat {iat} outside [{before}, {after}]"
    );
    assert_eq!(exp, iat + 300);
}
