//! Opaque handles through the facade: lending handles to recipes, part-wise retries that keep the
//! handle type, and retry schedules under paused tokio time.

use std::time::Duration;

use anykms::local::{Fault, LocalAeadKey, LocalKeyset, LocalProvider};
use anykms::prelude::*;
use anykms::recipes::EnvelopeAead;
use anykms::{
    AeadKey, AeadKeyWrap, ErrorKind, MacAlgorithm, MacKey, Registry, RetryPolicy, retry_layer,
};

fn registry(ks: &LocalKeyset) -> Registry {
    Registry::builder()
        .provider(LocalProvider::new(ks.clone()).allow_ephemeral_local_keys())
        .build()
        .unwrap()
}

/// A recipe can borrow a handle (`EnvelopeAead<AeadKeyWrap<&AeadKey>>`) instead of owning or
/// `Arc`-ing it.
#[tokio::test]
async fn recipes_borrow_handles() {
    let ks = LocalKeyset::builder().aead("kek").build();
    let kek: AeadKey = registry(&ks).aead("local://default/kek").unwrap();
    let envelope: EnvelopeAead<AeadKeyWrap<&AeadKey>> =
        EnvelopeAead::new("", (&kek).into_key_wrap()).unwrap();
    let ct = envelope.encrypt(b"pt", b"aad").await.unwrap();
    assert_eq!(&*envelope.decrypt(&ct, b"aad").await.unwrap(), b"pt");
    let boxed = EnvelopeAead::new("", Box::new(kek.clone()).into_key_wrap()).unwrap();
    assert_eq!(&*boxed.decrypt(&ct, b"aad").await.unwrap(), b"pt");
}

/// A retry layer applied to a handle returns the same handle type with the same parts, and the
/// concrete key stays reachable.
#[tokio::test(start_paused = true)]
async fn retry_layer_keeps_the_handle_type() {
    let ks = LocalKeyset::builder().aead("kek").hmac("tokens").build();
    let reg = registry(&ks);
    let kek: AeadKey = reg
        .aead("local://default/kek")
        .unwrap()
        .layer(&retry_layer());
    assert!(kek.supports_rewrap() && kek.supports_data_keys() && kek.supports_describe());
    assert!(kek.downcast_ref::<LocalAeadKey>().is_some());
    ks.inject(Fault::throttled(2));
    let ct = kek.encrypt(b"x", b"").await.unwrap();
    assert_eq!(&*kek.decrypt_utf8(&ct, b"").await.unwrap(), "x");

    let mac: MacKey = reg
        .mac("local://default/tokens", MacAlgorithm::HmacSha256)
        .unwrap()
        .layer(&retry_layer());
    ks.inject(Fault::unavailable(1));
    let tag = mac.mac(b"m").await.unwrap();
    mac.verify_mac(b"m", &tag).await.unwrap();
}

/// A registry-level layer retries every handle it opens.
#[tokio::test(start_paused = true)]
async fn registry_layer_retries_every_handle() {
    let ks = LocalKeyset::builder().aead("kek").build();
    let reg = Registry::builder()
        .provider(LocalProvider::new(ks.clone()).allow_ephemeral_local_keys())
        .layer(retry_layer())
        .build()
        .unwrap();
    let kek = reg.aead("local://default/kek").unwrap();
    ks.inject(Fault::timeout(3));
    kek.encrypt(b"x", b"").await.unwrap();
}

/// A handle from a retrying registry ignores a second retry layer: one schedule (at most 9.3 s
/// of backoff), not six nested ones.
#[tokio::test(start_paused = true)]
async fn retry_layers_do_not_nest() {
    let ks = LocalKeyset::builder().aead("kek").build();
    let reg = Registry::builder()
        .provider(LocalProvider::new(ks.clone()).allow_ephemeral_local_keys())
        .layer(retry_layer())
        .build()
        .unwrap();
    let kek = reg.aead("local://default/kek").unwrap();
    assert!(kek.is_retrying());
    let kek = kek.layer(&retry_layer());
    ks.inject(Fault::unavailable(100));
    let started = tokio::time::Instant::now();
    assert!(kek.encrypt(b"x", b"").await.is_err());
    assert!(
        started.elapsed() <= Duration::from_millis(9300),
        "{:?}",
        started.elapsed()
    );
}

/// With tokio's sleep and clock, a paused runtime runs the default schedule (several seconds of
/// backoff) at once, and the deadline still applies in tokio time.
#[tokio::test(start_paused = true)]
async fn paused_time_runs_the_schedule_instantly() {
    let ks = LocalKeyset::builder().aead("kek").build();
    let kek = registry(&ks).aead("local://default/kek").unwrap();

    let started = std::time::Instant::now();
    let tokio_started = tokio::time::Instant::now();
    ks.inject(Fault::unavailable(100));
    let e = kek
        .clone()
        .layer(&retry_layer())
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable);
    // 5 retries of the default policy wait 4.65 to 9.3 s of tokio time...
    let simulated = tokio_started.elapsed();
    assert!(
        (Duration::from_millis(4650)..=Duration::from_millis(9300)).contains(&simulated),
        "{simulated:?}"
    );
    // ...and no real time.
    assert!(started.elapsed() < Duration::from_secs(2));

    // The deadline is measured on the same clock: 2 s of tokio time allows only a few retries.
    ks.clear_faults();
    ks.inject(Fault::unavailable(100));
    let layer = retry_layer().with_policy(
        RetryPolicy::default()
            .with_backoff(Duration::from_secs(1), Duration::from_secs(1))
            .with_deadline(Duration::from_secs(2)),
    );
    let tokio_started = tokio::time::Instant::now();
    assert!(kek.clone().layer(&layer).encrypt(b"x", b"").await.is_err());
    assert!(tokio_started.elapsed() <= Duration::from_secs(2));

    // `RetryPolicy::immediate()` takes no time at all.
    ks.clear_faults();
    ks.inject(Fault::throttled(5));
    let layer = retry_layer().with_policy(RetryPolicy::immediate());
    let tokio_started = tokio::time::Instant::now();
    kek.layer(&layer).encrypt(b"x", b"").await.unwrap();
    assert_eq!(tokio_started.elapsed(), Duration::ZERO);
}
