#![no_main]
//! Differential/round-trip target: encrypt with a local KEK (unpadded or padded), check decryption, then check that
//! any single-byte mutation either fails with DecryptFailed or (only inside the unauthenticated
//! key-wrapping slot) still yields the original plaintext.
use std::future::Future;
use std::pin::pin;
use std::sync::OnceLock;
use std::task::{Context, Poll, Waker};

use anykms_core::{Aead, Ciphertext, ErrorKind};
use anykms_local::{LocalAeadKey, LocalKeyset};
use anykms_recipes::EnvelopeAead;
use anykms_recipes::envelope::Padding;
use libfuzzer_sys::fuzz_target;

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn kek() -> &'static LocalAeadKey {
    static K: OnceLock<LocalAeadKey> = OnceLock::new();
    K.get_or_init(|| LocalKeyset::builder().aead("kek").build().aead_key("kek"))
}

fuzz_target!(|input: (Vec<u8>, Vec<u8>, Vec<u8>, u16, u8, u8)| {
    let (pt, aad, kek_id, pos, xor, pad) = input;
    if kek_id.len() > 255 {
        return;
    }
    // Unpadded, or padded to blocks of 2 to 129 bytes.
    let padding = match pad {
        0 => Padding::NONE,
        n => Padding::block(usize::from(n % 128) + 2),
    };
    let env = EnvelopeAead::new(&kek_id, kek().into_key_wrap())
        .expect("kek_id fits")
        .with_padding(padding);
    let ct = block_on(env.encrypt(&pt, &aad)).expect("encrypt");
    assert_eq!(*block_on(env.decrypt(&ct, &aad)).expect("decrypt"), pt);
    if xor == 0 || ct.is_empty() {
        return;
    }
    let mut bytes = ct.as_bytes().to_vec();
    let i = pos as usize % bytes.len();
    bytes[i] ^= xor;
    match block_on(env.decrypt(&Ciphertext::from_bytes(bytes), &aad)) {
        Ok(back) => assert_eq!(*back, pt, "mutation at {i} produced a different plaintext"),
        Err(e) => assert_eq!(e.kind(), ErrorKind::DecryptFailed, "mutation at {i}: {e}"),
    }
});
