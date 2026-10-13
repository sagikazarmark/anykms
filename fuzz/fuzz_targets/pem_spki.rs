#![no_main]
use anykms_core::{Digest, DigestVerifier, MessageVerifier, Signature, SignatureAlgorithm};
use anykms_recipes::{LocalVerifier, public_key_from_pem, public_key_from_spki_der};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&[u8], &[u8], u8)| {
    let (data, sig, alg) = input;
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = public_key_from_pem(s, None);
    }
    let Ok(pk) = public_key_from_spki_der(data, None) else {
        return;
    };
    let alg = SignatureAlgorithm::ALL[alg as usize % SignatureAlgorithm::ALL.len()];
    // The verifier is pinned to `alg`; an algorithm of another key type fails here.
    let Ok(v) = LocalVerifier::new(pk, alg) else {
        return;
    };
    let sig = Signature::from_parts(alg, None, sig.to_vec());
    let fut = async {
        match alg.hash() {
            Some(h) => v.verify_digest(&Digest::compute(h, b"m"), &sig).await,
            None => v.verify_message(b"m", &sig).await,
        }
    };
    // Arbitrary keys and signatures must not panic. The result is not asserted: the fuzzer picks
    // the public key as well as the signature, so a verifying pair is possible (any key whose
    // private key is known, with a signature over "m" from it), and "never verifies" cannot be
    // guaranteed.
    let mut f = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    if let std::task::Poll::Ready(r) = f.as_mut().poll(&mut cx) {
        let _ = r;
    }
});
