#![no_main]
use anykms_core::encoding::{decode_signature, decode_tag, encode_signature, encode_tag};
use anykms_core::{Digest, HashAlgorithm};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u8, &[u8])| {
    let (sel, data) = input;
    let alg = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ][sel as usize % 3];
    match Digest::new(alg, data) {
        Ok(d) => assert_eq!(d.as_bytes(), data),
        Err(_) => assert_ne!(data.len(), alg.output_len()),
    }
    if let Ok(s) = decode_signature(data) {
        assert_eq!(encode_signature(&s).unwrap(), data);
    }
    if let Ok(t) = decode_tag(data) {
        assert_eq!(encode_tag(&t).unwrap(), data);
    }
});
