#![no_main]
//! The AAD wire encoding: lowercase hex that decodes back to the AAD, within the cap.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|aad: &[u8]| {
    match anykms_aws::__fuzz::encode_aad(aad) {
        None => assert!(aad.is_empty() || aad.len() > anykms_aws::MAX_AAD_BYTES),
        Some(v) => {
            assert!(v.len() == 2 * aad.len() && v.len() <= 6144);
            assert!(v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
            let back: Vec<u8> = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(back, aad);
        }
    }
});
