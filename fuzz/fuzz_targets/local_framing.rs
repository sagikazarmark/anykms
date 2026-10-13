#![no_main]
use anykms_local::{__fuzz::frame, parse_local_ciphertext};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse: accepted frames are well-formed and canonical (re-framing gives the same bytes).
    if let Some((v, nonce, ct)) = parse_local_ciphertext(data) {
        assert!(v > 0);
        assert_eq!(nonce.len(), 12);
        assert!(ct.len() >= 16);
        assert_eq!(frame(v, nonce, ct), data);
    }
    // Frame → parse round trip: the first 8 bytes pick the version, the rest is nonce ‖ ct.
    if let Some((v, rest)) = data.split_first_chunk::<8>() {
        let version = u64::from_le_bytes(*v);
        if version > 0 && rest.len() >= 12 + 16 {
            let (nonce, ct) = rest.split_at(12);
            let framed = frame(version, nonce, ct);
            assert_eq!(parse_local_ciphertext(&framed), Some((version, nonce, ct)));
        }
    }
});
