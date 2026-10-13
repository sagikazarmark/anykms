#![no_main]
use anykms_azure::framing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse, then re-encode: an accepted frame round-trips byte for byte.
    if let Ok(f) = framing::parse(data) {
        let again = framing::encode(f.alg(), f.version(), f.body()).unwrap();
        assert_eq!(again, data);
        if let Some((iv, ct, tag)) = f.gcm_parts() {
            assert_eq!(iv.len(), framing::GCM_IV_LEN);
            assert_eq!(tag.len(), framing::GCM_TAG_LEN);
            assert_eq!(framing::encode_gcm(f.version(), iv, ct, tag).unwrap(), data);
        }
    }
});
