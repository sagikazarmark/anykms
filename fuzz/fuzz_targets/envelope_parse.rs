#![no_main]
use anykms_recipes::Envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(e) = Envelope::parse(data) {
        assert_eq!(e.version(), 1);
        assert!(e.kek_id().len() <= 255);
        assert!(!e.wrapped_dek().is_empty() && e.wrapped_dek().len() <= 4096);
        assert!(e.payload().len() >= 16);
    }
});
