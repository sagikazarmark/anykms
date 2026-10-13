#![no_main]
use anykms_transit::__fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u16, &[u8])| {
    let (status, body) = input;
    let _ = __fuzz::parse_key_info(body);
    let _ = __fuzz::classify(status, body);
    if let Ok(s) = std::str::from_utf8(body) {
        if let Some((v, rest)) = __fuzz::parse_versioned(s) {
            assert!(v > 0);
            assert!(s.ends_with(rest));
        }
    }
});
