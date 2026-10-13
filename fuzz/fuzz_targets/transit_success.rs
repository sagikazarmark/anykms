#![no_main]
//! Decoding of transit success responses (encrypt/rewrap, decrypt, datakey, sign, verify, hmac).
//!
//! Input: `[which, body...]`; `which % 6` picks the operation and `which / 6` the algorithm.
use anykms_transit::__fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [which, body @ ..] = data else { return };
    let _ = __fuzz::decode_success(*which, body);
});
