#![no_main]
//! Success-body decoding of every operation: `[which, body...]` (`which % 9`).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [which, body @ ..] = data else { return };
    let _ = anykms_aws::__fuzz::decode_success(*which, body);
});
