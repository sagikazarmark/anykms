#![no_main]
use anykms_gcp::__fuzz;
use libfuzzer_sys::fuzz_target;

// Success-body decoding and checks (CRC32C, verified flags, names) of every operation: never a
// panic, whatever the body.
fuzz_target!(|input: (u8, &[u8])| {
    let (which, body) = input;
    let _ = __fuzz::decode_success(which, body);
    let _ = __fuzz::crc32c(body);
});
