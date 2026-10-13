#![no_main]
use anykms_gcp::__fuzz;
use libfuzzer_sys::fuzz_target;

// Error-response classification (google.rpc.Status JSON, its details, non-JSON bodies): never a
// panic, and every status gets a kind.
fuzz_target!(|input: (u16, u8, &[u8])| {
    let (status, op, body) = input;
    let _ = __fuzz::classify(status, body, op);
});
