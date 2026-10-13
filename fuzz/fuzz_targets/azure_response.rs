#![no_main]
use anykms_azure::__fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u16, u8, &[u8])| {
    let (status, which, body) = input;
    // Error classification (status, code, inner codes), success bodies (sign/wrap/encrypt,
    // verify, key bundles), key bundles with the portable view, token responses.
    let _ = __fuzz::classify(status, body);
    let _ = __fuzz::decode_success(which, body);
    let _ = __fuzz::parse_key_bundle(body);
    let _ = __fuzz::token_response(status, body);
});
