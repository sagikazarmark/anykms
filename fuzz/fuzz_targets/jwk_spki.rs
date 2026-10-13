#![no_main]
use anykms_azure::__fuzz;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, &str, Option<&str>)| {
    // RSA (n, e) or EC (crv, x, y) JWK members to a validated SubjectPublicKeyInfo.
    let (a, b, c) = input;
    let _ = __fuzz::jwk_spki(a, b, c);
    for crv in ["P-256", "P-384", "P-521"] {
        let _ = __fuzz::jwk_spki(crv, a, Some(b));
    }
});
