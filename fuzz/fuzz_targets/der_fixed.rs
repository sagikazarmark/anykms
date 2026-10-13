#![no_main]
use anykms_recipes::ecdsa_der::{der_to_fixed, fixed_to_der};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u8, &[u8])| {
    let (sel, data) = input;
    let n = [32usize, 48, 66][sel as usize % 3];
    if let Ok(fixed) = der_to_fixed(data, n) {
        // Strict DER: re-encoding gives back exactly the input.
        assert_eq!(fixed_to_der(&fixed, n).expect("re-encode"), data);
    }
    if data.len() == 2 * n {
        let der = fixed_to_der(data, n).expect("fixed input encodes");
        assert_eq!(der_to_fixed(&der, n).expect("decode"), data);
    }
});
