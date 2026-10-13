#![no_main]
//! The shared config/credentials file parser.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = anykms_aws::__fuzz::parse_profile(s);
});
