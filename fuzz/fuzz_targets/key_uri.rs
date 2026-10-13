#![no_main]
use anykms_core::{ErrorKind, KeyUri, Operation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    // A3(c): key URIs come from configuration.
    if let Err(e) = KeyUri::parse(s) {
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Configuration, Operation::ParseUri)
        );
    }
    if let Ok(u) = KeyUri::parse(s) {
        // Display round-trips exactly.
        let again = KeyUri::parse(&u.to_string()).expect("displayed URI parses");
        assert_eq!(again, u);
        let _ = anykms_transit::TransitKeyRef::parse(&u);
        let _ = anykms_local::parse_local_uri(&u);
    }
});
