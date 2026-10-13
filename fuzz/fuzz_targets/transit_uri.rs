#![no_main]
use anykms_core::KeyUri;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let Ok(u) = KeyUri::parse(&format!("hashivault:{s}")) else {
        return;
    };
    if let Ok(r) = anykms_transit::TransitKeyRef::parse(&u) {
        // Accepted URIs only contain validated segments.
        let ok = |x: &str| {
            !x.is_empty()
                && x.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        };
        assert!(r.mount().split('/').all(ok), "{r:?}");
        assert!(ok(r.name()) && r.name() != "." && r.name() != "..", "{r:?}");
        assert!(!r.alias().contains(['@', ':', '/']), "{r:?}");
        if let Some(ns) = r.namespace() {
            assert!(ns.split('/').all(ok), "{r:?}");
        }
    }
});
