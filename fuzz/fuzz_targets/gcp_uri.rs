#![no_main]
use anykms_core::KeyUri;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    // The hook asserts that an accepted URI's canonical form parses to the same reference.
    let accepted = anykms_gcp::__fuzz::parse_uri(s);
    let Ok(u) = KeyUri::parse(&format!("gcp-kms:{s}")) else {
        return;
    };
    if let Ok(r) = anykms_gcp::GcpKeyRef::parse(&u) {
        assert!(accepted, "{s:?}");
        // Accepted URIs only contain validated segments: nothing that adds path structure, a
        // query or another host.
        for part in [r.project(), r.location(), r.key_ring(), r.key()] {
            assert!(!part.is_empty(), "{r:?}");
            assert!(!part.contains(['/', '?', '#', '%', '@']), "{r:?}");
            assert!(part != "." && part != "..", "{r:?}");
        }
        assert!(r.version().is_none_or(|v| v > 0), "{r:?}");
    }
});
