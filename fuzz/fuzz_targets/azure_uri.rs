#![no_main]
use anykms_azure::AzureKeyRef;
use anykms_core::{ErrorKind, Operation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    // Parses, checks the host policy, and asserts that an accepted URI reparses to itself.
    let _ = anykms_azure::__fuzz::parse_uri(&format!("azure-kv:{s}"));
    // A3(c): a key URI is configuration, a key identifier input.
    if let Err(e) = AzureKeyRef::parse(format!("azure-kv:{s}").as_str()) {
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Configuration, Operation::ParseUri)
        );
    }
    match AzureKeyRef::from_key_id(s) {
        Err(e) => {
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::InvalidArgument, Operation::Construct)
            )
        }
        Ok(u) => {
            let _ = u.with_version(s).map_err(|e| {
                assert_eq!(
                    (e.kind(), e.operation()),
                    (ErrorKind::InvalidArgument, Operation::Construct)
                )
            });
        }
    }
    if let Ok(u) = AzureKeyRef::from_key_id(s) {
        let ok =
            |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        assert!(ok(u.name()), "{u:?}");
        assert!(u.version().is_none_or(|v| v.len() == 32), "{u:?}");
        assert!(!u.host().contains(['/', '@', '?', '#', '%']), "{u:?}");
        assert_eq!(AzureKeyRef::from_key_id(&u.to_key_id()).unwrap(), u);
    }
});
