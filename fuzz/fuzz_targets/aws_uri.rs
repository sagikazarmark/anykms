#![no_main]
//! The aws-kms:// ARN grammar: accepted URIs name a 12-digit account, a region of the AWS
//! region shape (so a derived host is always `kms.<region>.<suffix>`) and a key id or alias of
//! the allowed characters, and parse the same way twice.
use anykms_core::{ErrorKind, KeyUri, Operation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let Ok(u) = KeyUri::parse(&format!("aws-kms:{s}")) else {
        return;
    };
    // A3(c): a refused URI is configuration, labeled ParseUri.
    if let Err(e) = anykms_aws::AwsKeyRef::parse(&u) {
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Configuration, Operation::ParseUri)
        );
    }
    if let Ok(r) = anykms_aws::AwsKeyRef::parse(&u) {
        assert!(
            r.account().len() == 12 && r.account().bytes().all(|b| b.is_ascii_digit()),
            "{r:?}"
        );
        assert!(!r.arn().contains(['?', '#', '%', ' ']), "{r:?}");
        let again = anykms_aws::AwsKeyRef::parse_arn(r.arn()).expect("re-parses");
        assert_eq!(again, r);
        let region = r.region();
        assert!(region.split('-').count() >= 3, "{r:?}");
        assert!(
            region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{r:?}"
        );
        assert!(
            region
                .rsplit('-')
                .next()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())),
            "{r:?}"
        );
        match (r.key_id(), r.alias_name()) {
            (None, Some(a)) => assert!(!a.starts_with("aws/"), "{r:?}"),
            (Some(k), None) => assert!(
                k.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{r:?}"
            ),
            _ => panic!("{r:?}"),
        }
    }
    let _ = anykms_aws::__fuzz::parse_uri(s);
});
