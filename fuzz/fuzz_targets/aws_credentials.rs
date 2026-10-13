#![no_main]
//! Credential responses: IMDS / container JSON, STS XML (success and
//! error) and RFC 3339 expirations. `[which, body...]`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [which, body @ ..] = data else { return };
    match which % 4 {
        0 => drop(anykms_aws::__fuzz::parse_credentials_json(body)),
        1 => drop(anykms_aws::__fuzz::parse_sts(
            200,
            &String::from_utf8_lossy(body),
        )),
        2 => drop(anykms_aws::__fuzz::parse_sts(
            400,
            &String::from_utf8_lossy(body),
        )),
        _ => drop(anykms_aws::__fuzz::parse_time(&String::from_utf8_lossy(
            body,
        ))),
    }
});
