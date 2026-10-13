#![no_main]
//! Error-response classification: `[status_hi, status_lo, header_len, header..., body...]`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [hi, lo, n, rest @ ..] = data else { return };
    let status = u16::from_be_bytes([*hi, *lo]) % 600;
    let n = usize::from(*n).min(rest.len());
    let (header, body) = rest.split_at(n);
    let header = std::str::from_utf8(header).ok();
    let _ = anykms_aws::__fuzz::classify(status, header, body);
});
