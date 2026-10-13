//! Server messages as they may appear in errors and logs.
//!
//! A server's error message may echo request input (key names, plaintext fragments), so a
//! backend keeps only messages it has pinned as safe and reduces anything else to its length and
//! a keyed fingerprint ([`ServerMessage::Redacted`]).
//!
//! The fingerprint is the first 6 bytes of HMAC-SHA256 under a per-process random key, drawn from
//! the OS RNG on first use: equal messages get equal fingerprints within one process (to
//! correlate repeated failures in logs), but a fingerprint cannot be checked offline against
//! guesses, as an unkeyed hash of a low-entropy echoed input could. Fingerprints are therefore not
//! comparable across processes or restarts.
//!
//! Two more server- or configuration-supplied values get the same treatment: request ids
//! ([`request_id`]) and URLs in `Debug` output ([`url_origin`]).

use anykms_core::ServerMessage;
use hmac::Mac as _;

/// How a message is compared with a backend's pinned messages.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pinned {
    /// The whole message equals a pinned message.
    Exact,
    /// The message contains a pinned fragment, ignoring ASCII case. The fragment is kept, not
    /// the whole message (which may name resources).
    ContainsIgnoreCase,
}

/// `message` as it may appear in errors and logs: the first entry of `known` it matches
/// (see [`Pinned`]) verbatim, or its length and a keyed fingerprint ([`fingerprint`]).
pub fn redact(message: &str, known: &[&'static str], pinned: Pinned) -> ServerMessage {
    let hit = known.iter().find(|k| match pinned {
        Pinned::Exact => message == **k,
        Pinned::ContainsIgnoreCase => contains_ci(message, k),
    });
    match hit {
        Some(k) => ServerMessage::Known((*k).into()),
        None => fingerprint(message),
    }
}

/// `message` as its length and a keyed fingerprint (see the module docs), whatever it says.
pub fn fingerprint(message: &str) -> ServerMessage {
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(fingerprint_key())
        .expect("any key length");
    mac.update(message.as_bytes());
    let h = mac.finalize().into_bytes();
    let fp: String = h[..6].iter().map(|b| format!("{b:02x}")).collect();
    ServerMessage::redacted(message.len(), fp)
}

/// Per-process random key for message fingerprints, drawn from the OS RNG on first use.
fn fingerprint_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        getrandom::fill(&mut k).expect("operating system RNG failed");
        k
    })
}

/// `haystack` contains `needle`, ignoring ASCII case. An empty `needle` is always contained.
pub fn contains_ci(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// A server-sent request id as it may appear in errors and logs: 1–128 characters, all visible
/// ASCII ([`u8::is_ascii_graphic`]). Anything else (empty, too long, spaces, control or non-ASCII
/// characters) is `None`: the id is server-controlled and must not inject into logs.
pub fn request_id(id: &str) -> Option<&str> {
    ((1..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_graphic())).then_some(id)
}

/// The origin of a URL, `scheme://host:port`, for the `Debug` output of anything holding a URL
/// (a proxy URL may carry credentials in its userinfo; a path or query may carry tokens). The
/// port is the scheme's default when the URL names none, and is left out when the scheme has no
/// default. A string that does not parse as a URL is `<invalid URL>`.
pub fn url_origin(url: &str) -> String {
    let Ok(u) = reqwest::Url::parse(url) else {
        return "<invalid URL>".to_owned();
    };
    let host = u.host_str().unwrap_or("");
    match u.port_or_known_default() {
        Some(port) => format!("{}://{host}:{port}", u.scheme()),
        None => format!("{}://{host}", u.scheme()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(m: &str) -> String {
        match fingerprint(m) {
            ServerMessage::Redacted { fingerprint, .. } => fingerprint,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn fingerprint_is_keyed_and_stable_within_a_process() {
        assert_eq!(fp("echo: abc"), fp("echo: abc"));
        assert_ne!(fp("echo: abc"), fp("echo: abd"));
        assert_eq!(fp("echo: abc").len(), 12);
        // Not the unkeyed SHA-256 prefix.
        use sha2::Digest as _;
        let unkeyed: String = sha2::Sha256::digest(b"echo: abc")[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(fp("echo: abc"), unkeyed);
    }

    #[test]
    fn pinned_messages() {
        let known = &["Vault is sealed", "Rate exceeded"];
        assert_eq!(
            redact("Rate exceeded", known, Pinned::Exact),
            ServerMessage::Known("Rate exceeded".into())
        );
        assert!(matches!(
            redact("Rate exceeded!", known, Pinned::Exact),
            ServerMessage::Redacted { len: 14, .. }
        ));
        // The fragment is kept, not the message.
        assert_eq!(
            redact(
                "error: VAULT IS SEALED (key x)",
                known,
                Pinned::ContainsIgnoreCase
            ),
            ServerMessage::Known("Vault is sealed".into())
        );
        let r = redact("Key 'SECRET' not found", known, Pinned::ContainsIgnoreCase);
        assert!(!r.to_string().contains("SECRET"));
    }

    #[test]
    fn contains_ci_ignores_ascii_case() {
        assert!(contains_ci("Vault IS Sealed", "is sealed"));
        assert!(contains_ci("abc", ""));
        assert!(!contains_ci("ab", "abc"));
        assert!(!contains_ci("abc", "abd"));
    }

    #[test]
    fn request_ids_are_filtered() {
        assert_eq!(request_id("abc-123/X=="), Some("abc-123/X=="));
        assert_eq!(request_id(&"a".repeat(128)).map(str::len), Some(128));
        assert_eq!(request_id(&"a".repeat(129)), None);
        assert_eq!(request_id(""), None);
        assert_eq!(request_id("a b"), None);
        assert_eq!(request_id("a\nb"), None);
        assert_eq!(request_id("a\u{7f}"), None);
        assert_eq!(request_id("é"), None);
    }

    #[test]
    fn url_origin_drops_everything_but_the_origin() {
        assert_eq!(
            url_origin("http://user:SECRET@proxy.example:3128/p?token=SECRET#f"),
            "http://proxy.example:3128"
        );
        assert_eq!(
            url_origin("https://kms.example/x"),
            "https://kms.example:443"
        );
        assert_eq!(url_origin("http://[::1]:8200"), "http://[::1]:8200");
        assert_eq!(
            url_origin("socks5://u:p@10.0.0.1:1080"),
            "socks5://10.0.0.1:1080"
        );
        assert_eq!(url_origin("::not a url SECRET"), "<invalid URL>");
    }
}
