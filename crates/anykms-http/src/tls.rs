//! rustls crypto provider selection and the client TLS configuration.

use std::fmt;
use std::sync::Arc;

use anykms_core::{Error, ErrorKind, Operation, Result};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

fn config_err(backend: &'static str, m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, backend, Operation::Configure, m)
}

/// Whether `error` is the `Configuration` error of [`TlsOptions::build`] when the system trust store
/// holds no usable root certificate and no `ca_pem` replaces it, rather than any other
/// configuration problem. The facade's `with_default_providers()` skips a cloud provider on it.
pub fn is_missing_system_roots(error: &Error) -> bool {
    error.kind() == ErrorKind::Configuration
        && std::error::Error::source(error).is_some_and(|s| s.is::<NoSystemRoots>())
}

/// The source of the error [`is_missing_system_roots`] recognizes.
#[derive(Debug)]
struct NoSystemRoots;

impl fmt::Display for NoSystemRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the system trust store holds no usable root certificate")
    }
}

impl std::error::Error for NoSystemRoots {}

/// The rustls crypto provider and where it came from (`"configured"`, `"process default"`,
/// `"aws-lc-rs"` or `"ring"`), in this order:
///
/// 1. `configured`, the provider set in the backend's configuration;
/// 2. the process default ([`CryptoProvider::install_default`]);
/// 3. aws-lc-rs, with the `rustls-aws-lc-rs` feature;
/// 4. ring, with the `rustls-ring` feature.
///
/// An application's installed default (a FIPS provider, say) therefore wins over a provider that
/// a default feature enabled, and aws-lc-rs wins over ring when both features are on (features
/// unify across a dependency graph, so both can be on without anyone asking). With none of these,
/// `Configuration` naming the features and `setting` (the backend's configuration method for 1,
/// e.g. `"ServerConfig::crypto_provider"`). Nothing is installed process-wide.
pub fn select_provider(
    backend: &'static str,
    configured: Option<&Arc<CryptoProvider>>,
    setting: &'static str,
) -> Result<(Arc<CryptoProvider>, &'static str)> {
    // Used only when no provider feature is enabled.
    let _ = (backend, setting);
    if let Some(p) = configured {
        return Ok((p.clone(), "configured"));
    }
    if let Some(p) = CryptoProvider::get_default() {
        return Ok((p.clone(), "process default"));
    }
    #[cfg(feature = "rustls-aws-lc-rs")]
    return Ok((
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        "aws-lc-rs",
    ));
    #[cfg(all(feature = "rustls-ring", not(feature = "rustls-aws-lc-rs")))]
    return Ok((Arc::new(rustls::crypto::ring::default_provider()), "ring"));
    #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    {
        Err(Error::new(
            ErrorKind::Configuration,
            backend,
            Operation::Configure,
            format!(
                "no rustls crypto provider: enable the `rustls-ring` or `rustls-aws-lc-rs` \
                 feature, install a process default with CryptoProvider::install_default, or pass \
                 one to {setting}"
            ),
        ))
    }
}

/// [`select_provider`], with a debug event (`tracing` feature) naming the provider chosen.
pub fn crypto_provider(
    backend: &'static str,
    configured: Option<&Arc<CryptoProvider>>,
    setting: &'static str,
) -> Result<Arc<CryptoProvider>> {
    let (provider, source) = select_provider(backend, configured, setting)?;
    #[cfg(feature = "tracing")]
    tracing::debug!(
        backend,
        provider = source,
        "rustls crypto provider selected"
    );
    let _ = source;
    Ok(provider)
}

/// Decodes the first private key in `pem` (PKCS#8, PKCS#1 or SEC1). Unlike rustls-pki-types'
/// PEM reader, every intermediate buffer (base64 text, DER) is zeroizing; the DER moves into the
/// returned key, which rustls wipes after loading it. Encrypted keys are refused. Errors are
/// `Configuration` with fixed messages (never the contents).
pub fn private_key_from_pem(backend: &'static str, pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    use base64::Engine as _;
    use rustls_pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    let bad = || config_err(backend, "cannot parse the client key PEM");
    let encrypted = || config_err(backend, "encrypted client keys are not supported");
    let mut lines = pem
        .split(|&b| b == b'\n')
        .map(|l| l.trim_ascii())
        .filter(|l| !l.is_empty());
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix(b"-----BEGIN ")
            .and_then(|l| l.strip_suffix(b"-----"))
        else {
            continue;
        };
        let make: fn(Vec<u8>) -> PrivateKeyDer<'static> = match label {
            b"PRIVATE KEY" => |d| PrivatePkcs8KeyDer::from(d).into(),
            b"RSA PRIVATE KEY" => |d| PrivatePkcs1KeyDer::from(d).into(),
            b"EC PRIVATE KEY" => |d| PrivateSec1KeyDer::from(d).into(),
            b"ENCRYPTED PRIVATE KEY" => return Err(encrypted()),
            // Anything else (certificates, EC PARAMETERS, ...) is skipped.
            _ => continue,
        };
        let mut b64 = Zeroizing::new(Vec::with_capacity(pem.len()));
        let mut ended = false;
        for line in lines.by_ref() {
            if let Some(end) = line
                .strip_prefix(b"-----END ")
                .and_then(|l| l.strip_suffix(b"-----"))
            {
                if end != label {
                    return Err(bad());
                }
                ended = true;
                break;
            }
            if line.contains(&b':') {
                // RFC 1421 headers (`Proc-Type: 4,ENCRYPTED`): a legacy encrypted key.
                return Err(encrypted());
            }
            b64.extend_from_slice(line);
        }
        if !ended {
            return Err(bad());
        }
        let mut der = Zeroizing::new(vec![0u8; b64.len() / 4 * 3 + 3]);
        let n = base64::engine::general_purpose::STANDARD
            .decode_slice(&b64[..], &mut der[..])
            .map_err(|_| bad())?;
        der.truncate(n);
        // Moves the allocation out; the emptied Zeroizing has nothing left to wipe.
        return Ok(make(std::mem::take(&mut *der)));
    }
    Err(bad())
}

/// What goes into a client TLS configuration ([`TlsOptions::build`]).
///
/// Defaults: system roots (required), no client certificate, the provider of
/// [`select_provider`], ALPN `http/1.1` only.
#[derive(Clone)]
pub struct TlsOptions<'a> {
    ca_pem: Option<&'a [u8]>,
    client_identity: Option<(&'a [u8], &'a [u8])>,
    crypto_provider: Option<Arc<CryptoProvider>>,
    provider_setting: &'static str,
    require_roots: bool,
    http2: bool,
}

impl fmt::Debug for TlsOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsOptions")
            .field("ca_pem", &self.ca_pem.is_some())
            .field("client_identity", &self.client_identity.is_some())
            .field("crypto_provider", &self.crypto_provider.is_some())
            .field("require_roots", &self.require_roots)
            .field("http2", &self.http2)
            .finish()
    }
}

impl Default for TlsOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TlsOptions<'a> {
    /// The defaults.
    pub fn new() -> Self {
        Self {
            ca_pem: None,
            client_identity: None,
            crypto_provider: None,
            provider_setting: "the backend's crypto_provider setting",
            require_roots: true,
            http2: false,
        }
    }

    /// Trusts only the certificates in `pem` instead of the system roots.
    pub fn ca_pem(mut self, pem: Option<&'a [u8]>) -> Self {
        self.ca_pem = pem;
        self
    }

    /// Presents a client certificate chain and its private key (PEM; see
    /// [`private_key_from_pem`]).
    pub fn client_identity(mut self, identity: Option<(&'a [u8], &'a [u8])>) -> Self {
        self.client_identity = identity;
        self
    }

    /// The configured crypto provider (first in [`select_provider`]'s order), and the name of the
    /// backend setting that configures it, for the error when no provider is available.
    pub fn crypto_provider(
        mut self,
        provider: Option<Arc<CryptoProvider>>,
        setting: &'static str,
    ) -> Self {
        self.crypto_provider = provider;
        self.provider_setting = setting;
        self
    }

    /// Whether having no trusted root is an error (default `true`). A client used only for
    /// plain-HTTP loopback servers needs none.
    pub fn require_roots(mut self, require: bool) -> Self {
        self.require_roots = require;
        self
    }

    /// Offers HTTP/2 in ALPN (`h2`, then `http/1.1`); default `http/1.1` only.
    pub fn http2(mut self, http2: bool) -> Self {
        self.http2 = http2;
        self
    }

    /// Builds the rustls client configuration: safe default protocol versions, the roots, the
    /// optional client certificate, and ALPN. Errors are `Configuration` with fixed messages.
    pub fn build(&self, backend: &'static str) -> Result<rustls::ClientConfig> {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;

        let err = |m| config_err(backend, m);
        let mut roots = rustls::RootCertStore::empty();
        match self.ca_pem {
            Some(pem) => {
                for cert in CertificateDer::pem_slice_iter(pem) {
                    let cert = cert.map_err(|_| err("cannot parse the CA certificate PEM"))?;
                    roots.add(cert).map_err(|_| err("invalid CA certificate"))?;
                }
                if roots.is_empty() {
                    return Err(err("the CA certificate PEM contains no certificates"));
                }
            }
            None => {
                let loaded = rustls_native_certs::load_native_certs();
                for cert in loaded.certs {
                    let _ = roots.add(cert);
                }
            }
        }
        if roots.is_empty() && self.require_roots {
            // Only the system roots can come up empty here: an empty `ca_pem` failed above.
            return Err(
                err("no trusted CA certificates (system roots unavailable and no ca_pem)")
                    .with_source(NoSystemRoots),
            );
        }
        let provider = crypto_provider(
            backend,
            self.crypto_provider.as_ref(),
            self.provider_setting,
        )?;
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| err("TLS configuration failed"))?
            .with_root_certificates(roots);
        let mut tls = match self.client_identity {
            Some((cert, key)) => {
                let chain = CertificateDer::pem_slice_iter(cert)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| err("cannot parse the client certificate PEM"))?;
                let key = private_key_from_pem(backend, key)?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|_| err("invalid client certificate or key"))?
            }
            None => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = if self.http2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        Ok(tls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the empty-system-roots error is recognized, not another `Configuration` error with
    /// the same backend.
    #[test]
    fn missing_system_roots_is_recognized() {
        let e = config_err("x", "no trusted CA certificates").with_source(NoSystemRoots);
        assert!(is_missing_system_roots(&e));
        assert!(!is_missing_system_roots(&config_err(
            "x",
            "the CA certificate PEM contains no certificates"
        )));
        let e = TlsOptions::new()
            .ca_pem(Some(b"no certificates here"))
            .build("x")
            .unwrap_err();
        assert!(!is_missing_system_roots(&e), "{e}");
    }

    const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

    /// The published crate does not ship `tests/` (no test keys in the package): the tests that
    /// read them pass without checking anything when run from an unpacked package. In the
    /// repository the directory always exists.
    fn unpackaged() -> bool {
        let missing = !std::path::Path::new(DATA).is_dir();
        if missing {
            eprintln!("skipped: {DATA} is not in the package");
        }
        missing
    }

    fn data(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DATA}/{name}")).unwrap()
    }

    #[test]
    fn private_keys_decode_like_pki_types() {
        use rustls_pki_types::pem::PemObject;
        if unpackaged() {
            return;
        }
        // Test-only keys: PKCS#8, SEC1 (after an EC PARAMETERS block) and PKCS#1.
        for name in ["server-key.pem", "sec1-key.pem", "rsa-pkcs1-key.pem"] {
            let pem = data(name);
            let ours = private_key_from_pem("t", &pem).unwrap();
            let theirs = PrivateKeyDer::from_pem_slice(&pem).unwrap();
            assert_eq!(ours, theirs);
        }
        let crlf = String::from_utf8(data("server-key.pem"))
            .unwrap()
            .replace('\n', "\r\n");
        assert!(private_key_from_pem("t", crlf.as_bytes()).is_ok());
        let enc =
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let e = private_key_from_pem("t", enc).unwrap_err();
        assert!(e.to_string().contains("encrypted"), "{e}");
        let legacy = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(private_key_from_pem("t", legacy).is_err());
        let ca = data("ca.pem");
        for bad in [
            &b""[..],
            &ca,
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n",
            b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        ] {
            assert!(private_key_from_pem("t", bad).is_err());
        }
    }

    /// The configured provider always wins; without one (and with no process default installed
    /// in this test binary) the features decide.
    #[test]
    fn provider_precedence() {
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        {
            if unpackaged() {
                return;
            }
            let (p, source) = select_provider("t", None, "x").unwrap();
            #[cfg(feature = "rustls-aws-lc-rs")]
            assert_eq!(source, "aws-lc-rs");
            #[cfg(not(feature = "rustls-aws-lc-rs"))]
            assert_eq!(source, "ring");
            let mine = Arc::new(CryptoProvider {
                cipher_suites: vec![],
                ..(*p).clone()
            });
            let (chosen, source) = select_provider("t", Some(&mine), "x").unwrap();
            assert_eq!(source, "configured");
            assert!(Arc::ptr_eq(&chosen, &mine));
            // A provider without cipher suites cannot build a TLS config: proof it is used.
            let e = TlsOptions::new()
                .ca_pem(Some(&data("ca.pem")))
                .crypto_provider(Some(mine), "x")
                .build("t")
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration);
            TlsOptions::new()
                .ca_pem(Some(&data("ca.pem")))
                .build("t")
                .unwrap();
        }
        #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
        {
            let e = select_provider("t", None, "Cfg::crypto_provider").unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration);
            assert!(e.to_string().contains("rustls-aws-lc-rs"), "{e}");
            assert!(e.to_string().contains("Cfg::crypto_provider"), "{e}");
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn alpn_and_identity() {
        if unpackaged() {
            return;
        }
        let ca = data("ca.pem");
        let tls = TlsOptions::new().ca_pem(Some(&ca)).build("t").unwrap();
        assert_eq!(tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let tls = TlsOptions::new()
            .ca_pem(Some(&ca))
            .http2(true)
            .build("t")
            .unwrap();
        assert_eq!(tls.alpn_protocols[0], b"h2".to_vec());
        let (cert, key) = (data("server.pem"), data("server-key.pem"));
        TlsOptions::new()
            .ca_pem(Some(&ca))
            .client_identity(Some((&cert, &key)))
            .build("t")
            .unwrap();
        let e = TlsOptions::new()
            .ca_pem(Some(b"no certs"))
            .build("t")
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
    }
}
