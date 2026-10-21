//! Server configuration.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anykms_core::{Error, ErrorKind, Operation, Result};
use anykms_http::HttpTransport;
use anykms_http::url::Url;

use crate::BACKEND;
use crate::auth::Login;
use crate::token::{EnvToken, FileToken, NoToken, StaticToken, TokenSource};
use crate::uri::{namespace_ok, reserved_segment, segment_ok};

/// The server implementation. It is a property of the configured server, never of the key URI,
/// so moving a server from Vault to OpenBao never forces stored URIs to change.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flavor {
    /// HashiCorp Vault.
    Vault,
    /// OpenBao.
    OpenBao,
}

/// One Vault or OpenBao server.
#[derive(Clone)]
pub struct ServerConfig {
    pub(crate) address: String,
    pub(crate) flavor: Flavor,
    pub(crate) token: Arc<dyn TokenSource>,
    pub(crate) login: Option<Login>,
    pub(crate) namespace: Option<String>,
    pub(crate) allowed_namespaces: Vec<String>,
    pub(crate) allowed_mounts: Option<Vec<String>>,
    pub(crate) http_transport: Option<Arc<dyn HttpTransport>>,
    pub(crate) allow_loopback_http: bool,
    pub(crate) max_response_bytes: usize,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("address", &anykms_http::redact::url_origin(&self.address))
            .field("flavor", &self.flavor)
            .field("token", &self.token)
            .field("login", &self.login)
            .field("namespace", &self.namespace)
            .field("allowed_namespaces", &self.allowed_namespaces)
            .field("allowed_mounts", &self.allowed_mounts)
            .field("http_transport", &self.http_transport.is_some())
            .field("allow_loopback_http", &self.allow_loopback_http)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

fn config_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

/// The reason an I/O operation failed, without the `(os error N)` suffix. `io::Error` messages
/// name the failure (`No such file or directory`), never file contents.
pub(crate) fn io_reason(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error ") {
        Some(i) => s[..i].to_owned(),
        None => s,
    }
}

/// `cannot read the <what> <path> (<var>): <reason>`, with the I/O error as its source. Paths are
/// not secret; contents never appear.
fn file_err(what: &str, var: &str, path: &std::path::Path, e: std::io::Error) -> Error {
    config_err(format!(
        "cannot read the {what} {} ({var}): {}",
        path.display(),
        io_reason(&e)
    ))
    .with_source(e)
}

impl ServerConfig {
    /// A server at `address` (e.g. `https://vault.internal:8200`). Sends no token until one is
    /// configured.
    pub fn new(address: impl Into<String>, flavor: Flavor) -> Self {
        Self {
            address: address.into().trim_end_matches('/').to_owned(),
            flavor,
            token: Arc::new(NoToken),
            login: None,
            namespace: None,
            allowed_namespaces: Vec::new(),
            allowed_mounts: None,
            http_transport: None,
            allow_loopback_http: false,
            max_response_bytes: 32 * 1024 * 1024,
        }
    }

    /// Sets the token source. Replaces a [`login`](Self::login).
    pub fn token_source(mut self, source: Arc<dyn TokenSource>) -> Self {
        self.token = source;
        self.login = None;
        self
    }

    /// Logs in with an auth method (Kubernetes or JWT) and renews the token (see [`Login`]).
    /// Replaces the token source; a later token setter replaces the login.
    pub fn login(mut self, login: Login) -> Self {
        self.login = Some(login);
        self
    }

    /// Uses a fixed token. It is never renewed (see [`TokenSource`]).
    pub fn token(self, token: impl Into<String>) -> Self {
        self.token_source(Arc::new(StaticToken::new(token)))
    }

    /// Reads the token from a file (e.g. a Vault/Bao Agent sink). On Unix the file must not be
    /// group- or world-accessible (see [`FileToken`] for the Agent and Kubernetes settings); to
    /// accept such a file, pass `FileToken::new(path).allow_insecure_permissions()` to
    /// [`token_source`](Self::token_source).
    pub fn token_file(self, path: impl Into<PathBuf>) -> Self {
        self.token_source(Arc::new(FileToken::new(path)))
    }

    /// Reads the token from an environment variable on every request.
    pub fn token_env(self, var: impl Into<String>) -> Self {
        self.token_source(Arc::new(EnvToken::new(var)))
    }

    /// Sends no token (Vault/Bao Agent API proxy with `use_auto_auth_token`).
    pub fn no_token(self) -> Self {
        self.token_source(Arc::new(NoToken))
    }

    /// The namespace used for every request (note: Vault CE silently ignores namespaces).
    pub fn namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Additional namespaces a key URI may select with `?namespace=`.
    pub fn allowed_namespaces<I: IntoIterator<Item = S>, S: Into<String>>(mut self, ns: I) -> Self {
        self.allowed_namespaces = ns.into_iter().map(Into::into).collect();
        self
    }

    /// Restricts the mounts key URIs may use.
    ///
    /// Without this list any single-segment mount (`transit`, `transit-envelope`) may be used. A
    /// multi-segment mount (`team-a/transit`) is opened **only** when listed here: Vault
    /// Enterprise resolves leading path segments as namespaces, so an unlisted
    /// `team-b/transit` would reach namespace `team-b` and bypass
    /// [`allowed_namespaces`](Self::allowed_namespaces). List such a mount only when it is a real
    /// mount path, or prefer `?namespace=` for namespaces. Mounts with a reserved segment (`sys`,
    /// `auth`, `identity`, `cubbyhole`) are always refused.
    pub fn allowed_mounts<I: IntoIterator<Item = S>, S: Into<String>>(mut self, mounts: I) -> Self {
        self.allowed_mounts = Some(mounts.into_iter().map(Into::into).collect());
        self
    }

    /// The HTTP transport this server is reached through. It owns TLS trust and client
    /// certificates, the crypto provider, timeouts, proxying and the HTTP version: configure them
    /// on [`ReqwestTransportBuilder`](anykms_http::ReqwestTransportBuilder) (the built-in
    /// transport, feature `reqwest`) or bring any [`HttpTransport`]. Without this, a default
    /// `ReqwestTransport` is built; without the `reqwest` feature, building the provider fails
    /// with `Configuration`. One transport may be shared by several servers and providers.
    pub fn http_transport(mut self, transport: impl HttpTransport) -> Self {
        self.http_transport = Some(Arc::new(transport));
        self
    }

    /// Whether a transport is set ([`http_transport`](Self::http_transport), or one [`EnvConfig`]
    /// built from the TLS variables). Without one the server builds a default `ReqwestTransport`;
    /// an application that shares one transport across providers sets it only then.
    pub fn has_http_transport(&self) -> bool {
        self.http_transport.is_some()
    }

    /// Allows plain `http://` for literal loopback addresses (`127.0.0.0/8`, `::1`), e.g. a
    /// Vault/Bao Agent API proxy. Any other plain-HTTP address is refused.
    pub fn allow_loopback_http(mut self) -> Self {
        self.allow_loopback_http = true;
        self
    }

    /// Maximum response body size (default 32 MiB, at least 64 KiB:
    /// [`MIN_RESPONSE_BYTES`](anykms_http::client::MIN_RESPONSE_BYTES)).
    pub fn max_response_bytes(mut self, n: usize) -> Self {
        self.max_response_bytes = n;
        self
    }

    /// The configured address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The flavor.
    pub fn flavor(&self) -> Flavor {
        self.flavor
    }

    pub(crate) fn validate(&self) -> Result<Url> {
        let url = Url::parse(&self.address)
            .map_err(|_| config_err("server address is not a valid URL"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(config_err("server address must not contain credentials"));
        }
        if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
            return Err(config_err("server address must be scheme://host[:port]"));
        }
        match url.scheme() {
            "https" => {}
            "http" => {
                let loopback = match url.host() {
                    Some(anykms_http::url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
                    Some(anykms_http::url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
                    _ => false,
                };
                if !loopback {
                    return Err(config_err(
                        "plain http:// is only allowed for literal loopback IPs (127.0.0.0/8, ::1); use https://",
                    ));
                }
                if !self.allow_loopback_http {
                    return Err(config_err(
                        "plain http:// requires ServerConfig::allow_loopback_http()",
                    ));
                }
            }
            _ => return Err(config_err("server address must use https://")),
        }
        if let Some(ns) = &self.namespace
            && !namespace_ok(ns)
        {
            return Err(config_err("invalid namespace"));
        }
        if !self.allowed_namespaces.iter().all(|n| namespace_ok(n)) {
            return Err(config_err("invalid allowed namespace"));
        }
        if let Some(m) = &self.allowed_mounts {
            if !m
                .iter()
                .all(|m| !m.is_empty() && m.split('/').all(segment_ok))
            {
                return Err(config_err("invalid allowed mount"));
            }
            if m.iter().any(|m| m.split('/').any(reserved_segment)) {
                return Err(config_err(
                    "allowed mounts cannot use a reserved segment (sys, auth, identity, cubbyhole)",
                ));
            }
        }
        if let Some(l) = &self.login {
            l.validate()?;
        }
        // Zero would make every response too large with a transient-looking error; refuse it up
        // front instead.
        if self.max_response_bytes < anykms_http::client::MIN_RESPONSE_BYTES {
            return Err(config_err(
                "max_response_bytes must be at least 64 KiB (anykms_http::client::MIN_RESPONSE_BYTES)",
            ));
        }
        Ok(url)
    }
}

/// Loads a [`ServerConfig`] from environment variables.
///
/// Vault: `VAULT_ADDR`, then the token (`VAULT_TOKEN`, else `VAULT_TOKEN_FILE`, else
/// `~/.vault-token`), `VAULT_NAMESPACE`, `VAULT_CACERT` or `VAULT_CAPATH`, `VAULT_CLIENT_CERT`
/// and `VAULT_CLIENT_KEY`.
///
/// OpenBao reads the `BAO_*` equivalents when `BAO_ADDR` is set, otherwise the `VAULT_*` ones.
/// **Every setting comes from the prefix that supplied the address**, so a token is never sent
/// to an address configured under the other prefix: with `BAO_ADDR`, `VAULT_*` variables are
/// ignored; with `VAULT_ADDR`, any `BAO_*` setting makes loading fail. The home token files are
/// `~/.bao-token`, then `~/.vault-token`.
///
/// - **A token source is required.** Loading fails if none of the token variables or home files
///   is present. Behind a Vault/Bao Agent API proxy with `use_auto_auth_token`, opt out with
///   [`no_token`](Self::no_token) or `ANYKMS_TRANSIT_NO_TOKEN=1` (or `true`), which also ignores
///   any token variables.
/// - **Login.** `ANYKMS_TRANSIT_AUTH=kubernetes` or `ANYKMS_TRANSIT_AUTH=jwt` logs in and renews
///   the token ([`Login`]) instead of reading one; the token variables are then ignored.
///   `ANYKMS_TRANSIT_AUTH_ROLE` is required; `ANYKMS_TRANSIT_AUTH_JWT_FILE` is required for `jwt`
///   (for `kubernetes` it replaces the service-account token path); `ANYKMS_TRANSIT_AUTH_MOUNT`
///   overrides the auth mount (default `kubernetes` or `jwt`).
/// - **Renamed variables.** The unprefixed `ANYKMS_AUTH`, `ANYKMS_AUTH_ROLE`,
///   `ANYKMS_AUTH_JWT_FILE`, `ANYKMS_AUTH_MOUNT`, `ANYKMS_NO_TOKEN` and
///   `ANYKMS_ALLOW_INSECURE_TOKEN_FILE` are now `ANYKMS_TRANSIT_*`. There are no aliases: any of
///   the old names that is set makes loading fail with `Configuration` naming its replacement,
///   even when the new name is set too. These are names used before 0.1.0; they are refused so
///   that a stale setting fails loudly, and the check may be removed in a future release.
/// - **TLS.** `*_SKIP_VERIFY=true` makes loading **fail** (there is no way to skip TLS
///   verification). `*_CACERT` (a PEM file) or `*_CAPATH` (a directory of PEM files; each
///   regular file must hold at least one certificate, subdirectories are skipped) replace the
///   system roots; as with the Vault CLI, `*_CACERT` wins when both are set. Plain `http://` is
///   allowed automatically only for literal loopback addresses.
/// - **Token files** must not be group- or world-accessible ([`FileToken`]). To accept one
///   anyway (e.g. a Kubernetes secret volume you cannot re-mode), call
///   [`allow_insecure_token_file`](Self::allow_insecure_token_file) or set
///   `ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE=1` (or `true`).
#[derive(Clone, Debug)]
pub struct EnvConfig {
    flavor: Flavor,
    home_token: bool,
    insecure_token_file: bool,
    no_token: bool,
}

/// Every per-prefix setting except the address.
const SETTINGS: &[&str] = &[
    "TOKEN",
    "TOKEN_FILE",
    "NAMESPACE",
    "CACERT",
    "CAPATH",
    "CLIENT_CERT",
    "CLIENT_KEY",
    "SKIP_VERIFY",
];

/// Upper bound for the client key file.
const MAX_KEY_FILE: usize = 1024 * 1024;

/// An environment-variable lookup shared with the sources that read variables later
/// ([`EnvToken`] re-reads `*_TOKEN` on every request).
pub(crate) type EnvLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The unprefixed names used before 0.1.0, now `ANYKMS_TRANSIT_*`, with their replacements. A set
/// old name is `Configuration` (no aliases), so that a stale setting fails loudly. This table and
/// its check may be removed in a future release.
const RENAMED: &[(&str, &str)] = &[
    ("ANYKMS_AUTH", "ANYKMS_TRANSIT_AUTH"),
    ("ANYKMS_AUTH_ROLE", "ANYKMS_TRANSIT_AUTH_ROLE"),
    ("ANYKMS_AUTH_JWT_FILE", "ANYKMS_TRANSIT_AUTH_JWT_FILE"),
    ("ANYKMS_AUTH_MOUNT", "ANYKMS_TRANSIT_AUTH_MOUNT"),
    ("ANYKMS_NO_TOKEN", "ANYKMS_TRANSIT_NO_TOKEN"),
    (
        "ANYKMS_ALLOW_INSECURE_TOKEN_FILE",
        "ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE",
    ),
];

fn flag(v: Option<String>) -> bool {
    v.is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

/// Reads a `*_CACERT` PEM file; `var` names the setting in errors.
fn read_ca_file(path: &std::path::Path, var: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| file_err("CA certificate file", var, path, e))
}

/// Concatenates the PEM files in a `*_CAPATH` directory (sorted by name, symlinks followed,
/// subdirectories skipped). Every file must hold at least one certificate.
fn read_ca_dir(dir: &str, var: &str) -> Result<Vec<u8>> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    let dir_err = |e| file_err("CA certificate directory", var, dir.as_ref(), e);
    let mut paths = std::fs::read_dir(dir)
        .map_err(dir_err)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(dir_err)?;
    paths.sort();
    let mut pem = Vec::new();
    for path in paths {
        let file_err = |e| file_err("CA certificate file", var, &path, e);
        if std::fs::metadata(&path).map_err(file_err)?.is_dir() {
            continue;
        }
        let file = std::fs::read(&path).map_err(file_err)?;
        let mut certs = 0;
        for cert in CertificateDer::pem_slice_iter(&file) {
            cert.map_err(|_| {
                config_err(format!(
                    "{var}: cannot parse the certificate file {}",
                    path.display()
                ))
            })?;
            certs += 1;
        }
        if certs == 0 {
            return Err(config_err(format!(
                "{var}: {} holds no PEM certificate",
                path.display()
            )));
        }
        pem.extend_from_slice(&file);
        pem.push(b'\n');
    }
    if pem.is_empty() {
        return Err(config_err(format!(
            "{var}: the directory {dir} holds no certificates"
        )));
    }
    Ok(pem)
}

impl EnvConfig {
    /// Vault variables.
    pub fn vault() -> Self {
        Self {
            flavor: Flavor::Vault,
            home_token: true,
            insecure_token_file: false,
            no_token: false,
        }
    }

    /// OpenBao variables (`BAO_*` when `BAO_ADDR` is set, otherwise `VAULT_*`).
    pub fn openbao() -> Self {
        Self {
            flavor: Flavor::OpenBao,
            ..Self::vault()
        }
    }

    /// Never fall back to the `~/.vault-token` (or `~/.bao-token`) file.
    pub fn no_home_token(mut self) -> Self {
        self.home_token = false;
        self
    }

    /// Accepts a group- or world-accessible token file
    /// ([`FileToken::allow_insecure_permissions`]). Same as setting
    /// `ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE=1`.
    pub fn allow_insecure_token_file(mut self) -> Self {
        self.insecure_token_file = true;
        self
    }

    /// Sends no token ([`ServerConfig::no_token`]), for a Vault/Bao Agent API proxy with
    /// `use_auto_auth_token`; token variables and files are ignored. Same as setting
    /// `ANYKMS_TRANSIT_NO_TOKEN=1`. Without it, loading fails when no token source is found.
    pub fn no_token(mut self) -> Self {
        self.no_token = true;
        self
    }

    /// Prefixes in precedence order: `BAO_*` before `VAULT_*` for OpenBao.
    fn prefixes(&self) -> &'static [&'static str] {
        match self.flavor {
            Flavor::OpenBao => &["BAO", "VAULT"],
            _ => &["VAULT"],
        }
    }

    /// Loads the configuration from the process environment.
    pub fn load(&self) -> Result<ServerConfig> {
        self.load_from(&|name| std::env::var(name).ok(), None)
    }

    /// Loads the configuration, reading variables from `lookup` instead of the process
    /// environment (`None` is unset; an empty value counts as unset, as with [`load`](Self::load)).
    /// The lookup is kept for variables read later: with `*_TOKEN`, every request re-reads the
    /// token through it ([`EnvToken`]). Files the variables name (`*_TOKEN_FILE`, `*_CACERT`,
    /// `~/.vault-token`, ...) are still read from the file system.
    pub fn load_with(
        &self,
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<ServerConfig> {
        let lookup: EnvLookup = Arc::new(lookup);
        self.load_from(&*lookup, Some(lookup.clone()))
    }

    /// `token_lookup`: where [`EnvToken`] re-reads the token (`None`: the process environment).
    fn load_from(
        &self,
        get: &dyn Fn(&str) -> Option<String>,
        token_lookup: Option<EnvLookup>,
    ) -> Result<ServerConfig> {
        if let Some((old, new)) = RENAMED.iter().find(|(old, _)| get(old).is_some()) {
            return Err(config_err(format!(
                "{old} was renamed to {new}: set {new} instead and unset {old}"
            )));
        }
        let set = |name: &str| get(name).filter(|v| !v.is_empty());
        // The prefix that supplies the address supplies every other setting too.
        let (prefix, addr) = self
            .prefixes()
            .iter()
            .find_map(|p| set(&format!("{p}_ADDR")).map(|a| (*p, a)))
            .ok_or_else(|| {
                config_err(match self.flavor {
                    Flavor::OpenBao => "BAO_ADDR (or VAULT_ADDR) is not set",
                    _ => "VAULT_ADDR is not set",
                })
            })?;
        if self.flavor == Flavor::OpenBao
            && prefix == "VAULT"
            && let Some(s) = SETTINGS.iter().find(|s| set(&format!("BAO_{s}")).is_some())
        {
            return Err(config_err(format!(
                "BAO_{s} is set but the address comes from VAULT_ADDR; every setting is read \
                     from the prefix that supplies the address: set BAO_ADDR, or unset BAO_{s}"
            )));
        }
        let var = |suffix: &str| set(&format!("{prefix}_{suffix}"));
        if let Some(v) = var("SKIP_VERIFY")
            && !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no")
        {
            return Err(config_err(format!(
                "{prefix}_SKIP_VERIFY is set; anykms never skips TLS verification"
            )));
        }
        let mut c = ServerConfig::new(addr, self.flavor);
        let insecure_ok =
            self.insecure_token_file || flag(get("ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE"));
        let token_file = |c: ServerConfig, path: PathBuf| {
            let f = FileToken::new(path);
            let f = if insecure_ok {
                f.allow_insecure_permissions()
            } else {
                f
            };
            c.token_source(Arc::new(f))
        };
        let home_files: &[&str] = match self.flavor {
            Flavor::OpenBao => &[".bao-token", ".vault-token"],
            _ => &[".vault-token"],
        };
        let home_file = || {
            let home = set("HOME").filter(|_| self.home_token)?;
            home_files
                .iter()
                .map(|f| PathBuf::from(&home).join(f))
                .find(|p| p.exists())
        };
        let no_token = self.no_token || flag(get("ANYKMS_TRANSIT_NO_TOKEN"));
        let source = if let Some(method) = set("ANYKMS_TRANSIT_AUTH") {
            if no_token {
                return Err(config_err(
                    "ANYKMS_TRANSIT_AUTH and no_token (ANYKMS_TRANSIT_NO_TOKEN) are both set; choose one",
                ));
            }
            let role = set("ANYKMS_TRANSIT_AUTH_ROLE").ok_or_else(|| {
                config_err("ANYKMS_TRANSIT_AUTH is set but ANYKMS_TRANSIT_AUTH_ROLE is not")
            })?;
            let jwt_file = set("ANYKMS_TRANSIT_AUTH_JWT_FILE");
            let mut login = match method.to_ascii_lowercase().as_str() {
                "kubernetes" => Login::kubernetes(role),
                "jwt" => Login::jwt(
                    role,
                    jwt_file.clone().ok_or_else(|| {
                        config_err("ANYKMS_TRANSIT_AUTH=jwt requires ANYKMS_TRANSIT_AUTH_JWT_FILE")
                    })?,
                ),
                _ => {
                    return Err(config_err(
                        "ANYKMS_TRANSIT_AUTH must be `kubernetes` or `jwt`",
                    ));
                }
            };
            if let Some(path) = jwt_file {
                login = login.jwt_file(path);
            }
            if let Some(mount) = set("ANYKMS_TRANSIT_AUTH_MOUNT") {
                login = login.mount(mount);
            }
            c = c.login(login);
            "login"
        } else if no_token {
            c = c.no_token();
            "none (explicit)"
        } else if var("TOKEN").is_some() {
            let name = format!("{prefix}_TOKEN");
            c = match token_lookup {
                Some(lookup) => c.token_source(Arc::new(EnvToken::with_lookup(name, lookup))),
                None => c.token_env(name),
            };
            "environment variable"
        } else if let Some(path) = var("TOKEN_FILE") {
            c = token_file(c, path.into());
            "token file"
        } else if let Some(path) = home_file() {
            c = token_file(c, path);
            "home token file"
        } else {
            let mut sources = format!("{prefix}_TOKEN, {prefix}_TOKEN_FILE");
            if self.home_token {
                for f in home_files {
                    sources.push_str(", ~/");
                    sources.push_str(f);
                }
            }
            let ignored = if prefix == "BAO" && set("VAULT_TOKEN").is_some() {
                " (VAULT_TOKEN is ignored because the address comes from BAO_ADDR)"
            } else {
                ""
            };
            return Err(config_err(format!(
                "no token found (checked {sources}){ignored}; behind a Vault/Bao Agent API proxy \
                 with use_auto_auth_token, opt out with EnvConfig::no_token() or ANYKMS_TRANSIT_NO_TOKEN=1"
            )));
        };
        #[cfg(feature = "tracing")]
        tracing::info!(token_source = source, prefix, flavor = ?self.flavor, "transit configuration loaded from environment");
        let _ = source;
        if let Some(ns) = var("NAMESPACE") {
            c = c.namespace(ns);
        }
        // As in the Vault CLI, CACERT takes precedence over CAPATH.
        let tls = EnvTls::load(prefix, &var)?;
        if let Some(tls) = tls {
            c.http_transport = Some(tls.transport()?);
        }
        // Scheme from the parsed URL (case-insensitive); validate() still enforces loopback-only.
        if Url::parse(&c.address).is_ok_and(|u| u.scheme() == "http") {
            c = c.allow_loopback_http();
        }
        c.validate()?;
        Ok(c)
    }
}

/// The TLS settings `EnvConfig` reads (`*_CACERT` or `*_CAPATH`, `*_CLIENT_CERT` with
/// `*_CLIENT_KEY`), which configure the built-in transport.
#[cfg_attr(not(feature = "reqwest"), allow(dead_code))]
struct EnvTls {
    ca_pem: Option<Vec<u8>>,
    client_identity: Option<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>)>,
}

impl EnvTls {
    /// `None` when no TLS variable is set (the default transport then applies).
    fn load(prefix: &str, var: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        let ca_pem = if let Some(path) = var("CACERT") {
            Some(read_ca_file(path.as_ref(), &format!("{prefix}_CACERT"))?)
        } else if let Some(dir) = var("CAPATH") {
            Some(read_ca_dir(&dir, &format!("{prefix}_CAPATH"))?)
        } else {
            None
        };
        let client_identity = match (var("CLIENT_CERT"), var("CLIENT_KEY")) {
            (Some(cert), Some(key)) => {
                let cert = std::fs::read(&cert).map_err(|e| {
                    file_err(
                        "client certificate file",
                        &format!("{prefix}_CLIENT_CERT"),
                        cert.as_ref(),
                        e,
                    )
                })?;
                // Read straight into a zeroizing buffer (std::fs::read could leave copies).
                let key =
                    anykms_http::zbuf::read_file(key.as_ref(), MAX_KEY_FILE).map_err(|e| {
                        file_err(
                            "client key file",
                            &format!("{prefix}_CLIENT_KEY"),
                            key.as_ref(),
                            e,
                        )
                    })?;
                Some((cert, key))
            }
            (None, None) => None,
            _ => {
                return Err(config_err(format!(
                    "set both {prefix}_CLIENT_CERT and {prefix}_CLIENT_KEY, or neither"
                )));
            }
        };
        Ok(match (ca_pem, client_identity) {
            (None, None) => None,
            (ca_pem, client_identity) => Some(Self {
                ca_pem,
                client_identity,
            }),
        })
    }

    /// The built-in transport with these settings (feature `reqwest`); without the feature,
    /// `Configuration`: TLS settings belong to the transport the application injects.
    fn transport(self) -> Result<Arc<dyn HttpTransport>> {
        #[cfg(feature = "reqwest")]
        {
            let mut b = anykms_http::ReqwestTransport::builder();
            if let Some(pem) = self.ca_pem {
                b = b.ca_pem(pem);
            }
            if let Some((cert, mut key)) = self.client_identity {
                // The key moves out of its zeroizing buffer into the builder's.
                b = b.client_identity(cert, std::mem::take(&mut *key));
            }
            Ok(Arc::new(b.build()?))
        }
        #[cfg(not(feature = "reqwest"))]
        {
            let Self { .. } = self;
            Err(config_err(
                "TLS variables (*_CACERT, *_CAPATH, *_CLIENT_CERT, *_CLIENT_KEY) configure the \
                 built-in transport, which needs the `reqwest` feature; configure TLS on the \
                 transport passed to ServerConfig::http_transport instead",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn load(cfg: &EnvConfig, vars: &[(&str, &str)]) -> Result<ServerConfig> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        cfg.load_with(move |n| vars.get(n).cloned())
    }

    #[test]
    fn renamed_variables_are_refused() {
        let base = [
            ("VAULT_ADDR", "https://vault.example:8200"),
            ("VAULT_TOKEN", "t"),
        ];
        assert_eq!(RENAMED.len(), 6);
        for (old, new) in RENAMED {
            // Set alone, set next to its new name, and set but empty: always refused.
            for with_new in [false, true] {
                for value in ["1", ""] {
                    let mut vars = base.to_vec();
                    vars.push((old, value));
                    if with_new {
                        vars.push((new, "1"));
                    }
                    let e = load(&EnvConfig::vault(), &vars).unwrap_err();
                    assert_eq!(e.kind(), ErrorKind::Configuration, "{old}: {e}");
                    assert!(
                        e.message().contains(&format!("{old} was renamed to {new}")),
                        "{old}: {e}"
                    );
                }
            }
        }
        assert!(load(&EnvConfig::vault(), &base).is_ok());
    }

    #[tokio::test]
    async fn token_variable_is_reread_through_the_lookup() {
        use std::sync::Mutex;
        let token = Arc::new(Mutex::new("first".to_owned()));
        let t = token.clone();
        // A name the process environment never holds: the token must come from the lookup.
        let c = EnvConfig::openbao()
            .load_with(move |n| match n {
                "BAO_ADDR" => Some("https://bao.example:8200".to_owned()),
                "BAO_TOKEN" => Some(t.lock().unwrap().clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(token_debug(&c), r#"EnvToken("BAO_TOKEN")"#);
        let read = || async { c.token.token().await.unwrap().unwrap() };
        assert_eq!(read().await.expose(), "first");
        *token.lock().unwrap() = "second".to_owned();
        assert_eq!(read().await.expose(), "second");
        *token.lock().unwrap() = String::new();
        let e = c.token.token().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
    }

    fn token_debug(c: &ServerConfig) -> String {
        format!("{:?}", c.token)
    }

    #[test]
    fn login_from_environment() {
        let addr = ("VAULT_ADDR", "https://vault.example:8200");
        let login = |vars: &[(&str, &str)]| {
            let mut all = vec![addr, ("VAULT_TOKEN", "ignored")];
            all.extend_from_slice(vars);
            load(&EnvConfig::vault(), &all).map(|c| format!("{:?}", c.login))
        };
        let k8s = login(&[
            ("ANYKMS_TRANSIT_AUTH", "kubernetes"),
            ("ANYKMS_TRANSIT_AUTH_ROLE", "app"),
        ])
        .unwrap();
        assert!(k8s.contains(r#"method: "kubernetes""#), "{k8s}");
        assert!(k8s.contains(r#"mount: "kubernetes""#), "{k8s}");
        assert!(k8s.contains(KUBERNETES_SA), "{k8s}");
        let jwt = login(&[
            ("ANYKMS_TRANSIT_AUTH", "JWT"),
            ("ANYKMS_TRANSIT_AUTH_ROLE", "ci"),
            ("ANYKMS_TRANSIT_AUTH_JWT_FILE", "/run/ci/jwt"),
            ("ANYKMS_TRANSIT_AUTH_MOUNT", "/jwt-ci/"),
        ])
        .unwrap();
        assert!(jwt.contains(r#"mount: "jwt-ci""#), "{jwt}");
        assert!(jwt.contains("/run/ci/jwt"), "{jwt}");
        for (vars, why) in [
            (
                vec![("ANYKMS_TRANSIT_AUTH", "kubernetes")],
                "ANYKMS_TRANSIT_AUTH_ROLE",
            ),
            (
                vec![
                    ("ANYKMS_TRANSIT_AUTH", "jwt"),
                    ("ANYKMS_TRANSIT_AUTH_ROLE", "r"),
                ],
                "ANYKMS_TRANSIT_AUTH_JWT_FILE",
            ),
            (
                vec![
                    ("ANYKMS_TRANSIT_AUTH", "ldap"),
                    ("ANYKMS_TRANSIT_AUTH_ROLE", "r"),
                ],
                "`kubernetes` or `jwt`",
            ),
            (
                vec![
                    ("ANYKMS_TRANSIT_AUTH", "kubernetes"),
                    ("ANYKMS_TRANSIT_AUTH_ROLE", "r"),
                    ("ANYKMS_TRANSIT_NO_TOKEN", "1"),
                ],
                "choose one",
            ),
            (
                vec![
                    ("ANYKMS_TRANSIT_AUTH", "kubernetes"),
                    ("ANYKMS_TRANSIT_AUTH_ROLE", "r"),
                    ("ANYKMS_TRANSIT_AUTH_MOUNT", "../sys"),
                ],
                "invalid login auth mount",
            ),
        ] {
            let e = login(&vars).unwrap_err();
            assert!(e.to_string().contains(why), "{e}");
        }
        // Without ANYKMS_TRANSIT_AUTH the token variable is used.
        assert_eq!(login(&[]).unwrap(), "None");
    }

    const KUBERNETES_SA: &str = crate::auth::KUBERNETES_SERVICE_ACCOUNT_TOKEN;

    #[test]
    fn zero_limits_are_refused() {
        let base = || ServerConfig::new("https://vault.example:8200", Flavor::Vault);
        assert!(base().validate().is_ok());
        for (c, what) in [
            (base().max_response_bytes(0), "max_response_bytes"),
            (
                base().max_response_bytes(64 * 1024 - 1),
                "max_response_bytes",
            ),
        ] {
            let e = c.validate().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration);
            assert!(e.to_string().contains(what), "{e}");
        }
        assert!(base().max_response_bytes(64 * 1024).validate().is_ok());
    }

    #[test]
    fn insecure_token_file_opt_in() {
        let vars = [
            ("VAULT_ADDR", "https://vault.example:8200"),
            ("VAULT_TOKEN_FILE", "/run/vault/token"),
        ];
        let strict =
            |c: &ServerConfig| token_debug(c).contains("allow_insecure_permissions: false");
        assert!(strict(&load(&EnvConfig::vault(), &vars).unwrap()));
        let c = load(&EnvConfig::vault().allow_insecure_token_file(), &vars).unwrap();
        assert!(!strict(&c), "{c:?}");
        for v in ["1", "true", "TRUE"] {
            let mut with = vars.to_vec();
            with.push(("ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE", v));
            let c = load(&EnvConfig::vault(), &with).unwrap();
            assert!(!strict(&c), "{v}: {c:?}");
        }
        let mut off = vars.to_vec();
        off.push(("ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE", "0"));
        assert!(strict(&load(&EnvConfig::vault(), &off).unwrap()));
    }

    #[test]
    fn openbao_settings_come_from_the_address_prefix() {
        let addr = ("BAO_ADDR", "https://bao.example:8200");
        let c = load(
            &EnvConfig::openbao(),
            &[
                addr,
                ("VAULT_TOKEN", "v"),
                ("BAO_TOKEN_FILE", "/run/bao/token"),
            ],
        )
        .unwrap();
        assert!(token_debug(&c).contains("/run/bao/token"), "{c:?}");

        let c = load(
            &EnvConfig::openbao(),
            &[
                addr,
                ("BAO_TOKEN", "b"),
                ("BAO_TOKEN_FILE", "/run/bao/token"),
                ("VAULT_NAMESPACE", "vault-ns"),
            ],
        )
        .unwrap();
        assert_eq!(token_debug(&c), r#"EnvToken("BAO_TOKEN")"#);
        // VAULT_* is ignored with BAO_ADDR.
        assert_eq!(c.namespace, None);

        // With BAO_ADDR, a VAULT_TOKEN is never used (it would go to the OpenBao address).
        let e = load(
            &EnvConfig::openbao(),
            &[
                addr,
                ("VAULT_TOKEN", "v"),
                ("VAULT_TOKEN_FILE", "/run/vault/token"),
            ],
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        let m = e.to_string();
        assert!(m.contains("BAO_TOKEN, BAO_TOKEN_FILE, ~/.bao-token"), "{m}");
        assert!(m.contains("VAULT_TOKEN is ignored"), "{m}");
        assert!(!m.contains("\"v\""), "{m}");

        // With VAULT_ADDR, OpenBao reads VAULT_* and refuses stray BAO_* settings.
        let vault_addr = ("VAULT_ADDR", "https://vault.example:8200");
        let c = load(
            &EnvConfig::openbao(),
            &[vault_addr, ("VAULT_TOKEN_FILE", "/run/vault/token")],
        )
        .unwrap();
        assert!(token_debug(&c).contains("/run/vault/token"), "{c:?}");
        for stray in ["BAO_TOKEN", "BAO_NAMESPACE", "BAO_CACERT"] {
            let e = load(
                &EnvConfig::openbao(),
                &[vault_addr, ("VAULT_TOKEN", "v"), (stray, "x")],
            )
            .unwrap_err();
            assert!(e.to_string().contains(stray), "{e}");
        }

        // Vault never reads BAO_*.
        let e = load(
            &EnvConfig::vault().no_home_token(),
            &[vault_addr, ("BAO_TOKEN", "b")],
        )
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("(checked VAULT_TOKEN, VAULT_TOKEN_FILE)"),
            "{e}"
        );
    }

    #[test]
    fn missing_token_fails_unless_opted_out() {
        let addr = ("VAULT_ADDR", "https://vault.example:8200");
        let e = load(&EnvConfig::vault(), &[addr]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        let m = e.to_string();
        assert!(
            m.contains("VAULT_TOKEN, VAULT_TOKEN_FILE, ~/.vault-token"),
            "{m}"
        );
        assert!(
            m.contains("no_token()") && m.contains("ANYKMS_TRANSIT_NO_TOKEN=1"),
            "{m}"
        );

        let c = load(&EnvConfig::vault().no_token(), &[addr]).unwrap();
        assert_eq!(token_debug(&c), "NoToken");
        for v in ["1", "true"] {
            let c = load(&EnvConfig::vault(), &[addr, ("ANYKMS_TRANSIT_NO_TOKEN", v)]).unwrap();
            assert_eq!(token_debug(&c), "NoToken");
        }
        // The opt-out wins over token variables: nothing is sent.
        let c = load(
            &EnvConfig::vault(),
            &[addr, ("VAULT_TOKEN", "t"), ("ANYKMS_TRANSIT_NO_TOKEN", "1")],
        )
        .unwrap();
        assert_eq!(token_debug(&c), "NoToken");
        assert!(
            load(
                &EnvConfig::vault(),
                &[addr, ("ANYKMS_TRANSIT_NO_TOKEN", "0")]
            )
            .is_err()
        );

        // A home token file counts.
        let home = scratch("home");
        write(&home.join(".vault-token"), b"hvs.x");
        let c = load(
            &EnvConfig::vault(),
            &[addr, ("HOME", home.to_str().unwrap())],
        )
        .unwrap();
        assert!(token_debug(&c).contains(".vault-token"), "{c:?}");
        assert!(
            load(
                &EnvConfig::vault().no_home_token(),
                &[addr, ("HOME", home.to_str().unwrap())],
            )
            .is_err()
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("anykms-env-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(p: &std::path::Path, data: &[u8]) {
        std::fs::write(p, data).unwrap();
    }

    // A self-signed certificate (CN=anykms test CA), used only as test data.
    const TEST_CA: &str = include_str!("../tests/data/ca.pem");

    /// The CA PEM `EnvTls` would hand the transport, from `vars`.
    fn env_ca_pem(vars: &[(&str, &str)]) -> Option<Vec<u8>> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let get = |n: &str| vars.get(&format!("VAULT_{n}")).cloned();
        EnvTls::load("VAULT", &get).unwrap().and_then(|t| t.ca_pem)
    }

    /// The TLS variables build a transport of their own, which a shared one must not replace;
    /// without them the server has none and takes the default (or a shared one).
    #[cfg(feature = "reqwest")]
    #[test]
    fn tls_variables_set_the_transport() {
        let base = [
            ("VAULT_ADDR", "https://vault.example:8200"),
            ("VAULT_TOKEN", "t"),
        ];
        assert!(
            !load(&EnvConfig::vault(), &base)
                .unwrap()
                .has_http_transport()
        );
        let dir = scratch("tls-vars");
        let ca = dir.join("ca.pem");
        write(&ca, TEST_CA.as_bytes());
        let mut vars = base.to_vec();
        vars.push(("VAULT_CACERT", ca.to_str().unwrap()));
        assert!(
            load(&EnvConfig::vault(), &vars)
                .unwrap()
                .has_http_transport()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn capath_loads_every_certificate_file() {
        let base = [
            ("VAULT_ADDR", "https://vault.example:8200"),
            ("VAULT_TOKEN", "t"),
        ];
        let dir = scratch("capath");
        write(&dir.join("a.pem"), TEST_CA.as_bytes());
        write(&dir.join("b.crt"), TEST_CA.as_bytes());
        std::fs::create_dir(dir.join("sub")).unwrap();
        let mut vars = base.to_vec();
        vars.push(("VAULT_CAPATH", dir.to_str().unwrap()));
        load(&EnvConfig::vault(), &vars).unwrap();
        let pem = env_ca_pem(&vars).unwrap();
        use rustls_pki_types::pem::PemObject as _;
        assert_eq!(
            rustls_pki_types::CertificateDer::pem_slice_iter(&pem).count(),
            2,
            "both files, subdirectory skipped"
        );

        // A file without certificates fails closed.
        write(&dir.join("README"), b"not a certificate");
        let e = load(&EnvConfig::vault(), &vars).unwrap_err();
        assert!(e.to_string().contains("VAULT_CAPATH"), "{e}");
        std::fs::remove_file(dir.join("README")).unwrap();

        // CACERT takes precedence (as in the Vault CLI).
        let ca = dir.join("a.pem");
        vars.push(("VAULT_CACERT", ca.to_str().unwrap()));
        load(&EnvConfig::vault(), &vars).unwrap();
        assert_eq!(env_ca_pem(&vars).as_deref(), Some(TEST_CA.as_bytes()));

        // Empty and missing directories fail.
        let empty = scratch("capath-empty");
        let mut vars = base.to_vec();
        vars.push(("VAULT_CAPATH", empty.to_str().unwrap()));
        assert!(load(&EnvConfig::vault(), &vars).is_err());
        let mut vars = base.to_vec();
        vars.push(("VAULT_CAPATH", "/nonexistent/anykms"));
        assert!(load(&EnvConfig::vault(), &vars).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&empty).unwrap();
    }

    #[test]
    fn file_errors_name_the_path_and_reason() {
        let base = [
            ("VAULT_ADDR", "https://vault.example:8200"),
            ("VAULT_TOKEN", "s.secret-token"),
        ];
        let missing = "/nonexistent/anykms/x.pem";
        for (vars, what) in [
            (vec![("VAULT_CACERT", missing)], "CA certificate file"),
            (vec![("VAULT_CAPATH", missing)], "CA certificate directory"),
            (
                vec![
                    ("VAULT_CLIENT_CERT", missing),
                    ("VAULT_CLIENT_KEY", missing),
                ],
                "client certificate file",
            ),
        ] {
            let mut all = base.to_vec();
            all.extend(vars);
            let e = load(&EnvConfig::vault(), &all).unwrap_err();
            let m = e.to_string();
            assert!(
                m.contains(&format!("cannot read the {what} {missing} (VAULT_"))
                    && m.ends_with(": No such file or directory"),
                "{m}"
            );
            assert!(!m.contains("secret-token"), "{m}");
            let src = std::error::Error::source(&e).expect("io source");
            assert_eq!(
                src.downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
                Some(std::io::ErrorKind::NotFound)
            );
        }

        // A client key that exists but cannot be read names the key path; contents never appear.
        let dir = scratch("keyfile");
        let cert = dir.join("cert.pem");
        write(&cert, TEST_CA.as_bytes());
        let mut all = base.to_vec();
        let cert_s = cert.to_str().unwrap().to_owned();
        let key_s = dir.to_str().unwrap().to_owned(); // a directory: reading it fails
        all.push(("VAULT_CLIENT_CERT", &cert_s));
        all.push(("VAULT_CLIENT_KEY", &key_s));
        let m = load(&EnvConfig::vault(), &all).unwrap_err().to_string();
        assert!(
            m.contains(&format!(
                "cannot read the client key file {key_s} (VAULT_CLIENT_KEY): "
            )),
            "{m}"
        );
        assert!(!m.contains("BEGIN"), "{m}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loopback_http_scheme_is_case_insensitive() {
        let c = load(
            &EnvConfig::vault().no_token(),
            &[("VAULT_ADDR", "HTTP://127.0.0.1:8100")],
        )
        .unwrap();
        assert!(c.allow_loopback_http);
        assert!(
            load(
                &EnvConfig::vault().no_token(),
                &[("VAULT_ADDR", "HTTP://vault.example:8200")],
            )
            .is_err()
        );
    }
}
