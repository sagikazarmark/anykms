//! Token sources.
//!
//! # Renewal
//!
//! Only [`Login`](crate::Login) (Kubernetes or JWT auth, set with
//! [`ServerConfig::login`](crate::ServerConfig::login)) logs in and renews. The token sources here
//! hand out a token they are given and never call `auth/token/renew-self`: a service token with
//! a TTL stops working when it expires, and every request then fails with `PermissionDenied`.
//! Without `Login`, use one of:
//!
//! - a Vault/Bao Agent that authenticates and renews, with its token sink read through
//!   [`FileToken`] (re-read whenever it changes) or its API proxy with
//!   `use_auto_auth_token` and [`NoToken`];
//! - a batch token or a periodic token whose lifetime covers the process;
//! - a custom [`TokenSource`] that logs in or renews and hands out the current token.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::config::EnvLookup;

/// A Vault/OpenBao token: zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct Token(Zeroizing<String>);

impl Token {
    /// Wraps a token.
    pub fn new(token: impl Into<String>) -> Self {
        Self(Zeroizing::new(token.into()))
    }

    /// The token text. Avoid copying it into buffers that are not zeroized.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for Token {
    fn from(token: String) -> Self {
        Self::new(token)
    }
}

impl From<&str> for Token {
    fn from(token: &str) -> Self {
        Self::new(token)
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Supplies the Vault/OpenBao token for each request. Object-safe; implement it for login flows
/// that [`Login`](crate::Login) does not cover (AppRole, cloud IAM, ...).
///
/// The token is requested before every HTTP request, so a source can hand out a refreshed token
/// at any time. Apart from `Login`, anykms never renews tokens (see the [crate docs](crate)): a
/// source for tokens with a TTL must renew or re-login on its own, or read a token that an agent
/// keeps fresh.
pub trait TokenSource: Send + Sync + fmt::Debug {
    /// The token to send, or `None` to send no token (e.g. behind a Vault/Bao Agent API proxy
    /// with `use_auto_auth_token`).
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>>;

    /// Called when the server rejected `rejected` with 403. Sources that can refresh (such as
    /// [`FileToken`]) drop their cache; if the next [`token`](Self::token) differs, the request is
    /// retried exactly once.
    fn invalidate(&self, rejected: &Token) {
        let _ = rejected;
    }
}

/// A fixed token. It is never renewed (see the [crate docs](crate)).
pub struct StaticToken(Token);

impl StaticToken {
    /// Wraps a token.
    pub fn new(token: impl Into<String>) -> Self {
        Self(Token::new(token))
    }
}

impl fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticToken(<redacted>)")
    }
}

impl TokenSource for StaticToken {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async move { Ok(Some(self.0.clone())) })
    }
}

/// No token: requests are sent without `X-Vault-Token`.
#[derive(Debug, Default)]
pub struct NoToken;

impl TokenSource for NoToken {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async { Ok(None) })
    }
}

/// Reads the token from an environment variable on every request. The token is never renewed
/// (see the [crate docs](crate)); a process that updates the variable is picked up on the next
/// request.
///
/// A configuration loaded through a custom lookup
/// ([`EnvConfig::load_with`](crate::EnvConfig::load_with),
/// [`TransitProvider::from_env_with`](crate::TransitProvider::from_env_with)) re-reads the
/// variable through that lookup, not the process environment.
pub struct EnvToken {
    var: String,
    lookup: Option<EnvLookup>,
}

impl fmt::Debug for EnvToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EnvToken").field(&self.var).finish()
    }
}

impl EnvToken {
    /// Reads `var` (e.g. `VAULT_TOKEN`).
    pub fn new(var: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            lookup: None,
        }
    }

    /// Reads `var` through `lookup` instead of the process environment.
    pub(crate) fn with_lookup(var: impl Into<String>, lookup: EnvLookup) -> Self {
        Self {
            var: var.into(),
            lookup: Some(lookup),
        }
    }
}

impl TokenSource for EnvToken {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async move {
            // The value read here is wiped once trimmed and copied into the token. The process
            // environment (or the lookup's own store) keeps a copy that cannot be wiped.
            let raw = Zeroizing::new(match &self.lookup {
                None => std::env::var_os(&self.var)
                    .map(std::ffi::OsString::into_encoded_bytes)
                    .unwrap_or_default(),
                Some(lookup) => lookup(&self.var)
                    .map(String::into_bytes)
                    .unwrap_or_default(),
            });
            match std::str::from_utf8(&raw).map(str::trim) {
                Ok(t) if !t.is_empty() => Ok(Some(Token::new(t))),
                _ => Err(Error::new(
                    ErrorKind::Configuration,
                    BACKEND,
                    Operation::Configure,
                    "token environment variable is empty, unset or not UTF-8",
                )),
            }
        })
    }
}

const MAX_TOKEN_FILE: u64 = 8 * 1024;

/// Reads the token from a file, e.g. a Vault/Bao Agent sink.
///
/// The file is opened and checked (a blocking `open` and `fstat`; the permission check applies
/// to the opened file, so it cannot race a swap of the path) before every request, and re-read
/// when its modification time, size or (on Unix) inode changes, and after the server rejects the
/// token; reads are small blocking file reads. An in-place rewrite that keeps the size and the
/// modification time (coarse file-system timestamps, or a writer that restores the mtime) is not
/// noticed until the server rejects the cached token with 403: the token is then re-read and the
/// request retried once with the new token (see [`TokenSource::invalidate`]). Agents that write
/// a new file and rename it over the old one (Vault/Bao Agent sinks, Kubernetes volumes) change
/// the inode and are always noticed. Symlinks are followed (permissions are those of the target).
/// A single trailing newline is trimmed. A missing file makes requests fail with `Unavailable`
/// (a rotation race: the agent may be replacing it); every other failure is `Configuration`,
/// which retrying cannot fix: an unreadable file (`EACCES`), an empty file, a file over 8 KiB,
/// one that is not UTF-8 or holds whitespace or control characters, and anything but a regular
/// file (a FIFO, device or directory, refused before it is read). Contents are never echoed.
///
/// With the `tracing` feature, every read of the file (not a cached token) runs in a token span
/// (`anykms.transit.token`, `credential = "token_file"`), with a `debug` event on success and a
/// `warn` event naming the path and the error on failure.
///
/// On Unix, a file that is group- or world-accessible (`mode & 0o077 != 0`) is refused with
/// `Configuration`, unless [`allow_insecure_permissions`](Self::allow_insecure_permissions) is
/// set (from the environment: [`EnvConfig::allow_insecure_token_file`](crate::EnvConfig::allow_insecure_token_file)
/// or `ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE=1`). Common sources default to readable modes:
///
/// - Vault/Bao Agent's file sink writes `0640`: set `mode = 0600` (or `0400`) in the sink's
///   `config` block.
/// - Kubernetes secret and projected volumes default to `0644`: set `defaultMode: 0400` (or
///   `0600`, or a per-item `mode`) on the volume. The files are owned by root, so this suits a
///   container running as root. Do not rely on `fsGroup` for a non-root container: the kubelet
///   then adds group read to every file of these volumes (`0400` becomes `0440`), which this
///   check refuses. For a non-root container, have a Vault/Bao Agent sidecar running as the
///   container's user write the token (sink `mode = 0600`) into a shared `emptyDir`, or copy the
///   secret into one in an init container (`chmod 600`, owned by that user); otherwise opt in to
///   the group-readable file with `fsGroup` and `allow_insecure_permissions`.
///
/// Group access is refused too (not only world access): a group-readable token is shared with
/// every process in that group, which is rarely intended; opting in is one call.
pub struct FileToken {
    path: PathBuf,
    allow_insecure_permissions: bool,
    cache: Mutex<Option<(FileStamp, Token)>>,
}

/// What identifies one version of the token file: its `fstat` modification time, size and (on
/// Unix) device and inode.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    len: u64,
    #[cfg(unix)]
    dev_ino: (u64, u64),
}

impl FileStamp {
    /// `None` when the platform reports no modification time: such files are never cached.
    fn of(meta: &std::fs::Metadata) -> Option<Self> {
        Some(Self {
            mtime: meta.modified().ok()?,
            len: meta.len(),
            #[cfg(unix)]
            dev_ino: {
                use std::os::unix::fs::MetadataExt;
                (meta.dev(), meta.ino())
            },
        })
    }
}

impl fmt::Debug for FileToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileToken")
            .field("path", &self.path)
            .field(
                "allow_insecure_permissions",
                &self.allow_insecure_permissions,
            )
            .finish_non_exhaustive()
    }
}

impl FileToken {
    /// Reads tokens from `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            allow_insecure_permissions: false,
            cache: Mutex::new(None),
        }
    }

    /// Accepts token files that are group- or world-accessible (refused by default on Unix).
    pub fn allow_insecure_permissions(mut self) -> Self {
        self.allow_insecure_permissions = true;
        self
    }

    /// The token file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `token file <path> <what>`, `Configuration`: the path is not secret, the contents never
    /// appear.
    fn invalid(&self, what: &str) -> Error {
        Error::new(
            ErrorKind::Configuration,
            BACKEND,
            Operation::Configure,
            format!("token file {} {what}", self.path.display()),
        )
    }

    /// `cannot read the token file <path>: <reason>`, with the I/O error as its source, classified
    /// by [`token_file_error_kind`](anykms_http::zbuf::token_file_error_kind).
    fn unreadable(&self, e: std::io::Error) -> Error {
        Error::new(
            anykms_http::zbuf::token_file_error_kind(&e),
            BACKEND,
            Operation::Configure,
            format!(
                "cannot read the token file {}: {}",
                self.path.display(),
                crate::config::io_reason(&e)
            ),
        )
        .with_source(e)
    }

    /// The token: the cached one while the file is unchanged, otherwise a fresh read inside a
    /// token span.
    fn read(&self) -> Result<Token> {
        let started = anykms_core::time::Instant::now();
        let r = match self.read_inner() {
            Ok((tok, Fresh::Cached)) => return Ok(tok),
            Ok((tok, Fresh::Read)) => Ok(tok),
            Err(e) => Err(e),
        };
        // Created after the fact: a cached token (every request) gets no span.
        let span = anykms_http::token_span!(
            "anykms.transit.token",
            backend = BACKEND,
            credential = "token_file",
        );
        anykms_http::span::finish_token(&span, started, None, &r);
        #[cfg(feature = "tracing")]
        span.in_scope(|| match &r {
            Ok(_) => tracing::debug!(path = %self.path.display(), "token file reloaded"),
            Err(e) => tracing::warn!(
                path = %self.path.display(),
                error_kind = e.kind().as_str(),
                error = %e,
                "cannot use the token file"
            ),
        });
        r
    }

    fn read_inner(&self) -> Result<(Token, Fresh)> {
        use std::io::Read as _;
        // Open first, then check the opened file: checking the path before opening it would
        // race a swap of the file in between. Follows symlinks: the target's permissions are
        // what matter. Non-blocking on Unix, so opening a FIFO without a writer returns at once
        // (regular-file reads ignore the flag); the file-type check then refuses it.
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NONBLOCK);
        }
        let file = opts.open(&self.path).map_err(|e| self.unreadable(e))?;
        let meta = file.metadata().map_err(|e| self.unreadable(e))?;
        // FIFOs, devices and directories could block a runtime worker or never end.
        if !meta.is_file() {
            return Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Configure,
                format!("token file {} is not a regular file", self.path.display()),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !self.allow_insecure_permissions && meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::new(
                    ErrorKind::Configuration,
                    BACKEND,
                    Operation::Configure,
                    format!(
                        "token file {} is group- or world-accessible; chmod 600 it, or opt in \
                         with FileToken::allow_insecure_permissions",
                        self.path.display()
                    ),
                ));
            }
        }
        if meta.len() > MAX_TOKEN_FILE {
            return Err(self.invalid("is larger than 8 KiB"));
        }
        let stamp = FileStamp::of(&meta);
        {
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let (Some((cached, tok)), Some(stamp)) = (&*cache, stamp)
                && *cached == stamp
            {
                return Ok((tok.clone(), Fresh::Cached));
            }
        }
        let raw = {
            // Sized for the bound, so the buffer never reallocates (which would leave an unwiped
            // copy). Bounded read: the file may grow between the size check and the read.
            let cap = usize::try_from(MAX_TOKEN_FILE).expect("8 KiB fits in usize") + 1;
            let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(cap));
            file.take(MAX_TOKEN_FILE + 1)
                .read_to_end(&mut buf)
                .map_err(|e| self.unreadable(e))?;
            if buf.len() as u64 > MAX_TOKEN_FILE {
                return Err(self.invalid("is larger than 8 KiB"));
            }
            buf
        };
        let mut s = &raw[..];
        if let Some(x) = s.strip_suffix(b"\n") {
            s = x.strip_suffix(b"\r").unwrap_or(x);
        }
        if s.is_empty() {
            return Err(self.invalid("is empty"));
        }
        if s.iter()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(self.invalid("contains whitespace or control characters"));
        }
        let tok = Token::new(std::str::from_utf8(s).map_err(|_| self.invalid("is not UTF-8"))?);
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = stamp.map(|s| (s, tok.clone()));
        Ok((tok, Fresh::Read))
    }
}

/// Whether [`FileToken::read_inner`] served the cached token or read the file.
enum Fresh {
    Cached,
    Read,
}

impl TokenSource for FileToken {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async move { self.read().map(Some) })
    }

    fn invalidate(&self, rejected: &Token) {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache
            .as_ref()
            .is_some_and(|(_, t)| t.expose() == rejected.expose())
        {
            *cache = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_token() {
        let dir = std::env::temp_dir().join(format!("anykms-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("token");
        write_private(&p, "hvs.abc\n");
        let src = FileToken::new(&p);
        assert_eq!(src.token().await.unwrap().unwrap().expose(), "hvs.abc");
        std::fs::write(&p, "").unwrap();
        src.invalidate(&Token::from("hvs.abc"));
        assert_eq!(
            src.token().await.unwrap_err().kind(),
            ErrorKind::Configuration
        );
        std::fs::write(&p, "a b").unwrap();
        let e = src.token().await.unwrap_err();
        assert!(!format!("{e:?}").contains("a b"));
        assert!(e.message().contains(&*p.to_string_lossy()), "{e}");
        std::fs::write(&p, vec![b'x'; 9000]).unwrap();
        assert_eq!(
            src.token().await.unwrap_err().kind(),
            ErrorKind::Configuration
        );
        std::fs::remove_dir_all(&dir).unwrap();
        // A missing file (a rotation race) is Unavailable, and names the path and the I/O
        // reason.
        let e = src.token().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unavailable);
        assert_eq!(
            e.message(),
            format!(
                "cannot read the token file {}: No such file or directory",
                p.display()
            ),
        );
        assert!(std::error::Error::source(&e).is_some());
        assert!(!format!("{:?}", StaticToken::new("hvs.secret")).contains("hvs.secret"));
        assert!(!format!("{:?}", Token::from("hvs.secret")).contains("hvs.secret"));
    }

    #[tokio::test]
    async fn file_token_rewrite_keeping_mtime() {
        let dir = std::env::temp_dir().join(format!("anykms-token-mtime-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("token");
        write_private(&p, "hvs.aaa\n");
        let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
        let keep_mtime = |p: &Path| {
            std::fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        };
        let src = FileToken::new(&p);
        assert_eq!(src.token().await.unwrap().unwrap().expose(), "hvs.aaa");

        // In place, same size, same mtime: indistinguishable by fstat, so the cached token is
        // served until the server rejects it and the client invalidates it (the 403 path).
        std::fs::write(&p, "hvs.bbb\n").unwrap();
        keep_mtime(&p);
        assert_eq!(src.token().await.unwrap().unwrap().expose(), "hvs.aaa");
        src.invalidate(&Token::from("hvs.aaa"));
        assert_eq!(src.token().await.unwrap().unwrap().expose(), "hvs.bbb");

        // A size change is noticed even with the same mtime.
        std::fs::write(&p, "hvs.cccc\n").unwrap();
        keep_mtime(&p);
        assert_eq!(src.token().await.unwrap().unwrap().expose(), "hvs.cccc");

        // So is a new file renamed over the old one (new inode), as agents write tokens.
        #[cfg(unix)]
        {
            let tmp = dir.join("token.tmp");
            write_private(&tmp, "hvs.dddd\n");
            keep_mtime(&tmp);
            std::fs::rename(&tmp, &p).unwrap();
            assert_eq!(src.token().await.unwrap().unwrap().expose(), "hvs.dddd");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn write_private(p: &Path, contents: &str) {
        std::fs::write(p, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_token_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("anykms-token-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("token");
        write_private(&p, "hvs.abc\n");
        // A symlink is followed: the target's (private) mode counts, not the link's.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(
            FileToken::new(&link)
                .token()
                .await
                .unwrap()
                .unwrap()
                .expose(),
            "hvs.abc"
        );
        for mode in [0o640, 0o604, 0o660, 0o644] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            for path in [&p, &link] {
                let e = FileToken::new(path).token().await.unwrap_err();
                assert_eq!(e.kind(), ErrorKind::Configuration, "{mode:o}: {e}");
            }
            assert_eq!(
                FileToken::new(&p)
                    .allow_insecure_permissions()
                    .token()
                    .await
                    .unwrap()
                    .unwrap()
                    .expose(),
                "hvs.abc"
            );
        }
        // A cached token is not served once the file becomes group-readable.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let src = FileToken::new(&p);
        src.token().await.unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            src.token().await.unwrap_err().kind(),
            ErrorKind::Configuration
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A FIFO (no writer) or a directory at the token path is refused at once, never read. Read
    /// on a separate thread: a blocking open would stall a runtime's timer along with it.
    #[cfg(unix)]
    #[test]
    fn file_token_refuses_non_regular_files() {
        let dir = std::env::temp_dir().join(format!("anykms-token-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        for path in [&fifo, &dir] {
            let (tx, rx) = std::sync::mpsc::channel();
            let src = FileToken::new(path);
            std::thread::spawn(move || tx.send(src.read().map(|_| ())));
            let e = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("must not block")
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
            assert!(e.to_string().contains("not a regular file"), "{e}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
