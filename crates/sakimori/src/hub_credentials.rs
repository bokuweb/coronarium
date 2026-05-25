//! `~/.config/sakimori/credentials` — TOML credentials file.
//!
//! Tertiary source for the hub-ingest URL + token, layered
//! UNDER `--hub-ingest-url` / `--hub-ingest-token` CLI flags
//! and the `SAKIMORI_INGEST_URL` / `SAKIMORI_TOKEN` env vars:
//!
//!   precedence: flag > env > credentials file
//!
//! Lets an operator put `[hub]` into one file once and run
//! `sakimori run` without juggling `SAKIMORI_TOKEN=` env exports
//! every shell.
//!
//! ## File format (TOML)
//!
//! ```toml
//! [hub]
//! ingest_url = "https://hub.example/v1/acme/_user/<member-id>/events"
//! token      = "skm_user_…"
//! ```
//!
//! Only the `[hub]` table is read; unknown keys are tolerated
//! (`#[serde(default)]`-ed) so a future `[telemetry]` or
//! `[proxy]` section can land without breaking older binaries.
//!
//! ## File location
//!
//! `${SAKIMORI_CONFIG_DIR}/credentials` if the env var is set,
//! otherwise `${XDG_CONFIG_HOME:-$HOME/.config}/sakimori/credentials`.
//! The env-var override exists so the test suite can point at a
//! tmpdir without touching the real `$HOME`.
//!
//! ## Permission gate
//!
//! On Unix, the file is required to be **not group/world-readable**
//! (`0o077` mode bits clear). The file IS the bearer credential
//! and is read silently at every `sakimori run` — leaving it
//! world-readable is the same shape of bug as a chmod-644 ssh
//! private key. We fail closed: a too-permissive file logs a
//! `log::warn!` and is treated as absent, never silently consumed.
//! Windows has no equivalent check (NTFS ACLs need a different
//! API); the warning is skipped there.

use std::path::PathBuf;

use serde::Deserialize;

/// Env var that overrides the credentials-file directory.
/// Test-only and operator escape hatch; never set in normal
/// use.
pub const CONFIG_DIR_ENV: &str = "SAKIMORI_CONFIG_DIR";

/// The basename of the credentials file inside the config
/// directory. Matches Cargo's `credentials.toml` style.
pub const CREDENTIALS_BASENAME: &str = "credentials";

/// Parsed credentials. Only `[hub]` is consumed today; the
/// `#[serde(default)]` on the field means a fresh file that
/// only declares `[hub]` is the typical shape.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct Credentials {
    #[serde(default)]
    pub hub: HubCredentials,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct HubCredentials {
    /// `SAKIMORI_INGEST_URL` equivalent. Same shape +
    /// validation as the CLI flag (`https://hub/.../events`).
    pub ingest_url: Option<String>,
    /// `SAKIMORI_TOKEN` equivalent. The bearer token. Never
    /// echoed in logs / error messages — `HubCredentials`
    /// has a custom `Debug` below that redacts it.
    pub token: Option<String>,
}

/// Default config-file path. `None` when neither the override
/// env nor `$HOME` is available (CI sandbox without HOME).
pub fn default_credentials_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(CONFIG_DIR_ENV)
        && !dir.is_empty()
    {
        return Some(PathBuf::from(dir).join(CREDENTIALS_BASENAME));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("sakimori").join(CREDENTIALS_BASENAME))
}

/// Read and parse the credentials file at `path`. Returns:
///   - `Ok(None)` when the file doesn't exist (the common
///     case — operator hasn't onboarded).
///   - `Ok(Some(creds))` on successful parse.
///   - `Err(_)` on read / parse / permission failure. The
///     caller in `cli.rs` logs a `warn` and proceeds as if
///     `Ok(None)` — fail-closed, don't make a typo block the
///     whole CLI.
pub fn load_credentials(path: &PathBuf) -> Result<Option<Credentials>, LoadError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(LoadError::Io(e.to_string())),
    };
    enforce_unix_perms(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| LoadError::NotUtf8)?;
    let creds: Credentials = toml::from_str(text).map_err(|e| LoadError::Parse(e.to_string()))?;
    Ok(Some(creds))
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("read: {0}")]
    Io(String),
    #[error("file is not valid UTF-8")]
    NotUtf8,
    #[error("toml parse: {0}")]
    Parse(String),
    #[error("file is too permissive (must be chmod 600 / 0o077-clear)")]
    TooPermissive,
}

#[cfg(unix)]
fn enforce_unix_perms(path: &PathBuf) -> Result<(), LoadError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| LoadError::Io(e.to_string()))?;
    let mode = meta.permissions().mode();
    // Bits 0o077 = group + world (rwxrwx). The file may have
    // user bits set; group / world MUST be zero. Same rule as
    // `~/.aws/credentials` and `~/.ssh/id_*`.
    if mode & 0o077 != 0 {
        return Err(LoadError::TooPermissive);
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_unix_perms(_path: &PathBuf) -> Result<(), LoadError> {
    // Windows ACL check needs a different API — out of scope
    // for v1. The operator's responsibility on Windows.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_hub_section() {
        let s = r#"
            [hub]
            ingest_url = "https://hub.example/v1/acme/_user/u/events"
            token      = "skm_user_abc"
        "#;
        let c: Credentials = toml::from_str(s).unwrap();
        assert_eq!(
            c.hub.ingest_url.as_deref(),
            Some("https://hub.example/v1/acme/_user/u/events"),
        );
        assert_eq!(c.hub.token.as_deref(), Some("skm_user_abc"));
    }

    #[test]
    fn missing_hub_section_yields_empty_optionals() {
        let c: Credentials = toml::from_str("").unwrap();
        assert!(c.hub.ingest_url.is_none());
        assert!(c.hub.token.is_none());
    }

    #[test]
    fn unknown_top_level_sections_are_tolerated() {
        let s = r#"
            [hub]
            token = "skm_user_x"

            [future_section]
            anything = "goes"
        "#;
        let c: Credentials = toml::from_str(s).unwrap();
        assert_eq!(c.hub.token.as_deref(), Some("skm_user_x"));
    }

    #[test]
    fn missing_file_returns_none() {
        let tmp = tempdir();
        let path = tmp.join("not-there");
        assert_eq!(load_credentials(&path).unwrap(), None);
    }

    #[test]
    fn invalid_utf8_errors() {
        let tmp = tempdir();
        let path = tmp.join("c");
        std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
        #[cfg(unix)]
        chmod_600(&path);
        assert!(matches!(load_credentials(&path), Err(LoadError::NotUtf8)));
    }

    #[test]
    fn malformed_toml_errors() {
        let tmp = tempdir();
        let path = tmp.join("c");
        std::fs::write(&path, "this = is not valid =\ntoml").unwrap();
        #[cfg(unix)]
        chmod_600(&path);
        assert!(matches!(load_credentials(&path), Err(LoadError::Parse(_))));
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_file_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir();
        let path = tmp.join("c");
        std::fs::write(&path, "[hub]\ntoken = \"skm_x\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_credentials(&path),
            Err(LoadError::TooPermissive),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn chmod_600_accepted() {
        let tmp = tempdir();
        let path = tmp.join("c");
        std::fs::write(&path, "[hub]\ntoken = \"skm_x\"\n").unwrap();
        chmod_600(&path);
        let c = load_credentials(&path).unwrap().unwrap();
        assert_eq!(c.hub.token.as_deref(), Some("skm_x"));
    }

    #[test]
    fn default_path_respects_override_env() {
        let saved = std::env::var_os(CONFIG_DIR_ENV);
        // SAFETY: tests run single-threaded by `cargo test --
        // --test-threads=1` in this crate's CI; the env mutation
        // is local to this test.
        unsafe { std::env::set_var(CONFIG_DIR_ENV, "/tmp/zzz") };
        let p = default_credentials_path().unwrap();
        assert_eq!(p, std::path::Path::new("/tmp/zzz/credentials"));
        unsafe {
            match saved {
                Some(v) => std::env::set_var(CONFIG_DIR_ENV, v),
                None => std::env::remove_var(CONFIG_DIR_ENV),
            }
        }
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sakimori-creds-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[cfg(unix)]
    fn chmod_600(path: &PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
