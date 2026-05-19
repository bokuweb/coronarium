pub mod crates;
pub mod npm;
pub mod nuget;
pub mod pypi;

use std::time::Duration;

pub(crate) fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(15))
        .build()
}

// ---------------------------------------------------------------------------
// Per-ecosystem base-URL config
// ---------------------------------------------------------------------------

/// Per-ecosystem **base URL** for the publish-date lookup.
/// Defaults point at the canonical public registries. Override
/// when running `deps check` / `deps watch` against an internal
/// mirror (Verdaccio, JFrog Artifactory, GitHub Packages
/// internal, Takumi Guard, …). The path-shape *after* the base
/// stays hardcoded — the mirror must serve the canonical URL
/// shape for its ecosystem (same non-goal documented in the
/// proxy's `RegistryHosts` section).
///
/// Each field holds a normalised base URL: scheme + host +
/// optional port. Any path component is stripped at construction
/// time with a warn log (see [`Self::parse_base`]); the loaders
/// inside `published()` append the documented path shape
/// themselves.
///
/// Future work: per-ecosystem `Vec<String>` for staged-mirror
/// failover / DR. Single URL today; the use case is real but the
/// fallback policy needs its own design pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEndpoints {
    /// npm packument host. Default `https://registry.npmjs.org`.
    pub npm: String,
    /// crates.io API host. Default `https://crates.io`.
    pub crates: String,
    /// PyPI Warehouse JSON host. Default `https://pypi.org`.
    pub pypi: String,
    /// NuGet v3 host. Default `https://api.nuget.org`.
    pub nuget: String,
}

impl Default for RegistryEndpoints {
    fn default() -> Self {
        Self {
            npm: "https://registry.npmjs.org".to_string(),
            crates: "https://crates.io".to_string(),
            pypi: "https://pypi.org".to_string(),
            nuget: "https://api.nuget.org".to_string(),
        }
    }
}

impl RegistryEndpoints {
    /// Parse a user-supplied URL/host into a normalised base URL.
    /// Strips any path with a warn log (path-prefix support is
    /// intentionally not implemented — the mirror must serve the
    /// canonical path shape).
    ///
    /// Returns the normalised `scheme://host[:port]` string. If
    /// the input has no scheme, `https://` is prepended.
    pub fn parse_base(flag: &str, raw: &str) -> anyhow::Result<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("{flag}: empty registry URL");
        }
        let with_scheme = if trimmed.contains("://") {
            trimmed.to_string()
        } else {
            format!("https://{trimmed}")
        };
        // Split scheme + rest.
        let (scheme, rest) = with_scheme
            .split_once("://")
            .expect("we just ensured `://` is present");
        // Split host[:port] + path.
        let (host_port, path_tail) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if host_port.is_empty() {
            anyhow::bail!("{flag}: empty host in `{raw}`");
        }
        // Warn only when the trailing path is more than `/` — a
        // bare trailing slash is harmless; a real prefix
        // (`/artifactory/api/npm/repo`) probably reflects a user
        // expectation we don't honour (Codex R2 finding).
        if !path_tail.is_empty() && path_tail != "/" {
            log::warn!(
                "{flag}: path `{path_tail}` in `{raw}` ignored — registry-endpoint flags accept host only; the canonical path shape is appended internally",
            );
        }
        Ok(format!("{scheme}://{host_port}"))
    }

    /// Per-ecosystem 16-char hex sha256 fingerprint. Used as a
    /// cache-key prefix so that switching `--npm-registry`
    /// invalidates only npm cache entries, not crates/PyPI/NuGet
    /// (Codex R2 finding).
    pub fn fingerprint(base_url: &str) -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(base_url.as_bytes());
        let digest = h.finalize();
        let mut out = String::with_capacity(16);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in &digest[..8] {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_points_at_canonical_public_hosts() {
        let d = RegistryEndpoints::default();
        assert_eq!(d.npm, "https://registry.npmjs.org");
        assert_eq!(d.crates, "https://crates.io");
        assert_eq!(d.pypi, "https://pypi.org");
        assert_eq!(d.nuget, "https://api.nuget.org");
    }

    #[test]
    fn parse_base_accepts_bare_host() {
        let out = RegistryEndpoints::parse_base("--npm-registry", "npm.flatt.tech").unwrap();
        assert_eq!(out, "https://npm.flatt.tech");
    }

    #[test]
    fn parse_base_accepts_full_url() {
        let out =
            RegistryEndpoints::parse_base("--npm-registry", "https://npm.flatt.tech").unwrap();
        assert_eq!(out, "https://npm.flatt.tech");
    }

    #[test]
    fn parse_base_strips_trailing_slash_silently() {
        let out =
            RegistryEndpoints::parse_base("--npm-registry", "https://npm.flatt.tech/").unwrap();
        assert_eq!(out, "https://npm.flatt.tech");
    }

    #[test]
    fn parse_base_strips_path_prefix_with_warn() {
        let out = RegistryEndpoints::parse_base(
            "--nuget-registry",
            "https://art.corp/artifactory/api/nuget/repo",
        )
        .unwrap();
        assert_eq!(out, "https://art.corp");
    }

    #[test]
    fn parse_base_preserves_port() {
        let out = RegistryEndpoints::parse_base("--npm-registry", "http://127.0.0.1:9001").unwrap();
        assert_eq!(out, "http://127.0.0.1:9001");
    }

    #[test]
    fn parse_base_rejects_empty() {
        assert!(RegistryEndpoints::parse_base("--npm-registry", "").is_err());
        assert!(RegistryEndpoints::parse_base("--npm-registry", "  ").is_err());
        assert!(RegistryEndpoints::parse_base("--npm-registry", "https:///path").is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_different_per_url() {
        let a = RegistryEndpoints::fingerprint("https://registry.npmjs.org");
        let b = RegistryEndpoints::fingerprint("https://registry.npmjs.org");
        assert_eq!(a, b, "stable for identical input");
        let c = RegistryEndpoints::fingerprint("https://npm.flatt.tech");
        assert_ne!(a, c, "different URL → different fingerprint");
        assert_eq!(a.len(), 16, "fingerprint is 16 hex chars (8 bytes)");
    }
}
