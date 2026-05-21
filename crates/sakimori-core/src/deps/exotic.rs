//! Static `blockExoticSubdeps`-style lint for lockfiles.
//!
//! Inspired by pnpm 11's [`blockExoticSubdeps`] setting: a transitive
//! dependency that resolves to a git URL / tarball URL / local file path
//! bypasses every defence sakimori's proxy layer applies (release-age
//! filtering, integrity verification, lifecycle-script gate) because
//! none of those primitives have a "publish time" or registry-shaped
//! metadata to work with. Direct deps from exotic sources are a
//! legitimate (if rare) pattern — pinning a fork while waiting for an
//! upstream merge — but transitives almost never are: a registry
//! package shouldn't be pulling in a non-registry sibling. When it
//! does, the practical effect is that one corner of the dep graph
//! gets a free pass on every other check.
//!
//! Today: npm `package-lock.json` (v2/v3) and Cargo.lock.
//! Tomorrow: pnpm-lock.yaml, uv.lock, packages.lock.json.
//!
//! [`blockExoticSubdeps`]: https://pnpm.io/settings#blockexoticsubdeps

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::Ecosystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExoticSource {
    /// `git+...`, `git://`, `github:owner/repo`, `git@...:...`.
    Git,
    /// HTTP(S) tarball URL not pointing at the canonical registry.
    Tarball,
    /// `file:` / local path.
    File,
    /// Any other non-registry URL shape (e.g. `ssh:`, `bitbucket:`).
    Other,
}

impl ExoticSource {
    pub fn label(self) -> &'static str {
        match self {
            ExoticSource::Git => "git",
            ExoticSource::Tarball => "tarball",
            ExoticSource::File => "file",
            ExoticSource::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExoticFinding {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    pub source: ExoticSource,
    /// Raw source string from the lockfile (URL, path, etc.).
    pub raw: String,
    /// True iff this dep is a direct dependency of the root project.
    /// `false` ⇒ transitive (the high-signal case).
    pub direct: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct ExoticReport {
    pub scanned: usize,
    pub findings: Vec<ExoticFinding>,
}

impl ExoticReport {
    pub fn transitive_count(&self) -> usize {
        self.findings.iter().filter(|f| !f.direct).count()
    }
}

pub fn scan(path: &Path) -> Result<ExoticReport> {
    let eco = super::lockfile::detect(path)
        .with_context(|| format!("detecting lockfile type for {}", path.display()))?;
    match eco {
        Ecosystem::Npm => scan_npm(path),
        Ecosystem::Crates => scan_cargo(path),
        Ecosystem::Pypi | Ecosystem::Nuget => {
            anyhow::bail!(
                "exotic-subdep scan for {} lockfiles is not implemented yet — currently npm and crates only",
                eco.label()
            )
        }
        Ecosystem::Git | Ecosystem::VscodeExtension => {
            anyhow::bail!(
                "ecosystem {} has no lockfile shape — exotic scan is lockfile-only",
                eco.label()
            )
        }
    }
}

// ---------------------------------------------------------------- npm

#[derive(Debug, Deserialize)]
struct NpmLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: u32,
    #[serde(default)]
    packages: std::collections::BTreeMap<String, NpmPkg>,
}

#[derive(Debug, Deserialize)]
struct NpmPkg {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    link: bool,
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: std::collections::BTreeMap<String, String>,
}

fn scan_npm(path: &Path) -> Result<ExoticReport> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: NpmLock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as package-lock.json", path.display()))?;
    if lock.lockfile_version < 2 {
        anyhow::bail!(
            "package-lock.json lockfileVersion={} not supported (need >=2)",
            lock.lockfile_version
        );
    }

    // Direct-dep set comes from the root entry (key = "").
    let mut direct_names: BTreeSet<String> = BTreeSet::new();
    if let Some(root) = lock.packages.get("") {
        for src in [
            &root.dependencies,
            &root.dev_dependencies,
            &root.optional_dependencies,
            &root.peer_dependencies,
        ] {
            for k in src.keys() {
                direct_names.insert(k.clone());
            }
        }
    }

    let mut report = ExoticReport::default();
    for (key, entry) in &lock.packages {
        if key.is_empty() || entry.link {
            continue;
        }
        report.scanned += 1;
        let Some(raw) = entry.resolved.as_deref() else {
            // No `resolved` URL on a non-root, non-link entry is suspicious
            // on modern npm (v7+) — surface it as "other".
            let name = entry
                .name
                .clone()
                .or_else(|| name_from_path(key))
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            report.findings.push(ExoticFinding {
                ecosystem: "npm",
                name: name.clone(),
                version: entry.version.clone().unwrap_or_default(),
                source: ExoticSource::Other,
                raw: String::from("(no `resolved` field)"),
                direct: direct_names.contains(&name),
            });
            continue;
        };
        let Some(source) = classify_npm_resolved(raw) else {
            // Registry — not exotic. Skip.
            continue;
        };
        let name = entry
            .name
            .clone()
            .or_else(|| name_from_path(key))
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        report.findings.push(ExoticFinding {
            ecosystem: "npm",
            name: name.clone(),
            version: entry.version.clone().unwrap_or_default(),
            source,
            raw: raw.to_string(),
            direct: direct_names.contains(&name),
        });
    }
    Ok(report)
}

/// Returns `None` when the resolved URL points at a known registry
/// (= not exotic), or `Some(source)` describing the shape otherwise.
fn classify_npm_resolved(resolved: &str) -> Option<ExoticSource> {
    // Known-good registries: npm, yarn mirror, github packages.
    // Custom internal registries are honoured separately at the proxy
    // layer; for the lint, the conservative call is "if it's an HTTPS
    // tarball at a host we don't recognise as a registry, flag it".
    let r = resolved.trim();
    if r.starts_with("git+")
        || r.starts_with("git://")
        || r.starts_with("git@")
        || r.starts_with("github:")
        || r.starts_with("gitlab:")
        || r.starts_with("bitbucket:")
        || r.starts_with("gist:")
    {
        return Some(ExoticSource::Git);
    }
    if r.starts_with("file:") {
        return Some(ExoticSource::File);
    }
    if r.starts_with("https://") || r.starts_with("http://") {
        // Registry hosts → not exotic.
        if r.contains("registry.npmjs.org")
            || r.contains("registry.yarnpkg.com")
            || r.contains(".pkg.github.com")
            || r.contains("npm.pkg.github.com")
        {
            return None;
        }
        return Some(ExoticSource::Tarball);
    }
    // Anything else (ssh:, custom protocols, bare paths) → other.
    Some(ExoticSource::Other)
}

fn name_from_path(key: &str) -> Option<String> {
    let last = key.rsplit("node_modules/").next()?;
    if last.is_empty() {
        return None;
    }
    Some(last.trim_end_matches('/').to_string())
}

// -------------------------------------------------------------- cargo

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(rename = "package", default)]
    packages: Vec<CargoPkg>,
}

#[derive(Debug, Deserialize)]
struct CargoPkg {
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

fn scan_cargo(path: &Path) -> Result<ExoticReport> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: CargoLock = toml::from_str(&text)
        .with_context(|| format!("parsing {} as Cargo.lock", path.display()))?;

    // Workspace members are the entries with no `source`. Treat the
    // union of *their* declared dependencies as the "direct" set.
    let workspace_members: BTreeSet<&str> = lock
        .packages
        .iter()
        .filter(|p| p.source.is_none())
        .map(|p| p.name.as_str())
        .collect();
    let mut direct_names: BTreeSet<String> = BTreeSet::new();
    for p in &lock.packages {
        if workspace_members.contains(p.name.as_str()) {
            for d in &p.dependencies {
                // dep entries are either "name" or "name version" or
                // "name version (source)" — first whitespace-split token
                // is the name.
                if let Some(n) = d.split_whitespace().next() {
                    direct_names.insert(n.to_string());
                }
            }
        }
    }

    let mut report = ExoticReport::default();
    for p in &lock.packages {
        let Some(source) = p.source.as_deref() else {
            // Workspace member — skip; it's not "fetched" at all.
            continue;
        };
        report.scanned += 1;
        let kind = classify_cargo_source(source);
        let Some(kind) = kind else {
            continue;
        };
        report.findings.push(ExoticFinding {
            ecosystem: "crates",
            name: p.name.clone(),
            version: p.version.clone(),
            source: kind,
            raw: source.to_string(),
            direct: direct_names.contains(&p.name),
        });
    }
    Ok(report)
}

fn classify_cargo_source(source: &str) -> Option<ExoticSource> {
    if source.starts_with("registry+") || source.starts_with("sparse+") {
        return None;
    }
    if source.starts_with("git+") || source.starts_with("git://") {
        return Some(ExoticSource::Git);
    }
    if source.starts_with("path+") || source.starts_with("file:") {
        return Some(ExoticSource::File);
    }
    Some(ExoticSource::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sakimori-exotic-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn classify_npm_recognises_registry_and_exotic_shapes() {
        assert!(classify_npm_resolved("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz").is_none());
        assert!(classify_npm_resolved("https://registry.yarnpkg.com/foo").is_none());
        assert!(classify_npm_resolved("https://npm.pkg.github.com/foo").is_none());
        assert_eq!(
            classify_npm_resolved("git+https://github.com/x/y.git#abc"),
            Some(ExoticSource::Git)
        );
        assert_eq!(classify_npm_resolved("github:x/y"), Some(ExoticSource::Git));
        assert_eq!(
            classify_npm_resolved("file:../local"),
            Some(ExoticSource::File)
        );
        assert_eq!(
            classify_npm_resolved("https://example.com/random.tgz"),
            Some(ExoticSource::Tarball)
        );
        assert_eq!(
            classify_npm_resolved("ssh://git@gitea.internal:22/x/y.git"),
            Some(ExoticSource::Other)
        );
    }

    #[test]
    fn scan_npm_finds_exotic_subdeps_and_marks_direct() {
        let body = r#"{
  "name":"root","version":"0.0.0","lockfileVersion":3,"requires":true,
  "packages": {
    "": {
      "name":"root","version":"0.0.0",
      "dependencies": {"direct-git": "github:x/direct-git"}
    },
    "node_modules/lodash": {"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
    "node_modules/direct-git": {"version":"0.0.1","resolved":"git+https://github.com/x/direct-git.git"},
    "node_modules/sub-git": {"version":"0.0.1","resolved":"git+https://github.com/x/sub-git.git"},
    "node_modules/sub-tarball": {"version":"0.0.2","resolved":"https://example.com/sub-tarball-0.0.2.tgz"}
  }
}"#;
        let p = tmp("package-lock.json", body);
        let r = scan(&p).unwrap();
        assert_eq!(r.scanned, 4);
        assert_eq!(r.findings.len(), 3);

        let by_name: std::collections::BTreeMap<_, _> =
            r.findings.iter().map(|f| (f.name.clone(), f)).collect();
        assert_eq!(by_name["direct-git"].source, ExoticSource::Git);
        assert!(by_name["direct-git"].direct);
        assert_eq!(by_name["sub-git"].source, ExoticSource::Git);
        assert!(!by_name["sub-git"].direct);
        assert_eq!(by_name["sub-tarball"].source, ExoticSource::Tarball);
        assert!(!by_name["sub-tarball"].direct);

        assert_eq!(r.transitive_count(), 2);
    }

    #[test]
    fn classify_cargo_recognises_registry_and_exotic_shapes() {
        assert!(
            classify_cargo_source("registry+https://github.com/rust-lang/crates.io-index")
                .is_none()
        );
        assert!(classify_cargo_source("sparse+https://index.crates.io/").is_none());
        assert_eq!(
            classify_cargo_source("git+https://github.com/x/y.git#abc"),
            Some(ExoticSource::Git)
        );
        assert_eq!(
            classify_cargo_source("path+file:///home/u/proj"),
            Some(ExoticSource::File)
        );
    }

    #[test]
    fn scan_cargo_finds_exotic_subdeps_and_marks_direct() {
        let body = r#"
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = ["direct-git", "serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "direct-git"
version = "0.1.0"
source = "git+https://github.com/x/direct-git.git#abcdef"

[[package]]
name = "sub-git"
version = "0.1.0"
source = "git+https://github.com/x/sub-git.git#deadbeef"
"#;
        let p = tmp("Cargo.lock", body);
        let r = scan(&p).unwrap();
        // Only `source != None` entries count as "scanned".
        assert_eq!(r.scanned, 3);
        assert_eq!(r.findings.len(), 2);

        let by_name: std::collections::BTreeMap<_, _> =
            r.findings.iter().map(|f| (f.name.clone(), f)).collect();
        assert!(by_name["direct-git"].direct);
        assert_eq!(by_name["direct-git"].source, ExoticSource::Git);
        assert!(!by_name["sub-git"].direct);
        assert_eq!(by_name["sub-git"].source, ExoticSource::Git);
        assert_eq!(r.transitive_count(), 1);
    }

    #[test]
    fn scan_rejects_unsupported_ecosystems() {
        // poetry.lock detect → Pypi → bail!.
        let p = tmp("poetry.lock", "");
        let err = scan(&p).unwrap_err().to_string();
        assert!(err.contains("not implemented"), "unexpected error: {err}");
    }
}
