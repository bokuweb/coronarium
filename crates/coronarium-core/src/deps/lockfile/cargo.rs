//! Parse `Cargo.lock`. Only `source = "registry+https://github.com/rust-lang/crates.io-index"`
//! entries (or no `source` when pointing at crates.io via the sparse index) are
//! checkable — git / path deps don't have registry publish dates.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::deps::{Ecosystem, Package};

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(rename = "package", default)]
    packages: Vec<PkgEntry>,
}

#[derive(Debug, Deserialize)]
struct PkgEntry {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

pub fn parse(path: &Path) -> Result<Vec<Package>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: CargoLock = toml::from_str(&text)
        .with_context(|| format!("parsing {} as Cargo.lock", path.display()))?;

    let mut out = Vec::new();
    for p in lock.packages {
        let Some(source) = p.source.as_deref() else {
            // Workspace member / path dep — skip.
            continue;
        };
        // "registry+https://github.com/rust-lang/crates.io-index"
        // or       "sparse+https://index.crates.io/"
        if !source.contains("crates.io") {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Crates,
            name: p.name,
            version: p.version,
        });
    }
    Ok(out)
}
