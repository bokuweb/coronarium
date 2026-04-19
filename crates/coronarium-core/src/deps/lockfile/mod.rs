pub mod cargo;
pub mod npm;

use std::path::Path;

use anyhow::Result;

use super::{Ecosystem, Package};

pub fn detect(path: &Path) -> Result<Ecosystem> {
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    match fname {
        "package-lock.json" => Ok(Ecosystem::Npm),
        "Cargo.lock" => Ok(Ecosystem::Crates),
        _ => anyhow::bail!(
            "unsupported lockfile '{fname}' (supported: package-lock.json, Cargo.lock)"
        ),
    }
}

pub fn parse(eco: Ecosystem, path: &Path) -> Result<Vec<Package>> {
    match eco {
        Ecosystem::Npm => npm::parse(path),
        Ecosystem::Crates => cargo::parse(path),
    }
}
