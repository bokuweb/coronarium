//! NuGet `packages.lock.json`.
//!
//! Shape (version 1 and 2):
//!
//! ```json
//! {
//!   "version": 1,
//!   "dependencies": {
//!     "net6.0": {
//!       "Newtonsoft.Json": {
//!         "type": "Direct" | "Transitive" | "Project" | ...,
//!         "resolved": "13.0.1",
//!         "contentHash": "..."
//!       },
//!       ...
//!     },
//!     "net8.0": { ... }
//!   }
//! }
//! ```
//!
//! We collect the union of `(name, resolved)` across all target
//! frameworks and skip entries whose `type` is `Project` (intra-solution
//! project references, not registry packages).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::deps::{Ecosystem, Package};

#[derive(Debug, Deserialize)]
struct Lock {
    #[serde(default)]
    dependencies: BTreeMap<String, BTreeMap<String, Entry>>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
}

pub fn parse(path: &Path) -> Result<Vec<Package>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as packages.lock.json", path.display()))?;

    let mut out = Vec::new();
    for packages in lock.dependencies.values() {
        for (name, entry) in packages {
            if matches!(entry.r#type.as_deref(), Some("Project")) {
                continue;
            }
            let Some(version) = entry.resolved.as_deref() else {
                continue;
            };
            out.push(Package {
                ecosystem: Ecosystem::Nuget,
                name: name.clone(),
                version: version.to_string(),
            });
        }
    }
    Ok(out)
}
