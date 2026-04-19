//! Tiny on-disk cache for registry lookups.
//!
//! Schema: flat JSON `{ "<ecosystem>/<name>@<version>": "<rfc3339>" }`.
//! Publish dates don't change, so there's no TTL — the cache grows
//! indefinitely (users can just delete the file).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use super::Ecosystem;

pub struct Cache {
    path: PathBuf,
    map: BTreeMap<String, String>,
    dirty: bool,
}

impl Cache {
    pub fn open(path: &Path) -> Result<Self> {
        let map = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading cache {}", path.display()))?;
            // Tolerate a corrupt cache by starting fresh — the file is
            // just a speed hint, not authoritative.
            serde_json::from_str(&text).unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            map,
            dirty: false,
        })
    }

    pub fn get(&self, eco: &Ecosystem, name: &str, version: &str) -> Option<DateTime<Utc>> {
        let key = Self::key(eco, name, version);
        let s = self.map.get(&key)?;
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    }

    pub fn put(&mut self, eco: &Ecosystem, name: &str, version: &str, when: DateTime<Utc>) {
        self.map
            .insert(Self::key(eco, name, version), when.to_rfc3339());
        self.dirty = true;
    }

    pub fn save(self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir -p {}", parent.display()))?;
        }
        let serialized = serde_json::to_string(&self.map)?;
        std::fs::write(&self.path, serialized)
            .with_context(|| format!("writing cache {}", self.path.display()))?;
        Ok(())
    }

    fn key(eco: &Ecosystem, name: &str, version: &str) -> String {
        format!("{}/{}@{}", eco.label(), name, version)
    }
}
