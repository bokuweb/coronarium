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

    pub fn get(
        &self,
        eco: &Ecosystem,
        name: &str,
        version: &str,
        endpoint_fingerprint: &str,
    ) -> Option<DateTime<Utc>> {
        let key = Self::key(eco, name, version, endpoint_fingerprint);
        let s = self.map.get(&key)?;
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    }

    pub fn put(
        &mut self,
        eco: &Ecosystem,
        name: &str,
        version: &str,
        endpoint_fingerprint: &str,
        when: DateTime<Utc>,
    ) {
        self.map.insert(
            Self::key(eco, name, version, endpoint_fingerprint),
            when.to_rfc3339(),
        );
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

    /// Key includes a per-endpoint fingerprint so switching
    /// `--<eco>-registry` produces a fresh cache slot rather than
    /// returning a stale `(name, version)` answer from the
    /// previous registry. Codex R1+R2 finding: the same package
    /// can have different publish dates on different mirrors.
    /// Per-ecosystem only — changing `--npm-registry` doesn't
    /// invalidate cargo entries.
    fn key(eco: &Ecosystem, name: &str, version: &str, endpoint_fingerprint: &str) -> String {
        format!(
            "{}:{}/{}@{}",
            eco.label(),
            endpoint_fingerprint,
            name,
            version
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sakimori-cache-{id}/deps.json"))
    }

    const FP: &str = "0000000000000000";

    #[test]
    fn empty_cache_returns_none() {
        let c = Cache::open(&tmp()).unwrap();
        let dt: chrono::DateTime<Utc> = "2020-01-01T00:00:00Z".parse().unwrap();
        assert!(c.get(&Ecosystem::Crates, "serde", "1.0.0", FP).is_none());
        let _ = dt;
    }

    #[test]
    fn put_then_get_roundtrip_and_persists() {
        let path = tmp();
        let when: chrono::DateTime<Utc> = "2020-06-15T09:00:00Z".parse().unwrap();
        {
            let mut c = Cache::open(&path).unwrap();
            assert!(c.get(&Ecosystem::Npm, "foo", "1.2.3", FP).is_none());
            c.put(&Ecosystem::Npm, "foo", "1.2.3", FP, when);
            assert_eq!(c.get(&Ecosystem::Npm, "foo", "1.2.3", FP), Some(when));
            c.save().unwrap();
        }
        let c2 = Cache::open(&path).unwrap();
        assert_eq!(c2.get(&Ecosystem::Npm, "foo", "1.2.3", FP), Some(when));
        // Different ecosystem key doesn't collide.
        assert!(c2.get(&Ecosystem::Crates, "foo", "1.2.3", FP).is_none());
    }

    #[test]
    fn different_endpoint_fingerprint_does_not_collide() {
        let path = tmp();
        let when_a: chrono::DateTime<Utc> = "2020-01-01T00:00:00Z".parse().unwrap();
        let when_b: chrono::DateTime<Utc> = "2024-12-31T00:00:00Z".parse().unwrap();
        let mut c = Cache::open(&path).unwrap();
        c.put(&Ecosystem::Npm, "foo", "1.0.0", "aaaaaaaaaaaaaaaa", when_a);
        c.put(&Ecosystem::Npm, "foo", "1.0.0", "bbbbbbbbbbbbbbbb", when_b);
        assert_eq!(
            c.get(&Ecosystem::Npm, "foo", "1.0.0", "aaaaaaaaaaaaaaaa"),
            Some(when_a)
        );
        assert_eq!(
            c.get(&Ecosystem::Npm, "foo", "1.0.0", "bbbbbbbbbbbbbbbb"),
            Some(when_b)
        );
        // Switching endpoints must NOT return a stale answer from
        // the other (Codex R1 finding).
        assert_ne!(
            c.get(&Ecosystem::Npm, "foo", "1.0.0", "aaaaaaaaaaaaaaaa"),
            c.get(&Ecosystem::Npm, "foo", "1.0.0", "bbbbbbbbbbbbbbbb"),
        );
    }

    #[test]
    fn corrupt_cache_file_is_tolerated() {
        let path = tmp();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{not valid json").unwrap();
        let c = Cache::open(&path).unwrap();
        assert!(c.get(&Ecosystem::Npm, "x", "1", FP).is_none());
    }

    #[test]
    fn save_is_noop_when_not_dirty() {
        let path = tmp();
        let c = Cache::open(&path).unwrap();
        c.save().unwrap();
        // File shouldn't have been created (no parent mkdir either).
        assert!(!path.exists());
    }
}
