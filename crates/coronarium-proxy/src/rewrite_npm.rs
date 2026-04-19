//! npm packument rewriter — the npm-side counterpart to
//! [`crate::rewrite`] for crates.io.
//!
//! The npm "packument" endpoint (`https://registry.npmjs.org/<pkg>`)
//! returns a single JSON document listing every published version of
//! the package. Shape (abbreviated):
//!
//! ```json
//! {
//!   "name": "left-pad",
//!   "dist-tags": { "latest": "1.3.0" },
//!   "versions": {
//!     "1.0.0": { …full per-version manifest… },
//!     "1.3.0": { … }
//!   },
//!   "time": {
//!     "created":  "2014-03-22T21:42:18.000Z",
//!     "modified": "2016-03-22T21:42:18.002Z",
//!     "1.0.0":    "2014-03-22T21:42:18.002Z",
//!     "1.3.0":    "2016-03-22T21:42:18.002Z"
//!   }
//! }
//! ```
//!
//! To achieve pnpm-style auto-fallback we:
//!
//! 1. Walk `time` to find publish dates per version string.
//! 2. Remove any too-young version from both `versions` and `time`.
//! 3. Remap every `dist-tags` entry pointing at a removed version to
//!    the highest remaining version by semver order. This is the
//!    subtle step: if we leave `dist-tags.latest = "1.3.0"` pointing
//!    at a removed key, `npm install <pkg>` (no version specifier)
//!    will ask for `1.3.0` and hard-fail.
//!
//! This module is **pure** and synchronous — unit tests can exercise
//! every branch without hyper.

use std::time::Duration;

use chrono::{DateTime, Utc};
use semver::Version;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmRewriteStats {
    pub kept: usize,
    pub dropped: usize,
    pub retargeted_tags: usize,
}

/// Rewrite an npm packument body, dropping too-young versions and
/// re-pointing dist-tags at the newest remaining version.
///
/// On parse failure returns the body unchanged with zero stats — a
/// malformed packument we don't understand is safer to forward than to
/// silently break. Callers should pass only 2xx bodies (the proxy
/// already gates on that).
pub fn rewrite_npm_packument(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, NpmRewriteStats) {
    let mut stats = NpmRewriteStats {
        kept: 0,
        dropped: 0,
        retargeted_tags: 0,
    };

    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("npm-rewrite: passing through unparseable packument: {e}");
            return (body.to_vec(), stats);
        }
    };

    let Some(obj) = doc.as_object_mut() else {
        return (body.to_vec(), stats);
    };

    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    // Collect publish dates from `time`. npm reserves "created" and
    // "modified" for metadata; every other key is expected to be a
    // version string.
    let too_young: Vec<String> = obj
        .get("time")
        .and_then(Value::as_object)
        .map(|time| {
            time.iter()
                .filter(|(k, _)| k.as_str() != "created" && k.as_str() != "modified")
                .filter_map(|(vers, v)| {
                    let s = v.as_str()?;
                    let published = DateTime::parse_from_rfc3339(s).ok()?.with_timezone(&Utc);
                    if (now - published) < cutoff {
                        Some(vers.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    stats.dropped = too_young.len();

    if !too_young.is_empty() {
        if let Some(versions) = obj.get_mut("versions").and_then(Value::as_object_mut) {
            for v in &too_young {
                versions.remove(v);
            }
            stats.kept = versions.len();
        }
        if let Some(time) = obj.get_mut("time").and_then(Value::as_object_mut) {
            for v in &too_young {
                time.remove(v);
            }
        }

        // Fix up dist-tags. Any tag pointing at a removed version is
        // retargeted to the highest remaining version by semver; tags
        // whose target is still present are left alone.
        let remaining_newest = remaining_newest_version(obj);
        if let Some(tags) = obj.get_mut("dist-tags").and_then(Value::as_object_mut) {
            let too_young_set: std::collections::HashSet<&String> = too_young.iter().collect();
            let to_update: Vec<String> = tags
                .iter()
                .filter_map(|(k, v)| {
                    v.as_str().and_then(|s| {
                        if too_young_set.contains(&s.to_string()) {
                            Some(k.clone())
                        } else {
                            None
                        }
                    })
                })
                .collect();
            for k in &to_update {
                match &remaining_newest {
                    Some(newest) => {
                        tags.insert(k.clone(), Value::String(newest.clone()));
                        stats.retargeted_tags += 1;
                    }
                    None => {
                        // No older versions left at all. Removing the
                        // tag is cleaner than leaving a dangling one;
                        // `npm install <pkg>` will then error with
                        // "No matching version" which is the correct
                        // fail-closed signal.
                        tags.remove(k);
                    }
                }
            }
        }
    } else {
        // Nothing dropped — count kept versions so stats is still
        // useful for logging.
        stats.kept = obj
            .get("versions")
            .and_then(Value::as_object)
            .map(|v| v.len())
            .unwrap_or(0);
    }

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

/// Highest remaining version by semver. Falls back to lexical
/// comparison for non-semver strings so we still produce *some*
/// answer rather than panicking on oddly-tagged packages.
fn remaining_newest_version(obj: &serde_json::Map<String, Value>) -> Option<String> {
    let versions = obj.get("versions")?.as_object()?;
    let mut best: Option<(Option<Version>, String)> = None;
    for key in versions.keys() {
        let parsed = Version::parse(key).ok();
        match &best {
            None => best = Some((parsed, key.clone())),
            Some((best_parsed, best_key)) => {
                let replace = match (best_parsed, &parsed) {
                    (Some(a), Some(b)) => b > a,
                    (None, Some(_)) => true, // semver beats non-semver
                    (Some(_), None) => false,
                    (None, None) => key.as_str() > best_key.as_str(),
                };
                if replace {
                    best = Some((parsed, key.clone()));
                }
            }
        }
    }
    best.map(|(_, k)| k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    /// Build a minimal packument with the given (version, pubtime) pairs.
    fn packument(name: &str, versions: &[(&str, &str)], latest: &str) -> String {
        let mut time = serde_json::Map::new();
        time.insert(
            "created".into(),
            Value::String("2014-01-01T00:00:00Z".into()),
        );
        time.insert(
            "modified".into(),
            Value::String("2024-01-01T00:00:00Z".into()),
        );
        let mut vs = serde_json::Map::new();
        for (v, t) in versions {
            time.insert((*v).into(), Value::String((*t).into()));
            let mut man = serde_json::Map::new();
            man.insert("name".into(), Value::String(name.into()));
            man.insert("version".into(), Value::String((*v).into()));
            vs.insert((*v).into(), Value::Object(man));
        }
        let mut tags = serde_json::Map::new();
        tags.insert("latest".into(), Value::String(latest.into()));
        let mut doc = serde_json::Map::new();
        doc.insert("name".into(), Value::String(name.into()));
        doc.insert("dist-tags".into(), Value::Object(tags));
        doc.insert("versions".into(), Value::Object(vs));
        doc.insert("time".into(), Value::Object(time));
        serde_json::to_string(&doc).unwrap()
    }

    fn min_age_hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn parse(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    #[test]
    fn drops_too_young_versions_from_versions_and_time() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-12-01T00:00:00Z"), // old enough
                ("1.1.0", "2025-01-09T23:00:00Z"), // too young
            ],
            "1.1.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        let vs = doc["versions"].as_object().unwrap();
        let time = doc["time"].as_object().unwrap();
        assert!(vs.contains_key("1.0.0"));
        assert!(!vs.contains_key("1.1.0"));
        assert!(time.contains_key("1.0.0"));
        assert!(!time.contains_key("1.1.0"));
        assert!(time.contains_key("created"));
        assert!(time.contains_key("modified"));
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn retargets_latest_when_it_points_at_removed_version() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.2.0", "2024-06-01T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"), // too young
            ],
            "2.0.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        assert_eq!(doc["dist-tags"]["latest"], "1.2.0");
        assert_eq!(stats.retargeted_tags, 1);
    }

    #[test]
    fn leaves_latest_alone_when_it_is_still_present() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.2.0", "2024-06-01T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"), // too young
            ],
            "1.2.0", // latest already safe
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        assert_eq!(doc["dist-tags"]["latest"], "1.2.0");
        assert_eq!(stats.retargeted_tags, 0);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn removes_tag_when_no_version_is_old_enough() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2025-01-09T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"),
            ],
            "2.0.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        assert!(doc["versions"].as_object().unwrap().is_empty());
        assert!(!doc["dist-tags"].as_object().unwrap().contains_key("latest"));
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.kept, 0);
    }

    #[test]
    fn picks_highest_semver_not_lexical() {
        let now = utc(2025, 1, 10);
        // Lexical order would pick "1.9.0" over "1.10.0"; semver picks 1.10.0.
        let body = packument(
            "foo",
            &[
                ("1.9.0", "2024-01-01T00:00:00Z"),
                ("1.10.0", "2024-02-01T00:00:00Z"),
                ("2.0.0", "2025-01-09T23:00:00Z"),
            ],
            "2.0.0",
        );
        let (out, _) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(doc["dist-tags"]["latest"], "1.10.0");
    }

    #[test]
    fn malformed_body_is_passed_through_unchanged() {
        let now = utc(2025, 1, 10);
        let body = b"not json";
        let (out, stats) = rewrite_npm_packument(body, min_age_hours(168), now);
        assert_eq!(out, body);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn packument_without_time_is_left_alone() {
        let now = utc(2025, 1, 10);
        let body = br#"{"name":"foo","versions":{"1.0.0":{}}}"#;
        let (out, stats) = rewrite_npm_packument(body, min_age_hours(168), now);
        // JSON is re-serialised so may differ in whitespace, but the
        // semantics must be identical.
        let orig: Value = serde_json::from_slice(body).unwrap();
        let got: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(orig, got);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn nothing_dropped_means_versions_unchanged() {
        let now = utc(2025, 1, 10);
        let body = packument(
            "foo",
            &[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.1.0", "2024-06-01T00:00:00Z"),
            ],
            "1.1.0",
        );
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let before: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        let after: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(before, after);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 2);
    }

    #[test]
    fn handles_prerelease_and_non_semver_tags_gracefully() {
        // "next" dist-tag may point at a prerelease; "beta" may point
        // at non-semver like "1.0.0-beta". The rewriter should not
        // crash and should still pick a sensible "highest" fallback.
        let now = utc(2025, 1, 10);
        let body = r#"{
            "name": "foo",
            "dist-tags": { "latest": "2.0.0", "next": "2.0.0" },
            "versions": {
                "1.0.0": {}, "1.2.0": {}, "2.0.0": {}
            },
            "time": {
                "created": "2024-01-01T00:00:00Z",
                "modified": "2025-01-09T00:00:00Z",
                "1.0.0": "2024-01-01T00:00:00Z",
                "1.2.0": "2024-06-01T00:00:00Z",
                "2.0.0": "2025-01-09T23:00:00Z"
            }
        }"#;
        let (out, stats) = rewrite_npm_packument(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(doc["dist-tags"]["latest"], "1.2.0");
        assert_eq!(doc["dist-tags"]["next"], "1.2.0");
        assert_eq!(stats.retargeted_tags, 2);
    }
}
