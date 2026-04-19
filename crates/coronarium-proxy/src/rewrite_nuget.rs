//! NuGet registration-index rewriter.
//!
//! NuGet's "registration" endpoints are the per-package metadata
//! documents that list every published version plus its
//! `catalogEntry.published` timestamp. There are two shapes we
//! handle with the same rewriter:
//!
//! 1. `https://api.nuget.org/v3/registration<X>/<id>/index.json`
//!    — the top-level index. Contains an outer `items[]` where each
//!    element is a *page*. A page either carries its versions
//!    inline (`items` nested inside) or points at a separate
//!    page URL.
//!
//! 2. `https://api.nuget.org/v3/registration<X>/<id>/page/<lower>/<upper>.json`
//!    — a paged file. Same shape as an inline page: `items[]` of
//!    `{ catalogEntry: { version, published, … }, … }`.
//!
//! In both cases we walk `items[]` recursively, drop entries whose
//! `catalogEntry.published` is younger than `min_age`, and fix up
//! the `count` field so it stays consistent.
//!
//! Flat-container (`/v3-flatcontainer/<id>/index.json`) has no dates
//! inline, so it's NOT rewritten here. dotnet restore paths through
//! flat-container for nupkg download still hit the existing
//! tarball-level deny — fail-hard, not silent. Silent fallback for
//! flat-container is a roadmap item.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NugetRewriteStats {
    pub kept: usize,
    pub dropped: usize,
}

/// Rewrite a NuGet registration document (index.json or a paged
/// *.json file). Drops `items[]` entries recursively whose
/// `catalogEntry.published` is younger than `min_age`.
///
/// Pass-through on parse failure; the rewriter is best-effort and
/// preserves the body byte-for-byte when we don't understand it.
pub fn rewrite_nuget_registration(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, NugetRewriteStats) {
    let mut stats = NugetRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("nuget-rewrite: pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();
    filter_items_recursively(&mut doc, cutoff, now, &mut stats);
    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

fn filter_items_recursively(
    v: &mut Value,
    cutoff: chrono::Duration,
    now: DateTime<Utc>,
    stats: &mut NugetRewriteStats,
) {
    let Some(obj) = v.as_object_mut() else {
        return;
    };
    if let Some(items) = obj.get_mut("items").and_then(Value::as_array_mut) {
        // Two possibilities per item:
        // (a) leaf: { catalogEntry: { published: … } }
        // (b) page: { items: […] } — recurse.
        let before = items.len();
        items.retain_mut(|it| {
            if let Some(entry) = it.get("catalogEntry") {
                // Leaf — drop if too young.
                let keep = entry
                    .get("published")
                    .and_then(Value::as_str)
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| (now - dt.with_timezone(&Utc)) >= cutoff)
                    .unwrap_or(true); // unknown → keep
                if keep {
                    stats.kept += 1;
                } else {
                    stats.dropped += 1;
                }
                keep
            } else if it.get("items").is_some() {
                // Page with inline nested items — recurse; keep the
                // page even if it ends up empty, because it still
                // carries valid lower/upper bounds and a re-fetch URL.
                filter_items_recursively(it, cutoff, now, stats);
                if let Some(nested) = it.get("items").and_then(Value::as_array) {
                    let count = nested.len();
                    if let Some(obj) = it.as_object_mut() {
                        obj.insert(
                            "count".into(),
                            Value::Number(serde_json::Number::from(count)),
                        );
                    }
                }
                true
            } else {
                // Page reference without inline items — leave alone;
                // the separate fetch for that page will be rewritten
                // when the client follows the link.
                true
            }
        });
        let new_count = items.len();
        let _ = before;
        // Preserve the count field on the outer document / page so
        // downstream consumers don't see a stale length.
        if let Some(count) = obj.get_mut("count") {
            *count = Value::Number(serde_json::Number::from(new_count));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn min_age_hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn parse(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    fn leaf(version: &str, published: &str) -> Value {
        serde_json::json!({
            "@id": format!("https://api.nuget.org/v3/registration5-semver1/pkg/{version}.json"),
            "catalogEntry": {
                "id": "Pkg",
                "version": version,
                "published": published
            }
        })
    }

    fn paged_index(leaves: &[(&str, &str)]) -> String {
        serde_json::to_string(&serde_json::json!({
            "@id": "https://api.nuget.org/v3/registration5-semver1/pkg/index.json",
            "count": 1,
            "items": [{
                "@id": "page",
                "lower": leaves.first().map(|(v,_)| v).unwrap_or(&"0.0.0"),
                "upper": leaves.last().map(|(v,_)| v).unwrap_or(&"0.0.0"),
                "count": leaves.len(),
                "items": leaves.iter().map(|(v,t)| leaf(v,t)).collect::<Vec<_>>()
            }]
        }))
        .unwrap()
    }

    #[test]
    fn drops_young_leaf_entries_and_fixes_counts() {
        let now = utc(2025, 1, 10);
        let body = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00Z"),
            ("1.1.0", "2024-06-01T00:00:00Z"),
            ("2.0.0", "2025-01-09T23:00:00Z"), // too young
        ]);
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);

        let pages = doc["items"].as_array().unwrap();
        assert_eq!(pages.len(), 1);
        let page = &pages[0];
        let leaves = page["items"].as_array().unwrap();
        assert_eq!(leaves.len(), 2);
        assert_eq!(page["count"], 2);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 2);
    }

    #[test]
    fn keeps_entries_with_missing_or_unparseable_published() {
        let now = utc(2025, 1, 10);
        let body = serde_json::to_string(&serde_json::json!({
            "count": 1,
            "items": [{
                "count": 2,
                "items": [
                    { "catalogEntry": { "version": "1.0.0" /* no published */ } },
                    { "catalogEntry": { "version": "1.1.0", "published": "not-a-date" } }
                ]
            }]
        }))
        .unwrap();
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(
            doc["items"][0]["items"].as_array().unwrap().len(),
            2,
            "unknown dates should be kept (fail-open)"
        );
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn leaves_page_references_without_inline_items_alone() {
        // Some index.json pages reference a separate /page/<lower>/<upper>.json URL.
        let now = utc(2025, 1, 10);
        let body = serde_json::to_string(&serde_json::json!({
            "count": 1,
            "items": [{
                "@id": "https://api.nuget.org/v3/registration5-semver1/pkg/page/1.0.0/9.9.9.json",
                "lower": "1.0.0",
                "upper": "9.9.9"
                /* no "items" — client must fetch the page URL */
            }]
        }))
        .unwrap();
        let before: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let after: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(before, after);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 0);
    }

    #[test]
    fn malformed_body_passes_through() {
        let (out, stats) =
            rewrite_nuget_registration(b"not json", min_age_hours(168), utc(2025, 1, 10));
        assert_eq!(out, b"not json");
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn rfc3339_with_offset_works() {
        // NuGet commonly emits `+00:00` instead of `Z`.
        let now = utc(2025, 1, 10);
        let body = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00.000+00:00"),
            ("2.0.0", "2025-01-09T23:00:00.000+00:00"), // too young
        ]);
        let (_, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 1);
    }

    #[test]
    fn nothing_young_means_body_semantics_preserved() {
        let now = utc(2025, 1, 10);
        let body = paged_index(&[
            ("1.0.0", "2024-01-01T00:00:00Z"),
            ("1.1.0", "2024-06-01T00:00:00Z"),
        ]);
        let (out, stats) = rewrite_nuget_registration(body.as_bytes(), min_age_hours(168), now);
        let before: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        let after: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(before, after);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 2);
    }
}
