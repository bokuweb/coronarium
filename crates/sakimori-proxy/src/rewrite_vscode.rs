//! VS Code Marketplace / OpenVSX extension-query rewriter — the
//! editor-extension counterpart to [`crate::rewrite_npm`] +
//! [`crate::rewrite_pypi`].
//!
//! Both `marketplace.visualstudio.com` (Microsoft's gallery) and
//! `open-vsx.org` (the Eclipse-foundation mirror Cursor / VSCodium
//! query) expose a `POST .../gallery/extensionquery` endpoint that
//! returns a JSON document shaped like:
//!
//! ```json
//! {
//!   "results": [{
//!     "extensions": [{
//!       "publisher": { "publisherName": "ms-vscode", … },
//!       "extensionName": "vscode-eslint",
//!       "versions": [
//!         { "version": "3.0.10",
//!           "lastUpdated": "2024-05-14T12:00:00.000Z",
//!           "assetUri": "…", "files": [ … ] },
//!         { "version": "3.0.9",  "lastUpdated": "2024-04-12T…", … }
//!       ],
//!       …
//!     }]
//!   }]
//! }
//! ```
//!
//! Strategy mirrors the npm packument rewriter: drop entries from
//! every `versions[]` array whose `lastUpdated` is younger than
//! `min_age`. The VS Code client then picks the newest surviving
//! version naturally — same silent-fallback model pnpm uses for
//! `minimumReleaseAge`. If every version of an extension is filtered
//! out we leave the `extensions` entry in place with an empty
//! `versions: []`; the client's installer treats that as "no
//! installable version" and surfaces a clean error rather than the
//! whole query silently dropping the extension (which can mask
//! legitimate missing-on-mirror cases).
//!
//! Pure + synchronous; unit tests cover every branch without a real
//! HTTP server. The marketplace JSON does not preserve key insertion
//! order across all upstreams, but `serde_json` is built workspace-
//! wide with `preserve_order` so re-serialising leaves untouched
//! fields byte-stable.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VscodeRewriteStats {
    pub kept: usize,
    pub dropped: usize,
    /// Extensions whose entire `versions[]` was dropped. Useful for
    /// logging "no installable version" cases distinct from "partial
    /// trim".
    pub emptied_extensions: usize,
}

/// Rewrite a VS Code Marketplace / OpenVSX `extensionquery` JSON
/// body. Drops `versions[]` entries whose `lastUpdated` is younger
/// than `min_age`. Bytes that don't parse as JSON, or don't have the
/// expected envelope, are returned unchanged — defence shouldn't
/// invent rejections for non-standard responses.
pub fn rewrite_extensionquery_json(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, VscodeRewriteStats) {
    let mut stats = VscodeRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("vscode-rewrite: pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    let Some(results) = doc.get_mut("results").and_then(Value::as_array_mut) else {
        return (body.to_vec(), stats);
    };
    for result in results.iter_mut() {
        let Some(exts) = result.get_mut("extensions").and_then(Value::as_array_mut) else {
            continue;
        };
        for ext in exts.iter_mut() {
            let Some(versions) = ext.get_mut("versions").and_then(Value::as_array_mut) else {
                continue;
            };
            let before = versions.len();
            versions.retain(|v| {
                let Some(updated) = v.get("lastUpdated").and_then(Value::as_str) else {
                    // Missing timestamp — keep, fail-open. The
                    // tarball-pin path (#21 lifecycle gate) is the
                    // backstop for "we couldn't decide here".
                    return true;
                };
                let Ok(dt) = DateTime::parse_from_rfc3339(updated) else {
                    return true;
                };
                (now - dt.with_timezone(&Utc)) >= cutoff
            });
            let after = versions.len();
            stats.dropped += before - after;
            stats.kept += after;
            if before > 0 && after == 0 {
                stats.emptied_extensions += 1;
            }
        }
    }

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn body_with(versions_json: &str) -> Vec<u8> {
        format!(
            r#"{{"results":[{{"extensions":[{{"publisher":{{"publisherName":"ms-vscode"}},"extensionName":"vscode-eslint","versions":{versions_json}}}]}}]}}"#,
        )
        .into_bytes()
    }

    #[test]
    fn drops_versions_younger_than_min_age() {
        // now = 2024-05-20; min_age = 7 days; cutoff = 2024-05-13.
        // 3.0.10 (2024-05-19) — too young, drop.
        // 3.0.9  (2024-04-12) — old enough, keep.
        let now = Utc.with_ymd_and_hms(2024, 5, 20, 0, 0, 0).unwrap();
        let body = body_with(
            r#"[
              {"version":"3.0.10","lastUpdated":"2024-05-19T12:00:00.000Z"},
              {"version":"3.0.9","lastUpdated":"2024-04-12T12:00:00.000Z"}
            ]"#,
        );
        let (out, stats) = rewrite_extensionquery_json(&body, Duration::from_secs(7 * 86400), now);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.emptied_extensions, 0);
        let v: Value = serde_json::from_slice(&out).unwrap();
        let versions = v["results"][0]["extensions"][0]["versions"]
            .as_array()
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "3.0.9");
    }

    #[test]
    fn empties_versions_array_when_every_version_is_too_young() {
        let now = Utc.with_ymd_and_hms(2024, 5, 20, 0, 0, 0).unwrap();
        let body = body_with(
            r#"[
              {"version":"3.0.10","lastUpdated":"2024-05-19T12:00:00.000Z"},
              {"version":"3.0.11","lastUpdated":"2024-05-18T12:00:00.000Z"}
            ]"#,
        );
        let (out, stats) = rewrite_extensionquery_json(&body, Duration::from_secs(7 * 86400), now);
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.kept, 0);
        assert_eq!(stats.emptied_extensions, 1);
        let v: Value = serde_json::from_slice(&out).unwrap();
        // Extension entry survives so the client can produce a
        // "no installable version" error rather than silently
        // dropping the extension.
        assert!(
            v["results"][0]["extensions"][0]["versions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            v["results"][0]["extensions"][0]["extensionName"],
            "vscode-eslint"
        );
    }

    #[test]
    fn keeps_entries_with_unparseable_or_missing_timestamps_fail_open() {
        let now = Utc.with_ymd_and_hms(2024, 5, 20, 0, 0, 0).unwrap();
        let body = body_with(
            r#"[
              {"version":"3.0.10"},
              {"version":"3.0.9","lastUpdated":"not-a-date"},
              {"version":"3.0.8","lastUpdated":"2024-04-12T12:00:00.000Z"}
            ]"#,
        );
        let (_, stats) = rewrite_extensionquery_json(&body, Duration::from_secs(7 * 86400), now);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.kept, 3);
    }

    #[test]
    fn non_envelope_json_is_passed_through_byte_for_byte() {
        let now = Utc.with_ymd_and_hms(2024, 5, 20, 0, 0, 0).unwrap();
        let body = br#"{"unexpected":"shape"}"#;
        let (out, stats) = rewrite_extensionquery_json(body, Duration::from_secs(7 * 86400), now);
        assert_eq!(out, body);
        assert_eq!(stats, VscodeRewriteStats::default());
    }

    #[test]
    fn garbage_input_is_passed_through_byte_for_byte() {
        let now = Utc.with_ymd_and_hms(2024, 5, 20, 0, 0, 0).unwrap();
        let body = b"<html>not json</html>";
        let (out, stats) = rewrite_extensionquery_json(body, Duration::from_secs(7 * 86400), now);
        assert_eq!(out, body);
        assert_eq!(stats, VscodeRewriteStats::default());
    }

    #[test]
    fn multiple_extensions_are_filtered_independently() {
        let now = Utc.with_ymd_and_hms(2024, 5, 20, 0, 0, 0).unwrap();
        let body = r#"{"results":[{"extensions":[
              {"publisher":{"publisherName":"a"},"extensionName":"ext-a","versions":[
                {"version":"1.0","lastUpdated":"2024-05-19T12:00:00.000Z"},
                {"version":"0.9","lastUpdated":"2024-04-12T12:00:00.000Z"}
              ]},
              {"publisher":{"publisherName":"b"},"extensionName":"ext-b","versions":[
                {"version":"2.0","lastUpdated":"2024-04-01T12:00:00.000Z"}
              ]}
            ]}]}"#
            .as_bytes()
            .to_vec();
        let (out, stats) = rewrite_extensionquery_json(&body, Duration::from_secs(7 * 86400), now);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.kept, 2);
        let v: Value = serde_json::from_slice(&out).unwrap();
        let exts = v["results"][0]["extensions"].as_array().unwrap();
        assert_eq!(exts[0]["versions"].as_array().unwrap().len(), 1);
        assert_eq!(exts[0]["versions"][0]["version"], "0.9");
        assert_eq!(exts[1]["versions"].as_array().unwrap().len(), 1);
    }
}
