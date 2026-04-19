//! PyPI metadata rewriters — the pypi.org counterpart to
//! [`crate::rewrite`] (crates.io) and [`crate::rewrite_npm`] (npm).
//!
//! PyPI serves two metadata shapes we care about:
//!
//! 1. **Warehouse JSON API**: `GET /pypi/<pkg>/json` — returns
//!    `releases: { "X.Y.Z": [<file>, …], … }`. Each file carries
//!    `upload_time_iso_8601`. We drop entire version keys whose
//!    earliest file upload time is too young.
//!
//! 2. **Simple index (PEP 691 JSON)**: `GET /simple/<pkg>/` with
//!    `Accept: application/vnd.pypi.simple.v1+json` — returns
//!    `files: [{ "filename", "upload-time", "hashes", … }, …]` plus
//!    a top-level `versions: [...]` listing. We filter `files[]`
//!    per-file on `upload-time`.
//!
//! The Simple index HTML (PEP 503) is a separate story: it has no
//! upload time in the response, so we'd need an out-of-band lookup.
//! Modern pip/uv prefer the JSON endpoints anyway, so we leave HTML
//! as pass-through for now (the `files.pythonhosted.org` tarball
//! deny still catches too-young fetches there, just fail-hard).
//!
//! Pure + synchronous; unit tests cover every branch.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PypiRewriteStats {
    pub kept: usize,
    pub dropped: usize,
}

/// Rewrite a Warehouse JSON API body (`/pypi/<pkg>/json`). Drops
/// version keys from `releases` whose earliest `upload_time_iso_8601`
/// is younger than `min_age`.
pub fn rewrite_pypi_json_api(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, PypiRewriteStats) {
    let mut stats = PypiRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("pypi-rewrite(json): pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };
    let Some(obj) = doc.as_object_mut() else {
        return (body.to_vec(), stats);
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    if let Some(releases) = obj.get_mut("releases").and_then(Value::as_object_mut) {
        // Collect too-young version keys first to avoid borrow conflicts.
        let too_young: Vec<String> = releases
            .iter()
            .filter_map(|(vers, files)| {
                let files = files.as_array()?;
                let earliest = earliest_upload_time_json_api(files)?;
                if (now - earliest) < cutoff {
                    Some(vers.clone())
                } else {
                    None
                }
            })
            .collect();
        stats.dropped = too_young.len();
        for v in &too_young {
            releases.remove(v);
        }
        stats.kept = releases.len();
    }

    // Also blank `urls` (the "latest release's files" shortcut) if any
    // of its files were published too recently. pip/uv sometimes look
    // at `urls` directly when no version is specified.
    if let Some(urls) = obj.get_mut("urls").and_then(Value::as_array_mut) {
        urls.retain(|f| {
            f.get("upload_time_iso_8601")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| (now - dt.with_timezone(&Utc)) >= cutoff)
                .unwrap_or(true) // keep entries we can't parse
        });
    }

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

fn earliest_upload_time_json_api(files: &[Value]) -> Option<DateTime<Utc>> {
    files
        .iter()
        .filter_map(|f| {
            f.get("upload_time_iso_8601")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
        })
        .min()
}

/// Rewrite a PEP 691 Simple index JSON body (`/simple/<pkg>/` with
/// `Accept: application/vnd.pypi.simple.v1+json`). Drops `files[]`
/// entries whose `upload-time` is younger than `min_age`, then
/// prunes the top-level `versions[]` so it only lists versions that
/// still have at least one file.
pub fn rewrite_pypi_simple_json(
    body: &[u8],
    min_age: Duration,
    now: DateTime<Utc>,
) -> (Vec<u8>, PypiRewriteStats) {
    let mut stats = PypiRewriteStats::default();
    let mut doc: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("pypi-rewrite(simple-json): pass-through, parse failed: {e}");
            return (body.to_vec(), stats);
        }
    };
    let Some(obj) = doc.as_object_mut() else {
        return (body.to_vec(), stats);
    };
    let cutoff = chrono::Duration::from_std(min_age).unwrap_or_default();

    if let Some(files) = obj.get_mut("files").and_then(Value::as_array_mut) {
        let before = files.len();
        files.retain(|f| {
            match f
                .get("upload-time")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
            {
                Some(t) => (now - t) >= cutoff,
                None => true, // keep entries with no / unparseable time
            }
        });
        stats.kept = files.len();
        stats.dropped = before - files.len();
    }

    // Rebuild surviving version set from remaining filenames so the
    // top-level `versions` list doesn't advertise versions with zero
    // files. Filename format per PEP 427 / sdist conventions: first
    // `-` separated segment that starts with a digit is the version.
    if stats.dropped > 0 {
        let surviving: std::collections::HashSet<String> = obj
            .get("files")
            .and_then(Value::as_array)
            .map(|files| {
                files
                    .iter()
                    .filter_map(|f| f.get("filename").and_then(Value::as_str))
                    .filter_map(extract_version_from_filename)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(versions) = obj.get_mut("versions").and_then(Value::as_array_mut) {
            versions.retain(|v| v.as_str().map(|s| surviving.contains(s)).unwrap_or(true));
        }
    }

    let out = serde_json::to_vec(&doc).unwrap_or_else(|_| body.to_vec());
    (out, stats)
}

/// Cheap-and-cheerful "pull the version out of a PyPI filename":
/// strip the recognised archive extension, split on `-`, return the
/// first segment starting with a digit. Mirrors the logic already in
/// [`crate::parser::PypiParser::parse`].
fn extract_version_from_filename(filename: &str) -> Option<String> {
    let stem = filename
        .strip_suffix(".whl")
        .or_else(|| filename.strip_suffix(".tar.gz"))
        .or_else(|| filename.strip_suffix(".zip"))
        .or_else(|| filename.strip_suffix(".egg"))?;
    let parts: Vec<&str> = stem.split('-').collect();
    parts
        .iter()
        .skip(1)
        .find(|p| p.starts_with(|c: char| c.is_ascii_digit()))
        .map(|p| (*p).to_string())
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

    // ---------- JSON API ----------

    fn json_api(releases: &[(&str, &[&str])]) -> String {
        let mut rels = serde_json::Map::new();
        for (vers, times) in releases {
            let files: Vec<Value> = times
                .iter()
                .map(|t| {
                    let mut m = serde_json::Map::new();
                    m.insert(
                        "filename".into(),
                        Value::String(format!("pkg-{vers}.tar.gz")),
                    );
                    m.insert("upload_time_iso_8601".into(), Value::String((*t).into()));
                    Value::Object(m)
                })
                .collect();
            rels.insert((*vers).into(), Value::Array(files));
        }
        let mut doc = serde_json::Map::new();
        doc.insert("info".into(), Value::Object(serde_json::Map::new()));
        doc.insert("releases".into(), Value::Object(rels));
        doc.insert("urls".into(), Value::Array(vec![]));
        serde_json::to_string(&doc).unwrap()
    }

    #[test]
    fn json_api_drops_too_young_version_keys() {
        let now = utc(2025, 1, 10);
        let body = json_api(&[
            ("1.0.0", &["2024-12-01T00:00:00Z"]),
            ("1.1.0", &["2025-01-09T23:00:00Z"]), // too young
        ]);
        let (out, stats) = rewrite_pypi_json_api(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        let releases = doc["releases"].as_object().unwrap();
        assert!(releases.contains_key("1.0.0"));
        assert!(!releases.contains_key("1.1.0"));
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn json_api_keeps_version_if_any_file_is_old_enough() {
        // A version with one old file + one young file is judged by
        // the earliest (= oldest) upload_time. A real PyPI release
        // uploads all files close together, so this case is rare,
        // but it's the honest behaviour.
        let now = utc(2025, 1, 10);
        let body = json_api(&[("1.0.0", &["2024-06-01T00:00:00Z", "2025-01-09T23:00:00Z"])]);
        let (out, stats) = rewrite_pypi_json_api(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert!(doc["releases"].as_object().unwrap().contains_key("1.0.0"));
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn json_api_prunes_urls_shortcut() {
        // urls[] lists the latest release's files; if those are young
        // we strip them so tools that consult urls don't get a young
        // pin.
        let now = utc(2025, 1, 10);
        let body = r#"{
            "info": {},
            "releases": {},
            "urls": [
                {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "filename": "old.tar.gz"},
                {"upload_time_iso_8601": "2025-01-09T23:00:00Z", "filename": "new.tar.gz"}
            ]
        }"#;
        let (out, _) = rewrite_pypi_json_api(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        let urls = doc["urls"].as_array().unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0]["filename"], "old.tar.gz");
    }

    #[test]
    fn json_api_malformed_body_passes_through() {
        let (out, stats) = rewrite_pypi_json_api(b"not json", min_age_hours(168), utc(2025, 1, 10));
        assert_eq!(out, b"not json");
        assert_eq!(stats.dropped, 0);
    }

    // ---------- Simple JSON ----------

    fn simple_json(files: &[(&str, &str)], versions: &[&str]) -> String {
        let files_v: Vec<Value> = files
            .iter()
            .map(|(filename, t)| {
                let mut m = serde_json::Map::new();
                m.insert("filename".into(), Value::String((*filename).into()));
                m.insert("upload-time".into(), Value::String((*t).into()));
                Value::Object(m)
            })
            .collect();
        let mut doc = serde_json::Map::new();
        doc.insert("name".into(), Value::String("pkg".into()));
        doc.insert("files".into(), Value::Array(files_v));
        doc.insert(
            "versions".into(),
            Value::Array(
                versions
                    .iter()
                    .map(|v| Value::String((*v).into()))
                    .collect(),
            ),
        );
        serde_json::to_string(&doc).unwrap()
    }

    #[test]
    fn simple_json_drops_young_files_and_prunes_versions() {
        let now = utc(2025, 1, 10);
        let body = simple_json(
            &[
                ("pkg-1.0.0.tar.gz", "2024-06-01T00:00:00Z"),
                ("pkg-2.0.0.tar.gz", "2025-01-09T00:00:00Z"), // young
                ("pkg-2.0.0-py3-none-any.whl", "2025-01-09T00:00:01Z"), // young
            ],
            &["1.0.0", "2.0.0"],
        );
        let (out, stats) = rewrite_pypi_simple_json(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        let files = doc["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["filename"], "pkg-1.0.0.tar.gz");
        let versions: Vec<&str> = doc["versions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(versions, vec!["1.0.0"]);
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.kept, 1);
    }

    #[test]
    fn simple_json_keeps_files_with_no_upload_time() {
        // Some older index entries have no upload-time. We keep them
        // — the tarball deny path catches them downstream if needed.
        let now = utc(2025, 1, 10);
        let body =
            r#"{"name":"pkg","files":[{"filename":"pkg-0.0.1.tar.gz"}],"versions":["0.0.1"]}"#;
        let (out, stats) = rewrite_pypi_simple_json(body.as_bytes(), min_age_hours(168), now);
        let doc = parse(&out);
        assert_eq!(doc["files"].as_array().unwrap().len(), 1);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn simple_json_malformed_body_passes_through() {
        let (out, _) = rewrite_pypi_simple_json(
            b"<!doctype html>\n<body>not json</body>",
            min_age_hours(168),
            utc(2025, 1, 10),
        );
        assert_eq!(out, b"<!doctype html>\n<body>not json</body>");
    }

    // ---------- filename → version ----------

    #[test]
    fn filename_version_extraction_covers_common_shapes() {
        assert_eq!(
            extract_version_from_filename("requests-2.32.4.tar.gz").as_deref(),
            Some("2.32.4")
        );
        assert_eq!(
            extract_version_from_filename("requests-2.32.4-py3-none-any.whl").as_deref(),
            Some("2.32.4")
        );
        assert_eq!(
            extract_version_from_filename("my-cool-pkg-1.0.0.tar.gz").as_deref(),
            Some("1.0.0"),
            "hyphen-separated package name"
        );
        assert_eq!(extract_version_from_filename("weird.txt"), None);
        assert_eq!(extract_version_from_filename(""), None);
    }
}
