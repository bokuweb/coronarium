//! Sparse-index response rewriting.
//!
//! The crates.io sparse index (`https://index.crates.io/<prefix>/<name>`)
//! returns one JSON object per line, one per published version:
//!
//! ```text
//! {"name":"serde","vers":"1.0.200","deps":[…],"cksum":"…","yanked":false,…}
//! {"name":"serde","vers":"1.0.201","deps":[…],"cksum":"…","yanked":false,…}
//! ```
//!
//! Cargo's resolver treats a version that *isn't in the index* as
//! simply non-existent, and naturally falls back to older in-range
//! versions. That is exactly the pnpm-style "auto-fallback" semantics
//! we want for `minimumReleaseAge`: too-young versions become invisible
//! to the resolver without any error, while older acceptable versions
//! still resolve cleanly.
//!
//! This module provides a **pure** rewrite function so it can be unit
//! tested without spinning up hyper / hudsucker.

use chrono::{DateTime, Utc};
use coronarium_core::deps::Ecosystem;
use serde::Deserialize;

use crate::decision::{AgeOracle, Decider, Decision};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteStats {
    pub kept: usize,
    pub dropped: usize,
}

/// Minimal subset of each index line we need to make a decision. We
/// deserialise only `name` + `vers`; everything else is preserved
/// byte-for-byte by keeping the original line.
#[derive(Deserialize)]
struct IndexLine<'a> {
    name: &'a str,
    vers: &'a str,
}

/// Filter a crates.io sparse-index JSONL body in place, dropping lines
/// whose `(name, vers)` the decider rejects. Lines we can't parse are
/// passed through unchanged — an index line we don't understand is
/// safer to keep than to silently eat.
pub fn rewrite_crates_index_jsonl(
    body: &[u8],
    decider: &Decider<dyn AgeOracle>,
    now: DateTime<Utc>,
) -> (Vec<u8>, RewriteStats) {
    let mut out = Vec::with_capacity(body.len());
    let mut stats = RewriteStats {
        kept: 0,
        dropped: 0,
    };

    // Iterate over raw lines so we preserve the trailing newlines and
    // any non-JSON junk exactly as the upstream sent them.
    for line in split_lines_keep_terminator(body) {
        let trimmed = trim_trailing_newline(line);
        if trimmed.is_empty() {
            out.extend_from_slice(line);
            continue;
        }
        match serde_json::from_slice::<IndexLine>(trimmed) {
            Ok(parsed) => {
                let decision = decider.decide(Ecosystem::Crates, parsed.name, parsed.vers, now);
                match decision {
                    Decision::Allow => {
                        out.extend_from_slice(line);
                        stats.kept += 1;
                    }
                    Decision::Deny { reason } => {
                        log::info!(
                            "sparse-rewrite: dropping crates/{}@{} ({reason})",
                            parsed.name,
                            parsed.vers
                        );
                        stats.dropped += 1;
                    }
                }
            }
            Err(e) => {
                log::debug!("sparse-rewrite: passing through unparseable index line: {e}");
                out.extend_from_slice(line);
                stats.kept += 1;
            }
        }
    }

    (out, stats)
}

/// Yield each `\n`-terminated slice of `buf`, *including* the terminator
/// byte(s). The final chunk may lack a terminator.
fn split_lines_keep_terminator(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut i = 0;
    std::iter::from_fn(move || {
        if i >= buf.len() {
            return None;
        }
        let start = i;
        while i < buf.len() && buf[i] != b'\n' {
            i += 1;
        }
        if i < buf.len() {
            i += 1; // include the '\n'
        }
        Some(&buf[start..i])
    })
}

fn trim_trailing_newline(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Decider;
    use anyhow::Result;
    use chrono::TimeZone;
    use std::collections::HashMap;
    use std::time::Duration;

    /// Oracle keyed on (name, version). Unknown keys return `None`.
    #[derive(Default)]
    struct MapOracle {
        by_key: HashMap<(String, String), DateTime<Utc>>,
    }

    impl MapOracle {
        fn insert(mut self, name: &str, vers: &str, when: DateTime<Utc>) -> Self {
            self.by_key.insert((name.into(), vers.into()), when);
            self
        }
    }

    impl AgeOracle for MapOracle {
        fn published(
            &self,
            _: Ecosystem,
            name: &str,
            version: &str,
        ) -> Result<Option<DateTime<Utc>>> {
            Ok(self.by_key.get(&(name.into(), version.into())).copied())
        }
    }

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn dec(oracle: MapOracle, min_age_hours: u64) -> Decider<dyn AgeOracle> {
        Decider {
            oracle: Box::new(oracle) as Box<dyn AgeOracle>,
            min_age: Duration::from_secs(min_age_hours * 3600),
            fail_on_missing: false,
        }
    }

    #[test]
    fn keeps_old_drops_young() {
        let now = utc(2025, 1, 10);
        let oracle = MapOracle::default()
            .insert("serde", "1.0.100", now - chrono::Duration::days(30))
            .insert("serde", "1.0.200", now - chrono::Duration::hours(2));
        let d = dec(oracle, 168);

        let body = concat!(
            r#"{"name":"serde","vers":"1.0.100","cksum":"aaa","yanked":false}"#,
            "\n",
            r#"{"name":"serde","vers":"1.0.200","cksum":"bbb","yanked":false}"#,
            "\n",
        );
        let (out, stats) = rewrite_crates_index_jsonl(body.as_bytes(), &d, now);
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("1.0.100"));
        assert!(!out.contains("1.0.200"));
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn preserves_line_bytes_verbatim() {
        // Notably: preserves "yanked":false ordering, cksum, etc. — the
        // consumer relies on cksum matching the .crate tarball.
        let now = utc(2025, 1, 10);
        let oracle = MapOracle::default().insert("x", "1.0.0", now - chrono::Duration::days(30));
        let d = dec(oracle, 168);

        let body = r#"{"name":"x","vers":"1.0.0","cksum":"0123abcd","yanked":false,"features":{}}
"#;
        let (out, _) = rewrite_crates_index_jsonl(body.as_bytes(), &d, now);
        assert_eq!(out, body.as_bytes());
    }

    #[test]
    fn unknown_publish_date_fails_open_keeps_line() {
        // Oracle returns None (crate has no known publish date). The
        // decider defaults to Allow, so we keep the line.
        let now = utc(2025, 1, 10);
        let d = dec(MapOracle::default(), 168);

        let body = r#"{"name":"mystery","vers":"0.1.0"}
"#;
        let (out, stats) = rewrite_crates_index_jsonl(body.as_bytes(), &d, now);
        assert_eq!(out, body.as_bytes());
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn empty_body_round_trips() {
        let now = utc(2025, 1, 10);
        let d = dec(MapOracle::default(), 168);
        let (out, stats) = rewrite_crates_index_jsonl(b"", &d, now);
        assert!(out.is_empty());
        assert_eq!(stats.kept, 0);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn unparseable_line_is_passed_through() {
        let now = utc(2025, 1, 10);
        let d = dec(MapOracle::default(), 168);
        let body = b"not json at all\n";
        let (out, stats) = rewrite_crates_index_jsonl(body, &d, now);
        assert_eq!(out, body);
        assert_eq!(stats.kept, 1);
    }

    #[test]
    fn all_young_yields_empty_body_no_error() {
        // Every version is too new. Output is empty — cargo sees "no
        // matching versions" and errors cleanly at resolve time.
        let now = utc(2025, 1, 10);
        let oracle = MapOracle::default()
            .insert("hot", "1.0.0", now - chrono::Duration::hours(1))
            .insert("hot", "1.0.1", now - chrono::Duration::hours(2));
        let d = dec(oracle, 168);

        let body = concat!(
            r#"{"name":"hot","vers":"1.0.0"}"#,
            "\n",
            r#"{"name":"hot","vers":"1.0.1"}"#,
            "\n",
        );
        let (out, stats) = rewrite_crates_index_jsonl(body.as_bytes(), &d, now);
        assert!(out.is_empty());
        assert_eq!(stats.kept, 0);
        assert_eq!(stats.dropped, 2);
    }

    #[test]
    fn handles_crlf_line_endings() {
        let now = utc(2025, 1, 10);
        let oracle = MapOracle::default()
            .insert("a", "1.0.0", now - chrono::Duration::days(30))
            .insert("a", "9.9.9", now - chrono::Duration::hours(1));
        let d = dec(oracle, 168);

        let body = "{\"name\":\"a\",\"vers\":\"1.0.0\"}\r\n\
                    {\"name\":\"a\",\"vers\":\"9.9.9\"}\r\n";
        let (out, stats) = rewrite_crates_index_jsonl(body.as_bytes(), &d, now);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("1.0.0"));
        assert!(!out.contains("9.9.9"));
        // The kept line retains its CRLF terminator.
        assert!(out.ends_with("\r\n"));
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn final_line_without_terminator_is_still_processed() {
        let now = utc(2025, 1, 10);
        let oracle = MapOracle::default().insert("a", "1.0.0", now - chrono::Duration::days(30));
        let d = dec(oracle, 168);

        let body = br#"{"name":"a","vers":"1.0.0"}"#; // no trailing \n
        let (out, stats) = rewrite_crates_index_jsonl(body, &d, now);
        assert_eq!(out, body);
        assert_eq!(stats.kept, 1);
    }
}
