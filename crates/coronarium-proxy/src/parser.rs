//! Parse incoming HTTPS requests into a `(ecosystem, name, version)`
//! triple we can age-check. Unrecognised URLs return `Unknown` and the
//! proxy passes them through untouched.

use coronarium_core::deps::Ecosystem;

/// Result of inspecting one registry-bound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult {
    /// The request is downloading a specific version — we know
    /// enough to age-check.
    Pinned {
        ecosystem: Ecosystem,
        name: String,
        version: String,
    },
    /// The request is metadata (index lookup, search, etc.) — harmless
    /// even for a young package. Always allow.
    Metadata,
    /// Not a request we care about.
    Unknown,
}

pub trait RegistryParser: Send + Sync {
    /// The authority part this parser is responsible for (for routing).
    fn host(&self) -> &'static str;
    /// Parse the path + query of a request already known to be for
    /// [`Self::host`].
    fn parse(&self, path: &str) -> ParseResult;
}

/// Parser for `crates.io` + its sparse index host.
///
/// URL shapes we handle:
/// - `GET /api/v1/crates/<name>/<version>/download` — the tarball fetch.
///   This is the one we actually need to 403.
/// - `GET <shard>/<name>` (sparse index at index.crates.io) — returns
///   a newline-delimited JSON stream of ALL versions. The client uses
///   this for resolution. We currently treat it as Metadata and let it
///   through; we'll rewrite this to omit too-young versions in a
///   follow-up (that's the pnpm-style auto-fallback story).
/// - anything else → Unknown, pass through.
pub struct CratesIoParser;

impl RegistryParser for CratesIoParser {
    fn host(&self) -> &'static str {
        "crates.io"
    }
    fn parse(&self, path: &str) -> ParseResult {
        // Strip query string.
        let path = path.split('?').next().unwrap_or(path);
        let mut segs = path.trim_start_matches('/').split('/');
        match (segs.next(), segs.next(), segs.next()) {
            (Some("api"), Some("v1"), Some("crates")) => {
                let name = segs.next().unwrap_or_default();
                let version = segs.next().unwrap_or_default();
                let tail = segs.next().unwrap_or_default();
                if !name.is_empty() && !version.is_empty() && tail == "download" {
                    return ParseResult::Pinned {
                        ecosystem: Ecosystem::Crates,
                        name: name.to_string(),
                        version: version.to_string(),
                    };
                }
                ParseResult::Metadata
            }
            _ => ParseResult::Unknown,
        }
    }
}

/// Parser for the sparse index at `index.crates.io`. Entries look
/// like `GET /1/s/serde` (shard) → JSONL metadata. We treat these
/// as Metadata for now.
pub struct CratesIoSparseParser;

impl RegistryParser for CratesIoSparseParser {
    fn host(&self) -> &'static str {
        "index.crates.io"
    }
    fn parse(&self, _path: &str) -> ParseResult {
        ParseResult::Metadata
    }
}

pub fn default_parsers() -> Vec<Box<dyn RegistryParser>> {
    vec![Box::new(CratesIoParser), Box::new(CratesIoSparseParser)]
}

pub fn parse_for_host(parsers: &[Box<dyn RegistryParser>], host: &str, path: &str) -> ParseResult {
    for p in parsers {
        if host.eq_ignore_ascii_case(p.host()) {
            return p.parse(path);
        }
    }
    ParseResult::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_download_url_is_pinned() {
        let p = CratesIoParser;
        let r = p.parse("/api/v1/crates/serde/1.0.0/download");
        assert_eq!(
            r,
            ParseResult::Pinned {
                ecosystem: Ecosystem::Crates,
                name: "serde".into(),
                version: "1.0.0".into(),
            }
        );
    }

    #[test]
    fn crates_download_strips_query() {
        let p = CratesIoParser;
        let r = p.parse("/api/v1/crates/tokio/1.35.0/download?token=abc");
        if let ParseResult::Pinned { name, version, .. } = r {
            assert_eq!(name, "tokio");
            assert_eq!(version, "1.35.0");
        } else {
            panic!("expected Pinned, got {r:?}");
        }
    }

    #[test]
    fn crates_non_download_paths_are_metadata() {
        let p = CratesIoParser;
        assert_eq!(p.parse("/api/v1/crates/serde"), ParseResult::Metadata);
        assert_eq!(p.parse("/api/v1/crates"), ParseResult::Metadata);
        assert_eq!(p.parse("/api/v1/crates/serde/1.0.0"), ParseResult::Metadata);
    }

    #[test]
    fn unknown_paths_are_unknown() {
        let p = CratesIoParser;
        assert_eq!(p.parse("/"), ParseResult::Unknown);
        assert_eq!(p.parse("/api/v2/whatever"), ParseResult::Unknown);
    }

    #[test]
    fn sparse_index_is_metadata_for_now() {
        let p = CratesIoSparseParser;
        assert_eq!(p.parse("/1/s/serde"), ParseResult::Metadata);
        assert_eq!(p.parse("/3/t/tokio"), ParseResult::Metadata);
    }

    #[test]
    fn router_dispatches_on_host_case_insensitively() {
        let ps = default_parsers();
        let r = parse_for_host(&ps, "CRATES.IO", "/api/v1/crates/x/1.0/download");
        assert!(matches!(r, ParseResult::Pinned { .. }));
        let r = parse_for_host(&ps, "other.example", "/");
        assert_eq!(r, ParseResult::Unknown);
    }
}
