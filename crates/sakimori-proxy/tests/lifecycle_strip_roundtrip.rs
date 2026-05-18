//! Tarball roundtrip e2e for `--lifecycle-policy strip`.
//!
//! Unit tests in `src/lifecycle.rs::tests` cover single-entry happy
//! path, no-op, hash consistency, non-gzip rejection, the compressed
//! and decompressed caps, the `validate_entry_path` helper in
//! isolation, and a proptest harness ensuring strip never panics.
//!
//! This file fills the gaps those tests can't reach:
//!
//! 1. Multi-entry roundtrip with mode + symlink + hardlink +
//!    directory preservation through the full strip path.
//! 2. `max_entries` enforced end-to-end.
//! 3. `max_single_entry_bytes` enforced end-to-end.
//! 4. `BadPath` end-to-end (the existing test only calls the
//!    validator helper directly).
//! 5. Nested `package/node_modules/sub/package.json` invariant
//!    (only the *root* `package/package.json` is modified;
//!    enforced at `lifecycle.rs:472` by `components().count() == 2`).
//! 6. `package.json` top-level key ordering preserved (proves the
//!    workspace `serde_json` `preserve_order` feature is wired).
//! 7. `StripOutcome` → `StripCacheEntry::Stripped` coupling contract
//!    that the proxy uses inline at `proxy.rs:626-635`.
//!
//! Plan reviewed + approved by Codex (3 rounds).

use std::io::{Read, Write};
use std::path::PathBuf;

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use sakimori_proxy::lifecycle::{StripError, StripLimits, StripOutcome, strip_npm_tarball};
use sakimori_proxy::strip_cache::StripCacheEntry;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// One entry to pack into a synthetic .tgz. Mirrors the kinds the
/// strip path actually handles in `rebuild_tar`
/// (`lifecycle.rs:563-598`): regular files, symlinks, hardlinks,
/// directories.
enum Entry<'a> {
    File {
        path: &'a str,
        body: &'a [u8],
        mode: u32,
    },
    Symlink {
        path: &'a str,
        target: &'a str,
    },
    HardLink {
        path: &'a str,
        target: &'a str,
    },
    Directory {
        path: &'a str,
    },
    /// Escape hatch for the security tests: write the path bytes
    /// directly into the tar header's 100-byte `name` field,
    /// bypassing every validation in `tar::Header::set_path` and
    /// `tar::Builder::append_data`. Both reject `..` and leading
    /// `/`. The strip path, however, *does* read this field —
    /// these tests prove `validate_entry_path` catches what
    /// arrives in the unprotected wire format.
    RawPathRegular {
        raw_path: &'a str,
        body: &'a [u8],
    },
}

fn build_tgz(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for e in entries {
            match e {
                Entry::File { path, body, mode } => {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(body.len() as u64);
                    header.set_mode(*mode);
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_cksum();
                    builder.append_data(&mut header, path, *body).unwrap();
                }
                Entry::Symlink { path, target } => {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(0);
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_mode(0o777);
                    header.set_cksum();
                    builder.append_link(&mut header, path, target).unwrap();
                }
                Entry::HardLink { path, target } => {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(0);
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_mode(0o644);
                    header.set_cksum();
                    builder.append_link(&mut header, path, target).unwrap();
                }
                Entry::Directory { path } => {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(0);
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_mode(0o755);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, path, std::io::empty())
                        .unwrap();
                }
                Entry::RawPathRegular { raw_path, body } => {
                    // Bypass `set_path` (which rejects `..` /
                    // absolute paths) by writing directly into
                    // the 100-byte `name` field of the GNU header.
                    let mut header = tar::Header::new_gnu();
                    header.set_size(body.len() as u64);
                    header.set_mode(0o644);
                    header.set_entry_type(tar::EntryType::Regular);
                    let raw_bytes = raw_path.as_bytes();
                    assert!(
                        raw_bytes.len() <= 100,
                        "raw_path {raw_path} too long for legacy name field"
                    );
                    {
                        let buf = header.as_mut_bytes();
                        // Clear the first 100 bytes (name field) and
                        // write the raw path. Leaves the rest of
                        // the header (mode/size/etc. set above)
                        // intact.
                        for b in buf.iter_mut().take(100) {
                            *b = 0;
                        }
                        buf[..raw_bytes.len()].copy_from_slice(raw_bytes);
                    }
                    header.set_cksum();
                    builder.get_mut().write_all(header.as_bytes()).unwrap();
                    builder.get_mut().write_all(body).unwrap();
                    // Pad to 512-byte block boundary.
                    let pad = (512 - (body.len() % 512)) % 512;
                    if pad > 0 {
                        builder.get_mut().write_all(&vec![0u8; pad]).unwrap();
                    }
                }
            }
        }
        builder.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

struct ExtractedEntry {
    path: PathBuf,
    entry_type: tar::EntryType,
    mode: u32,
    body: Vec<u8>,
    link_name: Option<PathBuf>,
}

fn extract_tgz(bytes: &[u8]) -> Vec<ExtractedEntry> {
    let dec = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(dec);
    let mut out = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut e = entry.unwrap();
        let path = e.path().unwrap().into_owned();
        let entry_type = e.header().entry_type();
        let mode = e.header().mode().unwrap_or(0);
        let link_name = e.header().link_name().unwrap().map(|c| c.into_owned());
        let mut body = Vec::new();
        if entry_type.is_file() {
            e.read_to_end(&mut body).unwrap();
        }
        out.push(ExtractedEntry {
            path,
            entry_type,
            mode,
            body,
            link_name,
        });
    }
    out
}

fn find<'a>(entries: &'a [ExtractedEntry], path: &str) -> &'a ExtractedEntry {
    let target = std::path::Path::new(path);
    entries
        .iter()
        .find(|e| e.path == target)
        .unwrap_or_else(|| {
            panic!(
                "entry {path} not found in: {:?}",
                entries.iter().map(|e| &e.path).collect::<Vec<_>>()
            )
        })
}

/// Build a `package.json` body whose top-level key order matches
/// the slice. Relies on `serde_json`'s `preserve_order` feature.
fn ordered_package_json(pairs: &[(&str, serde_json::Value)]) -> Vec<u8> {
    let mut map = serde_json::Map::new();
    for (k, v) in pairs {
        map.insert((*k).to_string(), v.clone());
    }
    serde_json::to_vec(&serde_json::Value::Object(map)).unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: multi-entry roundtrip preserving mode + symlink + hardlink
// + directory
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_preserves_structure_modes_and_links() {
    let index_js = b"console.log('hello');\n";
    let nested_js = b"export const X = 1;\n";
    let bin_cli = b"#!/usr/bin/env node\nrequire('../index.js');\n";

    let pkg_json = br#"{"name":"demo","version":"1.0.0","scripts":{"preinstall":"a","install":"b","postinstall":"c","prepare":"d","test":"jest"}}"#;

    let tgz = build_tgz(&[
        Entry::File {
            path: "package/package.json",
            body: pkg_json,
            mode: 0o644,
        },
        Entry::File {
            path: "package/index.js",
            body: index_js,
            mode: 0o644,
        },
        Entry::File {
            path: "package/bin/cli",
            body: bin_cli,
            mode: 0o755,
        },
        Entry::File {
            path: "package/lib/nested.js",
            body: nested_js,
            mode: 0o644,
        },
        Entry::Symlink {
            path: "package/symlink",
            target: "index.js",
        },
        Entry::HardLink {
            path: "package/hardlink",
            target: "package/index.js",
        },
        Entry::Directory {
            path: "package/data/",
        },
    ]);

    let outcome = strip_npm_tarball(&tgz, &StripLimits::default())
        .expect("strip should succeed")
        .expect("strip should report Some — lifecycle scripts present");

    // All 4 lifecycle keys should be reported as stripped.
    let mut stages = outcome.stripped_stages.clone();
    stages.sort();
    assert_eq!(
        stages,
        vec!["install", "postinstall", "preinstall", "prepare"]
    );

    let extracted = extract_tgz(&outcome.bytes);

    // Per-entry preservation: mode, body, link target survive verbatim.
    let index = find(&extracted, "package/index.js");
    assert_eq!(index.entry_type, tar::EntryType::Regular);
    assert_eq!(index.body, index_js);
    assert_eq!(index.mode & 0o777, 0o644);

    let cli = find(&extracted, "package/bin/cli");
    assert_eq!(cli.body, bin_cli);
    assert_eq!(
        cli.mode & 0o777,
        0o755,
        "executable bit must survive the rewrite"
    );

    let nested = find(&extracted, "package/lib/nested.js");
    assert_eq!(nested.body, nested_js);

    let sym = find(&extracted, "package/symlink");
    assert!(sym.entry_type.is_symlink(), "symlink entry-type lost");
    assert_eq!(
        sym.link_name.as_deref().and_then(|p| p.to_str()),
        Some("index.js"),
        "symlink target must be preserved byte-for-byte"
    );

    let hard = find(&extracted, "package/hardlink");
    assert!(hard.entry_type.is_hard_link(), "hardlink entry-type lost");
    assert_eq!(
        hard.link_name.as_deref().and_then(|p| p.to_str()),
        Some("package/index.js"),
        "hardlink target must be preserved byte-for-byte"
    );

    let dir = find(&extracted, "package/data/");
    assert!(dir.entry_type.is_dir(), "directory entry-type lost");

    // Root package.json: lifecycle keys gone, non-lifecycle survives.
    let root = find(&extracted, "package/package.json");
    let v: serde_json::Value = serde_json::from_slice(&root.body).unwrap();
    let scripts = v["scripts"].as_object().expect("scripts object present");
    for key in ["preinstall", "install", "postinstall", "prepare"] {
        assert!(
            !scripts.contains_key(key),
            "lifecycle key {key} should be stripped from package.json"
        );
    }
    assert_eq!(scripts["test"], "jest", "non-lifecycle script must survive");
}

// ---------------------------------------------------------------------------
// Test 2: package.json top-level key ordering preserved
// ---------------------------------------------------------------------------

#[test]
fn package_json_top_level_key_order_preserved() {
    let scripts = serde_json::json!({
        "test": "jest",
        "postinstall": "foo",
        "install": "bar",
    });

    // The full top-level sequence we expect to see preserved
    // through the strip: scripts is one of seven keys, with
    // unrelated ones on both sides.
    let original = ordered_package_json(&[
        ("name", serde_json::json!("demo")),
        ("version", serde_json::json!("1.0.0")),
        ("description", serde_json::json!("the demo")),
        ("scripts", scripts),
        ("license", serde_json::json!("MIT")),
        ("repository", serde_json::json!({"type":"git","url":"x"})),
        ("dependencies", serde_json::json!({"left-pad":"1.3.0"})),
    ]);

    let tgz = build_tgz(&[Entry::File {
        path: "package/package.json",
        body: &original,
        mode: 0o644,
    }]);
    let outcome = strip_npm_tarball(&tgz, &StripLimits::default())
        .unwrap()
        .expect("scripts present → Some");

    let extracted = extract_tgz(&outcome.bytes);
    let root = find(&extracted, "package/package.json");
    let v: serde_json::Value = serde_json::from_slice(&root.body).unwrap();
    let actual_keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    let expected_keys = vec![
        "name",
        "version",
        "description",
        "scripts",
        "license",
        "repository",
        "dependencies",
    ];
    assert_eq!(
        actual_keys, expected_keys,
        "top-level key order must be preserved (preserve_order feature)"
    );

    // Scripts: only `test` should remain.
    let scripts = v["scripts"].as_object().unwrap();
    assert_eq!(
        scripts.keys().collect::<Vec<_>>(),
        vec!["test"],
        "only non-lifecycle script should remain after strip"
    );
    assert_eq!(scripts["test"], "jest");
}

// ---------------------------------------------------------------------------
// Test 3: nested package/node_modules/sub/package.json invariant
// ---------------------------------------------------------------------------

#[test]
fn nested_node_modules_package_json_untouched() {
    let root_pkg = br#"{"name":"root","scripts":{"postinstall":"root-evil","test":"keep"}}"#;
    let nested_pkg = br#"{"name":"sub","scripts":{"postinstall":"nested-also-evil"}}"#;

    let tgz = build_tgz(&[
        Entry::File {
            path: "package/package.json",
            body: root_pkg,
            mode: 0o644,
        },
        Entry::File {
            path: "package/node_modules/sub/package.json",
            body: nested_pkg,
            mode: 0o644,
        },
    ]);

    let outcome = strip_npm_tarball(&tgz, &StripLimits::default())
        .unwrap()
        .expect("root scripts present → Some");
    assert_eq!(outcome.stripped_stages, vec!["postinstall"]);

    let extracted = extract_tgz(&outcome.bytes);

    // Root package.json: postinstall gone, test stays.
    let root = find(&extracted, "package/package.json");
    let rv: serde_json::Value = serde_json::from_slice(&root.body).unwrap();
    let rs = rv["scripts"].as_object().unwrap();
    assert!(!rs.contains_key("postinstall"));
    assert_eq!(rs["test"], "keep");

    // Nested package.json: byte-identical to input. Pins the
    // contract that strip only touches the *root* package.json.
    let nested = find(&extracted, "package/node_modules/sub/package.json");
    assert_eq!(
        nested.body, nested_pkg,
        "nested node_modules/.../package.json must NOT be modified"
    );
}

// ---------------------------------------------------------------------------
// Test 4: security limits table — every row trips a specific
// StripError variant end-to-end. All fixtures include a root
// package.json with a lifecycle script so the strip path doesn't
// early-return via Ok(None) before the cap/path check is reached.
// ---------------------------------------------------------------------------

const ROOT_PKG_WITH_SCRIPT: &[u8] = br#"{"name":"x","scripts":{"postinstall":"a"}}"#;

#[test]
fn security_limit_max_entries_returns_too_many() {
    // max_entries = 3 → root pkg.json + 3 padding entries = 4 > 3.
    let entries = vec![
        Entry::File {
            path: "package/package.json",
            body: ROOT_PKG_WITH_SCRIPT,
            mode: 0o644,
        },
        Entry::File {
            path: "package/a.js",
            body: b"a",
            mode: 0o644,
        },
        Entry::File {
            path: "package/b.js",
            body: b"b",
            mode: 0o644,
        },
        Entry::File {
            path: "package/c.js",
            body: b"c",
            mode: 0o644,
        },
    ];
    let tgz = build_tgz(&entries);
    let limits = StripLimits {
        max_entries: 3,
        ..StripLimits::default()
    };
    let err = strip_npm_tarball(&tgz, &limits).unwrap_err();
    assert!(
        matches!(err, StripError::TooManyEntries(_)),
        "want TooManyEntries, got {err:?}"
    );
}

#[test]
fn security_limit_max_single_entry_bytes_returns_too_large_entry() {
    let huge_body = vec![b'x'; 8 * 1024];
    let tgz = build_tgz(&[
        Entry::File {
            path: "package/package.json",
            body: ROOT_PKG_WITH_SCRIPT,
            mode: 0o644,
        },
        Entry::File {
            path: "package/huge.bin",
            body: &huge_body,
            mode: 0o644,
        },
    ]);
    // Set the cap below the huge entry's size but above pkg.json.
    let limits = StripLimits {
        max_single_entry_bytes: 1024,
        ..StripLimits::default()
    };
    let err = strip_npm_tarball(&tgz, &limits).unwrap_err();
    assert!(
        matches!(err, StripError::TooLarge { kind: "entry", .. }),
        "want TooLarge {{ kind: entry }}, got {err:?}"
    );
}

#[test]
fn security_bad_path_traversal_returns_bad_path() {
    // tar::Builder::append_data rejects `..` paths at write time
    // (defence in depth on its side), so this test uses
    // RawPathRegular to bypass that and prove `validate_entry_path`
    // in the strip pipeline catches the on-wire form anyway.
    let tgz = build_tgz(&[
        Entry::File {
            path: "package/package.json",
            body: ROOT_PKG_WITH_SCRIPT,
            mode: 0o644,
        },
        Entry::RawPathRegular {
            raw_path: "package/../../etc/passwd",
            body: b"pwned",
        },
    ]);
    let err = strip_npm_tarball(&tgz, &StripLimits::default()).unwrap_err();
    assert!(
        matches!(err, StripError::BadPath(_)),
        "want BadPath, got {err:?}"
    );
}

#[test]
fn security_absolute_path_returns_bad_path() {
    let tgz = build_tgz(&[
        Entry::File {
            path: "package/package.json",
            body: ROOT_PKG_WITH_SCRIPT,
            mode: 0o644,
        },
        Entry::RawPathRegular {
            // tar::Builder::append_data + set_path both normalise
            // away the leading `/`. Bypass with a raw write so the
            // on-wire form actually reaches strip_npm_tarball.
            raw_path: "/etc/passwd",
            body: b"pwned",
        },
    ]);
    let err = strip_npm_tarball(&tgz, &StripLimits::default()).unwrap_err();
    assert!(
        matches!(err, StripError::BadPath(_)),
        "want BadPath, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: StripOutcome → StripCacheEntry::Stripped coupling
// ---------------------------------------------------------------------------

#[test]
fn strip_outcome_maps_to_strip_cache_entry() {
    let tgz = build_tgz(&[Entry::File {
        path: "package/package.json",
        body: br#"{"name":"x","scripts":{"postinstall":"a"}}"#,
        mode: 0o644,
    }]);
    let outcome: StripOutcome = strip_npm_tarball(&tgz, &StripLimits::default())
        .unwrap()
        .expect("strip should report Some");

    // Build the cache entry the same way `proxy.rs:626-635` does
    // when a tarball strip completes.
    let entry = StripCacheEntry::Stripped {
        new_integrity: format!("sha512-{}", outcome.sha512_b64),
        new_shasum: outcome.sha1_hex.clone(),
        bytes: std::sync::Arc::new(outcome.bytes.clone()),
    };

    // Public accessors return the right values.
    let integ = entry.new_integrity().expect("Stripped has integrity");
    assert!(
        integ.starts_with("sha512-"),
        "new_integrity must carry the sha512- SRI prefix, got {integ}"
    );
    assert_eq!(
        &integ["sha512-".len()..],
        outcome.sha512_b64,
        "SRI tail must equal outcome.sha512_b64 byte-for-byte"
    );
    assert_eq!(entry.new_shasum(), Some(outcome.sha1_hex.as_str()));

    // Bytes round-trip via pattern match (no `bytes()` accessor on
    // StripCacheEntry — pattern-match is the correct API per the
    // round-2 review).
    match entry {
        StripCacheEntry::Stripped { ref bytes, .. } => {
            assert_eq!(bytes.len(), outcome.bytes.len());
            assert_eq!(bytes.as_slice(), outcome.bytes.as_slice());
        }
        StripCacheEntry::NoStripNeeded => panic!("expected Stripped variant"),
    }
}
