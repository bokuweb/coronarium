//! `.vsix` (VS Code Extension package) inspector — the editor-
//! extension counterpart to [`crate::lifecycle::inspect_npm_tarball`].
//!
//! A `.vsix` is a zip archive (OPC-flavoured) containing an
//! `extension/` root with a `package.json` manifest. The fields we
//! care about for supply-chain audit are:
//!
//! - `activationEvents`: the VS Code primitive controlling when an
//!   extension's code runs. `["*"]` means "activate immediately on
//!   editor startup" — the highest-blast-radius value, and the one
//!   recent supply-chain droppers favour because it removes the
//!   need to convince a victim to invoke any specific command.
//!   `onStartupFinished` is a softer version of the same thing.
//! - `main`: the entry point JS the extension host runs.
//!   References to `child_process` / `node:vm` / `eval` inside that
//!   JS are obvious red flags, but the entry point first surfaces
//!   here.
//!
//! This module is **pure** — input bytes → result struct, no IO
//! beyond zip decoding. The proxy will call it on `.vsix` download
//! responses; CLI auditors can call it on locally cached `.vsix`
//! files to vet sideloads.
//!
//! Out of scope (for the first slice, per CLAUDE.md roadmap #21):
//!
//! - **`strip` mode** (rewrite `activationEvents: ["*"]` to `[]`
//!   and re-emit the zip). Substantially larger because we'd have
//!   to recompute the Marketplace integrity hash the editor then
//!   verifies. Audit / block are the load-bearing first slice.
//! - **`.crx`** (Chrome extensions). Chrome packages are signed
//!   end-to-end so strip is impossible by design; we'll wire `.crx`
//!   audit later.
//! - **`main` JS body scanning**. Catching `eval` / `child_process`
//!   in the bundled JS is valuable but is a larger surface (often
//!   minified / obfuscated) and lives more naturally in the
//!   `iocs::ContentNeedle` catalog than here.

use std::io::{Cursor, Read};

use serde::Deserialize;

/// Hard ceilings on the per-vsix walk so a malicious archive can't
/// stall the proxy. Both values are deliberately generous compared
/// to legitimate extensions (the biggest Marketplace extensions
/// are ~50 MiB compressed; `package.json` is at most a few KiB)
/// so they only fire on attack inputs.
pub const MAX_VSIX_BYTES: usize = 100 * 1024 * 1024;
pub const MAX_PACKAGE_JSON_BYTES: usize = 1024 * 1024;

/// What the inspector found in a `.vsix`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VsixInspection {
    /// `name` from `extension/package.json`. Empty when the manifest
    /// is missing or malformed.
    pub name: String,
    /// `publisher` from `extension/package.json`.
    pub publisher: String,
    /// `version` from `extension/package.json`.
    pub version: String,
    /// Raw `activationEvents` array from the manifest.
    pub activation_events: Vec<String>,
    /// `main` field — the JS entry the extension host loads.
    pub main: Option<String>,
    /// True when `activationEvents` contains the wildcard `"*"`
    /// or `onStartupFinished` — both fire without any user
    /// interaction. The block-mode decision keys off this.
    pub fires_on_startup: bool,
}

impl VsixInspection {
    /// Cheap accessor used by the block decision.
    pub fn has_startup_autorun(&self) -> bool {
        self.fires_on_startup
    }
}

#[derive(Debug)]
pub enum VsixInspectError {
    /// Body exceeded [`MAX_VSIX_BYTES`] — we refuse to walk it.
    TooLarge { size: usize },
    /// Bytes don't open as a zip archive.
    NotZip(String),
    /// `extension/package.json` exists but is past
    /// [`MAX_PACKAGE_JSON_BYTES`]; an honest extension manifest is
    /// at most a few KiB.
    ManifestTooLarge { size: u64 },
    /// IO error while reading the manifest entry.
    ManifestRead(String),
}

impl std::fmt::Display for VsixInspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { size } => {
                write!(
                    f,
                    "vsix body too large: {size} bytes (cap {MAX_VSIX_BYTES})"
                )
            }
            Self::NotZip(s) => write!(f, "vsix is not a valid zip: {s}"),
            Self::ManifestTooLarge { size } => {
                write!(
                    f,
                    "extension/package.json too large: {size} bytes (cap {MAX_PACKAGE_JSON_BYTES})"
                )
            }
            Self::ManifestRead(s) => write!(f, "reading extension/package.json: {s}"),
        }
    }
}

impl std::error::Error for VsixInspectError {}

#[derive(Debug, Deserialize)]
struct ManifestSlice {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "activationEvents")]
    activation_events: Option<Vec<String>>,
    #[serde(default)]
    main: Option<String>,
}

/// Inspect a `.vsix` body. Returns the structured manifest fields
/// plus a derived `fires_on_startup` flag the proxy uses to decide
/// audit / block.
///
/// Fail-open shape: a `.vsix` we can't *parse* (corrupt zip, missing
/// manifest, manifest that doesn't deserialise) returns the default
/// [`VsixInspection`] and the policy layer treats it as "no startup
/// autorun observed". This matches the npm inspector's behaviour —
/// defence shouldn't fabricate denials on malformed-but-legitimate
/// artefacts, and the editor itself will reject a truly broken
/// `.vsix` regardless. The errors returned are the
/// definitely-malicious shape: oversized body, oversized manifest.
pub fn inspect_vsix(body: &[u8]) -> Result<VsixInspection, VsixInspectError> {
    if body.len() > MAX_VSIX_BYTES {
        return Err(VsixInspectError::TooLarge { size: body.len() });
    }
    // `zip` requires Seek; wrap a Cursor.
    let cursor = Cursor::new(body);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => return Err(VsixInspectError::NotZip(e.to_string())),
    };

    // `.vsix` ships a single `extension/` root with all the
    // installable bits. `[Content_Types].xml` etc. live at the
    // archive root but we don't care about them — only the
    // manifest decides what runs.
    let mut entry = match archive.by_name("extension/package.json") {
        Ok(e) => e,
        Err(zip::result::ZipError::FileNotFound) => {
            // Same fail-open shape as the npm inspector: a tarball
            // without a recognisable manifest yields the default
            // (empty) inspection. Don't punish weird-but-valid
            // packages.
            return Ok(VsixInspection::default());
        }
        Err(e) => return Err(VsixInspectError::NotZip(e.to_string())),
    };
    if entry.size() > MAX_PACKAGE_JSON_BYTES as u64 {
        return Err(VsixInspectError::ManifestTooLarge { size: entry.size() });
    }
    let mut buf = Vec::with_capacity(entry.size() as usize);
    if let Err(e) = entry.read_to_end(&mut buf) {
        return Err(VsixInspectError::ManifestRead(e.to_string()));
    }
    Ok(parse_manifest(&buf))
}

fn parse_manifest(body: &[u8]) -> VsixInspection {
    let m: ManifestSlice = match serde_json::from_slice(body) {
        Ok(m) => m,
        Err(_) => return VsixInspection::default(),
    };
    let activation_events = m.activation_events.unwrap_or_default();
    let fires_on_startup = activation_events
        .iter()
        .any(|e| e == "*" || e == "onStartupFinished");
    VsixInspection {
        name: m.name.unwrap_or_default(),
        publisher: m.publisher.unwrap_or_default(),
        version: m.version.unwrap_or_default(),
        activation_events,
        main: m.main,
        fires_on_startup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// Build a synthetic `.vsix`: a zip containing
    /// `extension/package.json` (the only entry the inspector
    /// cares about) plus a junk entry to confirm extra files are
    /// ignored.
    fn build_vsix(manifest_json: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("[Content_Types].xml", opts).unwrap();
            zw.write_all(b"<types/>").unwrap();
            zw.start_file("extension/package.json", opts).unwrap();
            zw.write_all(manifest_json.as_bytes()).unwrap();
            zw.start_file("extension/README.md", opts).unwrap();
            zw.write_all(b"# noise").unwrap();
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extracts_manifest_fields_and_flags_wildcard_activation() {
        let body = build_vsix(
            r#"{
                "name": "evil-ext",
                "publisher": "attacker",
                "version": "1.0.0",
                "main": "./out/extension.js",
                "activationEvents": ["*"]
            }"#,
        );
        let i = inspect_vsix(&body).unwrap();
        assert_eq!(i.name, "evil-ext");
        assert_eq!(i.publisher, "attacker");
        assert_eq!(i.version, "1.0.0");
        assert_eq!(i.main.as_deref(), Some("./out/extension.js"));
        assert_eq!(i.activation_events, vec!["*".to_string()]);
        assert!(i.fires_on_startup, "wildcard `*` must flag startup autorun");
        assert!(i.has_startup_autorun());
    }

    #[test]
    fn on_startup_finished_also_flags_startup_autorun() {
        let body = build_vsix(
            r#"{
                "name": "x", "publisher": "y", "version": "1.0.0",
                "activationEvents": ["onStartupFinished"]
            }"#,
        );
        let i = inspect_vsix(&body).unwrap();
        assert!(i.fires_on_startup);
    }

    #[test]
    fn lazy_activation_events_do_not_flag_startup_autorun() {
        // `onCommand`, `onLanguage`, `workspaceContains`, etc. are
        // user/file-triggered — they don't run code until the user
        // does something specific. These must NOT trip the block
        // signal.
        let body = build_vsix(
            r#"{
                "name": "x", "publisher": "y", "version": "1.0.0",
                "activationEvents": [
                  "onCommand:foo.bar",
                  "onLanguage:rust",
                  "workspaceContains:**/Cargo.toml"
                ]
            }"#,
        );
        let i = inspect_vsix(&body).unwrap();
        assert!(!i.fires_on_startup);
        assert_eq!(i.activation_events.len(), 3);
    }

    #[test]
    fn missing_activation_events_field_is_safe() {
        // Modern VSCode extensions can omit `activationEvents`
        // entirely (the `contributes` keys imply lazy activation).
        // Inspector must treat absence as "no startup autorun".
        let body = build_vsix(r#"{ "name": "x", "publisher": "y", "version": "1.0.0" }"#);
        let i = inspect_vsix(&body).unwrap();
        assert!(!i.fires_on_startup);
        assert!(i.activation_events.is_empty());
    }

    #[test]
    fn missing_manifest_yields_default_inspection_not_error() {
        // A zip that's parseable but doesn't contain `extension/
        // package.json` returns a default Inspection. Some
        // hand-crafted .vsix variants legitimately omit fields;
        // we don't want to false-positive on weird-but-valid.
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            zw.start_file("misc.txt", SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"hi").unwrap();
            zw.finish().unwrap();
        }
        let i = inspect_vsix(&buf).unwrap();
        assert_eq!(i, VsixInspection::default());
    }

    #[test]
    fn malformed_manifest_json_yields_default_inspection() {
        let body = build_vsix("{not json");
        let i = inspect_vsix(&body).unwrap();
        assert_eq!(i, VsixInspection::default());
    }

    #[test]
    fn non_zip_input_returns_err_not_zip() {
        let body = b"this is not a zip file";
        let err = inspect_vsix(body).unwrap_err();
        assert!(matches!(err, VsixInspectError::NotZip(_)), "got {err:?}");
    }

    #[test]
    fn oversized_body_is_rejected_before_walking() {
        // The check is a length comparison — we can use a Vec of
        // any byte content past the cap, no need for it to be
        // valid zip data.
        let body = vec![0u8; MAX_VSIX_BYTES + 1];
        let err = inspect_vsix(&body).unwrap_err();
        assert!(
            matches!(err, VsixInspectError::TooLarge { .. }),
            "got {err:?}"
        );
    }
}
