//! Editor-extension directory tamper detection — the workspace-
//! snapshot counterpart for `~/.vscode/extensions/` and friends.
//!
//! Why a separate module: [`crate::tamper`] is workspace-rooted (one
//! root path → one snapshot). An "editor extension audit" naturally
//! spans several disjoint roots — the user's VS Code, Cursor, and
//! Windsurf extension directories, plus per-editor `User/
//! globalStorage/` trees — and we want them in one diffable
//! artefact so a sideloaded extension shows up regardless of which
//! editor it landed in. We rebuild a [`tamper::Snapshot`] from the
//! merged walk so all the existing diff / IOC-scan / JSON-log
//! infrastructure works unchanged downstream.
//!
//! Detection-only by design, exactly like [`crate::tamper`]: this
//! flags drift, it doesn't roll back. Pairs naturally with the
//! `file.deny` eBPF tripwire on the same paths (Roadmap entry #24)
//! so a runtime write into a snapshotted root is visible from both
//! the post-run diff and the live audit log.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::{
    iocs,
    tamper::{Diff, Options, Snapshot, diff},
};

/// One known editor-extension root we walk. The `label` is what gets
/// prefixed onto each file's relative path in the merged snapshot so
/// two editors that ship the same extension id don't collide
/// (`vscode/extensions/foo.bar-1.0.0/package.json` vs
/// `cursor/extensions/foo.bar-1.0.0/package.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorRoot {
    pub label: String,
    pub path: PathBuf,
}

/// Discover the editor extension roots that exist on the current
/// host. Returns only roots whose path is a directory at call time —
/// a user who doesn't have Cursor installed shouldn't see an empty
/// `cursor/` namespace polluting their diff. The mapping is
/// intentionally `$HOME`-based and platform-aware; passing a
/// pre-built `home` lets tests cover macOS / Linux / Windows shapes
/// without touching the real `$HOME`.
pub fn default_roots(home: &Path) -> Vec<EditorRoot> {
    let candidates: &[(&str, &[&str])] = &[
        // VS Code (official + Code-OSS / VSCodium share this path).
        ("vscode-extensions", &[".vscode", "extensions"]),
        // VS Code Insiders is a separate install root.
        (
            "vscode-insiders-extensions",
            &[".vscode-insiders", "extensions"],
        ),
        // Cursor — fork of VS Code, identical layout.
        ("cursor-extensions", &[".cursor", "extensions"]),
        // Windsurf — Codeium's fork.
        ("windsurf-extensions", &[".windsurf", "extensions"]),
        // VS Code user-installed scripts / global storage — where
        // a malicious extension would persist its payload across
        // reinstalls. macOS / Linux / Windows layouts differ;
        // [`platform_user_globalstorage`] resolves the right one.
    ];
    let mut out: Vec<EditorRoot> = candidates
        .iter()
        .map(|(label, segs)| {
            let mut p = home.to_path_buf();
            for s in *segs {
                p.push(s);
            }
            EditorRoot {
                label: (*label).to_string(),
                path: p,
            }
        })
        .collect();
    if let Some(gs) = platform_user_globalstorage(home) {
        out.push(EditorRoot {
            label: "vscode-user-globalstorage".into(),
            path: gs,
        });
    }
    out.retain(|r| r.path.is_dir());
    out
}

/// Locate the platform-appropriate `globalStorage` dir for VS Code.
/// On Linux that's `$XDG_CONFIG_HOME/Code/User/globalStorage` (fall
/// back to `~/.config/Code/User/globalStorage`); on macOS
/// `~/Library/Application Support/Code/User/globalStorage`;
/// on Windows `%APPDATA%\Code\User\globalStorage`. Returns `None`
/// when the platform is unrecognised so a hypothetical BSD build
/// just skips that root.
fn platform_user_globalstorage(home: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut p = home.to_path_buf();
        for s in [
            "Library",
            "Application Support",
            "Code",
            "User",
            "globalStorage",
        ] {
            p.push(s);
        }
        Some(p)
    }
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        Some(base.join("Code").join("User").join("globalStorage"))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        std::env::var_os("APPDATA").map(|s| {
            PathBuf::from(s)
                .join("Code")
                .join("User")
                .join("globalStorage")
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = home;
        None
    }
}

/// Walk every root in `roots` and merge the results into one
/// [`Snapshot`]. Paths are prefixed by `<label>/<rel>` so two roots
/// that happen to share a relative shape don't collide. The
/// snapshot's `root` is set to a synthetic path (`<editor-extensions>`)
/// since no single filesystem root covers the merged set; callers
/// that diff against this snapshot only consume `files` and
/// `unreadable`, both of which use the prefixed keys.
pub fn snapshot_roots(roots: &[EditorRoot], opts: &Options) -> Result<Snapshot> {
    let mut merged = Snapshot {
        root: PathBuf::from("<editor-extensions>"),
        files: BTreeMap::new(),
        unreadable: Vec::new(),
    };
    for root in roots {
        if !root.path.is_dir() {
            // A root that exists in default_roots() but disappeared
            // between discovery and the walk — treat as empty, no
            // error. Defence shouldn't fail on legitimate non-state.
            continue;
        }
        let one = Snapshot::take(&root.path, opts)?;
        let prefix = PathBuf::from(&root.label);
        for (rel, entry) in one.files {
            merged.files.insert(prefix.join(&rel), entry);
        }
        for rel in one.unreadable {
            merged.unreadable.push(prefix.join(&rel));
        }
    }
    Ok(merged)
}

/// Supervisor-facing baseline: discover every editor-extension root
/// under `home`, snapshot them, and report which roots were actually
/// present at discovery time. Empty when no editor is installed —
/// the supervisor MUST still run [`drift_extensions`] post-run, since
/// an attacker can create `~/.vscode/extensions/` during the
/// supervised step (sideload pattern).
pub fn baseline_extensions(home: &Path) -> Result<(Snapshot, Vec<EditorRoot>)> {
    let roots = default_roots(home);
    let snap = snapshot_roots(&roots, &Options::default())?;
    Ok((snap, roots))
}

/// Supervisor-facing post-run: re-discover roots (catches roots that
/// appeared during the supervised step), snapshot, diff against
/// `baseline`, and IOC-scan only the added/modified paths against
/// the bundled catalog. Pre-existing-compromise detection lives in
/// [`scan_existing_extensions`] and runs separately — see plan slice.
pub fn drift_extensions(home: &Path, baseline: &Snapshot) -> Result<ExtensionDrift> {
    let roots = default_roots(home);
    let current = snapshot_roots(&roots, &Options::default())?;
    let d = diff(baseline, &current);
    let scan_paths: Vec<&Path> = d
        .added
        .iter()
        .map(|p| p.as_path())
        .chain(d.modified.iter().map(|m| m.path.as_path()))
        .collect();
    // Snapshot paths are root-label-prefixed (e.g.
    // `vscode-extensions/foo.bar-1.0.0/extension/tasks.json`); pass
    // each root's *parent* — `$HOME` — as the content-read root and
    // re-materialise the absolute path per scan. Simpler: scan each
    // root individually with its own prefix.
    let iocs = scan_drift_in_roots(&roots, &scan_paths);
    Ok(ExtensionDrift {
        added: d.added.clone(),
        modified_paths: d.modified.iter().map(|m| m.path.clone()).collect(),
        removed: d.removed.clone(),
        diff: d,
        iocs,
    })
}

/// Pre-run sweep: snapshot every discovered root and IOC-scan every
/// file in it (path rules + content rules). The result tells the
/// caller "the host was already poisoned before sakimori attached"
/// — a separate signal from drift, with the same High-severity
/// unconditional-fail contract.
pub fn scan_existing_extensions(home: &Path) -> Result<iocs::Report> {
    let roots = default_roots(home);
    let mut findings: Vec<iocs::Finding> = Vec::new();
    for root in &roots {
        if !root.path.is_dir() {
            continue;
        }
        let snap = Snapshot::take(&root.path, &Options::default())?;
        // Scan the relative paths but use root.path as the content-
        // read root, then rewrite each finding's path to be
        // label-prefixed so the report distinguishes "this hit was
        // under cursor-extensions" from "this hit was under
        // vscode-extensions".
        let rel: Vec<&Path> = snap.files.keys().map(|p| p.as_path()).collect();
        let prefix = PathBuf::from(&root.label);
        for mut f in iocs::scan_paths_in_root(&root.path, rel.iter().copied()) {
            f.path = prefix.join(&f.path);
            findings.push(f);
        }
    }
    Ok(iocs::Report::new(findings))
}

/// Drift IOC scan helper: paths are already root-label-prefixed (per
/// [`snapshot_roots`]). Match each path back to its owning root so
/// the content-rule reader opens the right absolute file.
fn scan_drift_in_roots(roots: &[EditorRoot], paths: &[&Path]) -> iocs::Report {
    let mut findings: Vec<iocs::Finding> = Vec::new();
    for root in roots {
        let prefix = PathBuf::from(&root.label);
        // Filter paths owned by this root, strip the prefix so the
        // scanner can resolve the absolute path against root.path.
        let mine: Vec<PathBuf> = paths
            .iter()
            .filter_map(|p| p.strip_prefix(&prefix).ok().map(PathBuf::from))
            .collect();
        if mine.is_empty() {
            continue;
        }
        let mine_refs: Vec<&Path> = mine.iter().map(|p| p.as_path()).collect();
        for mut f in iocs::scan_paths_in_root(&root.path, mine_refs.iter().copied()) {
            f.path = prefix.join(&f.path);
            findings.push(f);
        }
    }
    iocs::Report::new(findings)
}

/// What the supervisor embeds in the report for the drift half.
#[derive(Debug, Clone)]
pub struct ExtensionDrift {
    /// Full structural diff. Same shape `workspace_drift` already
    /// serialises so reviewers can re-use existing tooling.
    pub diff: Diff,
    /// Convenience accessor — paths added vs. baseline.
    pub added: Vec<PathBuf>,
    /// Convenience accessor — paths whose content/metadata changed.
    pub modified_paths: Vec<PathBuf>,
    /// Convenience accessor — paths present in baseline, gone now.
    pub removed: Vec<PathBuf>,
    /// IOC findings on `added + modified_paths` only.
    pub iocs: iocs::Report,
}

impl ExtensionDrift {
    pub fn is_clean(&self) -> bool {
        self.diff.is_clean() && self.iocs.is_clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn tmp_home(tag: &str) -> PathBuf {
        let id = format!(
            "{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let p = std::env::temp_dir().join(format!("sakimori-edext-{tag}-{id}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn default_roots_only_returns_existing_dirs() {
        let home = tmp_home("default-roots-existing");
        // Create only the vscode extensions dir; cursor / windsurf
        // / insiders / globalStorage should be filtered out.
        fs::create_dir_all(home.join(".vscode").join("extensions")).unwrap();
        let roots = default_roots(&home);
        let labels: Vec<&str> = roots.iter().map(|r| r.label.as_str()).collect();
        assert!(
            labels.contains(&"vscode-extensions"),
            "want vscode-extensions in {labels:?}"
        );
        assert!(
            !labels.contains(&"cursor-extensions"),
            "cursor dir doesn't exist; must be filtered out: {labels:?}"
        );
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn snapshot_roots_prefixes_each_files_relative_path_with_label() {
        let home = tmp_home("snapshot-roots-prefix");
        let vscode_ext = home.join(".vscode").join("extensions");
        let cursor_ext = home.join(".cursor").join("extensions");
        fs::create_dir_all(vscode_ext.join("a.b-1.0.0")).unwrap();
        fs::create_dir_all(cursor_ext.join("a.b-1.0.0")).unwrap();
        fs::write(vscode_ext.join("a.b-1.0.0").join("package.json"), b"{}").unwrap();
        fs::write(cursor_ext.join("a.b-1.0.0").join("package.json"), b"{}").unwrap();

        let roots = vec![
            EditorRoot {
                label: "vscode-extensions".into(),
                path: vscode_ext.clone(),
            },
            EditorRoot {
                label: "cursor-extensions".into(),
                path: cursor_ext.clone(),
            },
        ];
        let snap = snapshot_roots(&roots, &Options::default()).unwrap();
        let keys: Vec<String> = snap
            .files
            .keys()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        // Both roots' identical relative paths must coexist under
        // distinct prefixes — the whole point of the label.
        assert!(
            keys.iter()
                .any(|k| k == "vscode-extensions/a.b-1.0.0/package.json"),
            "got: {keys:?}"
        );
        assert!(
            keys.iter()
                .any(|k| k == "cursor-extensions/a.b-1.0.0/package.json"),
            "got: {keys:?}"
        );
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn baseline_extensions_empty_home_returns_empty_snapshot() {
        let home = tmp_home("baseline-empty");
        let (snap, roots) = baseline_extensions(&home).unwrap();
        assert!(snap.files.is_empty());
        assert!(roots.is_empty());
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn drift_extensions_picks_up_root_created_after_baseline() {
        // The whole point of post-run re-discovery: an attacker who
        // creates `~/.vscode/extensions/` during the supervised step
        // must show up in drift even though baseline saw nothing.
        let home = tmp_home("drift-new-root");
        let (baseline, _) = baseline_extensions(&home).unwrap();
        // Now create the root + a file under it.
        let vscode_ext = home.join(".vscode").join("extensions").join("a.b-1.0.0");
        fs::create_dir_all(&vscode_ext).unwrap();
        fs::write(vscode_ext.join("package.json"), b"{}").unwrap();
        let drift = drift_extensions(&home, &baseline).unwrap();
        assert!(
            drift
                .added
                .iter()
                .any(|p| p.to_string_lossy().contains("a.b-1.0.0/package.json")),
            "expected the post-baseline-created file to appear in drift.added; got: {:?}",
            drift.added,
        );
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn drift_extensions_only_scans_added_or_modified_for_iocs() {
        // A `tasks.json` already present in baseline must NOT
        // re-trip the IOC scanner during drift — the pre-existing
        // sweep is the right surface for that. Avoids double-counting
        // the same finding across both buckets.
        let home = tmp_home("drift-iocs-add-only");
        let vscode_ext = home
            .join(".vscode")
            .join("extensions")
            .join("evil.ext-1.0.0")
            .join(".vscode");
        fs::create_dir_all(&vscode_ext).unwrap();
        let tasks_path = vscode_ext.join("tasks.json");
        fs::write(
            &tasks_path,
            br#"{"version":"2.0.0","tasks":[{"label":"x","type":"shell","command":"echo","runOn": "folderOpen"}]}"#,
        )
        .unwrap();

        let (baseline, _) = baseline_extensions(&home).unwrap();
        // No further changes → drift is empty, iocs is empty.
        let drift = drift_extensions(&home, &baseline).unwrap();
        assert!(
            drift.diff.is_clean(),
            "diff should be clean: {:?}",
            drift.diff
        );
        assert!(
            drift.iocs.is_clean(),
            "iocs should be clean: {:?}",
            drift.iocs
        );
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn drift_extensions_iocs_fires_on_newly_added_tasks_json() {
        let home = tmp_home("drift-iocs-fires");
        // Baseline is taken with an empty extensions dir; the
        // attacker drops a poisoned tasks.json under a new extension
        // folder during the run.
        fs::create_dir_all(home.join(".vscode").join("extensions")).unwrap();
        let (baseline, _) = baseline_extensions(&home).unwrap();
        let vscode_ext = home
            .join(".vscode")
            .join("extensions")
            .join("evil.ext-1.0.0")
            .join(".vscode");
        fs::create_dir_all(&vscode_ext).unwrap();
        fs::write(
            vscode_ext.join("tasks.json"),
            br#"{"version":"2.0.0","tasks":[{"label":"x","type":"shell","command":"echo","runOn": "folderOpen"}]}"#,
        )
        .unwrap();
        let drift = drift_extensions(&home, &baseline).unwrap();
        assert!(
            drift.iocs.has_high(),
            "expected High-severity IOC hit on tasks.json folderOpen; got: {:?}",
            drift.iocs,
        );
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn scan_existing_extensions_flags_pre_existing_tasks_json() {
        // The "you were already poisoned before sakimori attached"
        // signal. Catalog hit must be High-severity and path must be
        // label-prefixed so the report can tell which editor's
        // tree the hit came from.
        let home = tmp_home("scan-existing");
        let vscode_ext = home
            .join(".vscode")
            .join("extensions")
            .join("evil.ext-1.0.0")
            .join(".vscode");
        fs::create_dir_all(&vscode_ext).unwrap();
        fs::write(
            vscode_ext.join("tasks.json"),
            br#"{"version":"2.0.0","tasks":[{"label":"x","type":"shell","command":"echo","runOn": "folderOpen"}]}"#,
        )
        .unwrap();
        let rep = scan_existing_extensions(&home).unwrap();
        assert!(rep.has_high(), "expected High IOC at baseline: {:?}", rep);
        assert!(
            rep.findings
                .iter()
                .any(|f| f.path.to_string_lossy().starts_with("vscode-extensions/")),
            "finding must be prefixed by its root label: {:?}",
            rep.findings,
        );
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn scan_existing_extensions_empty_home_is_clean() {
        let home = tmp_home("scan-existing-empty");
        let rep = scan_existing_extensions(&home).unwrap();
        assert!(rep.is_clean());
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn snapshot_roots_skips_missing_root_without_erroring() {
        // A root listed in `roots` but absent from disk should not
        // be fatal — devs add / remove editors, and discovery may
        // race with the walk. Defence shouldn't invent failures.
        let home = tmp_home("snapshot-roots-missing");
        let absent = home.join(".cursor").join("extensions");
        let roots = vec![EditorRoot {
            label: "cursor-extensions".into(),
            path: absent,
        }];
        let snap = snapshot_roots(&roots, &Options::default()).unwrap();
        assert!(snap.files.is_empty());
        fs::remove_dir_all(home).ok();
    }
}
