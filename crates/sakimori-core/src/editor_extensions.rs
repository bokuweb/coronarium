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

use crate::tamper::{Options, Snapshot};

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
