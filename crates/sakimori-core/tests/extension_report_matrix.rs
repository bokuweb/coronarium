//! Matrix integration test for the editor-extension report surface.
//!
//! Mirrors the per-scenario / per-mode contract Codex required in the
//! plan review: each row drives a synthetic `$HOME` through
//! `editor_extensions::{baseline_extensions, scan_existing_extensions,
//! drift_extensions}` and then `report::write` to assert that the JSON
//! log carries the expected sibling top-level keys
//! (`extension_drift`, `extension_iocs`, `extension_iocs_baseline`)
//! and that high-severity catalog hits show up where they should.
//!
//! Full run/daemon integration is gated on eBPF + Linux, so this
//! covers the wiring at the report layer — the supervisor unwraps
//! these into the same `ReportArgs::extension` shape we're testing
//! directly.

use std::{fs, path::PathBuf};

use sakimori_core::{
    editor_extensions::{baseline_extensions, drift_extensions, scan_existing_extensions},
    policy::Policy,
    report::{ExtensionSection, ReportArgs, write},
    stats::Stats,
};

fn tmp_home(tag: &str) -> PathBuf {
    let id = format!(
        "{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let p = std::env::temp_dir().join(format!("sakimori-ext-matrix-{id}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn write_poisoned_tasks_json(home: &std::path::Path, ext_name: &str) {
    let dir = home
        .join(".vscode")
        .join("extensions")
        .join(ext_name)
        .join(".vscode");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("tasks.json"),
        br#"{"version":"2.0.0","tasks":[{"label":"x","type":"shell","command":"echo","runOn": "folderOpen"}]}"#,
    )
    .unwrap();
}

fn write_report_and_parse(
    home: &std::path::Path,
    section: ExtensionSection<'_>,
) -> serde_json::Value {
    let log_path = home.join("report.jsonl");
    let policy = Policy::permissive_audit();
    let stats = Stats::default();
    let args = ReportArgs {
        log: log_path.to_str().unwrap(),
        summary: None,
        html: None,
        command: "test",
        mode: sakimori_core::policy::Mode::Audit,
        policy: &policy,
        workspace_drift: None,
        workspace_iocs: None,
        extension: Some(section),
    };
    write(&args, &stats).expect("report::write");
    let raw = fs::read_to_string(&log_path).expect("read log");
    serde_json::from_str(&raw).expect("parse jsonl")
}

#[test]
fn matrix_clean_baseline_clean_run_no_extension_keys_in_json() {
    // No editors installed, no drift → none of the three sibling
    // keys should appear; they're suppressed when empty/clean per
    // the same convention as workspace_drift.
    let home = tmp_home("matrix-clean");
    let (baseline, _) = baseline_extensions(&home).unwrap();
    let iocs_baseline = scan_existing_extensions(&home).unwrap();
    let drift = drift_extensions(&home, &baseline).unwrap();

    let section = ExtensionSection {
        drift: Some(&drift.diff),
        iocs_drift: Some(&drift.iocs),
        iocs_baseline: Some(&iocs_baseline),
    };
    let json = write_report_and_parse(&home, section);
    assert!(json.get("extension_drift").is_none(), "{json}");
    assert!(json.get("extension_iocs").is_none(), "{json}");
    assert!(json.get("extension_iocs_baseline").is_none(), "{json}");
    fs::remove_dir_all(home).ok();
}

#[test]
fn matrix_pre_existing_high_ioc_surfaces_in_baseline_key() {
    let home = tmp_home("matrix-pre-existing-high");
    // Plant a poisoned tasks.json BEFORE the baseline runs.
    write_poisoned_tasks_json(&home, "evil.ext-1.0.0");
    let (baseline, _) = baseline_extensions(&home).unwrap();
    let iocs_baseline = scan_existing_extensions(&home).unwrap();
    let drift = drift_extensions(&home, &baseline).unwrap();

    assert!(
        iocs_baseline.has_high(),
        "test setup: baseline IOC should be High"
    );
    assert!(
        drift.diff.is_clean() && drift.iocs.is_clean(),
        "no drift between identical snapshots"
    );

    let section = ExtensionSection {
        drift: Some(&drift.diff),
        iocs_drift: Some(&drift.iocs),
        iocs_baseline: Some(&iocs_baseline),
    };
    let json = write_report_and_parse(&home, section);
    assert!(
        json.get("extension_iocs_baseline").is_some(),
        "pre-existing High IOC must surface in extension_iocs_baseline: {json}"
    );
    assert!(json.get("extension_drift").is_none(), "{json}");
    assert!(
        json.get("extension_iocs").is_none(),
        "drift-time bucket stays empty when nothing dropped during the run: {json}"
    );
    fs::remove_dir_all(home).ok();
}

#[test]
fn matrix_drift_high_ioc_surfaces_in_drift_key_not_baseline() {
    // Clean baseline; an attacker drops a poisoned tasks.json mid-run.
    let home = tmp_home("matrix-drift-high");
    fs::create_dir_all(home.join(".vscode").join("extensions")).unwrap();
    let (baseline, _) = baseline_extensions(&home).unwrap();
    let iocs_baseline = scan_existing_extensions(&home).unwrap();
    assert!(iocs_baseline.is_clean(), "clean baseline expected");
    write_poisoned_tasks_json(&home, "evil.ext-1.0.0");
    let drift = drift_extensions(&home, &baseline).unwrap();

    assert!(drift.iocs.has_high(), "drift-time High IOC expected");

    let section = ExtensionSection {
        drift: Some(&drift.diff),
        iocs_drift: Some(&drift.iocs),
        iocs_baseline: Some(&iocs_baseline),
    };
    let json = write_report_and_parse(&home, section);
    assert!(
        json.get("extension_iocs").is_some(),
        "drift-time IOC must surface in extension_iocs: {json}"
    );
    assert!(
        json.get("extension_drift").is_some(),
        "structural drift accompanies the IOC hit: {json}"
    );
    assert!(
        json.get("extension_iocs_baseline").is_none(),
        "baseline bucket stays empty when host wasn't pre-poisoned: {json}"
    );
    fs::remove_dir_all(home).ok();
}

#[test]
fn matrix_structural_drift_without_ioc_only_emits_drift_key() {
    // Add a benign file to a freshly-created extension dir — drift
    // fires but no catalog rule matches.
    let home = tmp_home("matrix-drift-benign");
    fs::create_dir_all(home.join(".vscode").join("extensions")).unwrap();
    let (baseline, _) = baseline_extensions(&home).unwrap();
    let iocs_baseline = scan_existing_extensions(&home).unwrap();
    let new_dir = home
        .join(".vscode")
        .join("extensions")
        .join("benign.ext-1.0.0");
    fs::create_dir_all(&new_dir).unwrap();
    fs::write(new_dir.join("README.md"), b"hi").unwrap();
    let drift = drift_extensions(&home, &baseline).unwrap();

    assert!(!drift.diff.is_clean(), "drift expected");
    assert!(drift.iocs.is_clean(), "no IOC: {:?}", drift.iocs);

    let section = ExtensionSection {
        drift: Some(&drift.diff),
        iocs_drift: Some(&drift.iocs),
        iocs_baseline: Some(&iocs_baseline),
    };
    let json = write_report_and_parse(&home, section);
    assert!(json.get("extension_drift").is_some(), "{json}");
    assert!(json.get("extension_iocs").is_none(), "{json}");
    assert!(json.get("extension_iocs_baseline").is_none(), "{json}");
    fs::remove_dir_all(home).ok();
}
