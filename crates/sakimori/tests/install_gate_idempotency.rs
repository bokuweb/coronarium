//! install-gate end-to-end via the **real binary**. Exercises the
//! CLI dispatcher → `install_block` / `strip_block` → on-disk rc
//! file mutation chain.
//!
//! Inline tests in `src/install_gate.rs::tests` cover the pure
//! string transforms (`install_block`, `strip_block`,
//! `render_shellenv`) in isolation. This file adds the missing
//! tier: the actual binary processes `--rc <PATH>` and writes the
//! file. A regression that broke argv plumbing (renamed `--rc`,
//! swapped install / uninstall handlers, lost the sentinel
//! markers in the dispatcher) would pass every inline test and
//! silently mis-mutate the user's `.zshrc`.
//!
//! Uses the standard `CARGO_BIN_EXE_<name>` env var that Cargo
//! sets for `tests/`-tier integration tests, so the binary doesn't
//! need to be on `$PATH`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn sakimori_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sakimori"))
}

fn tmp_rc(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "sakimori-install-gate-e2e-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(".testshellrc")
}

fn run_install_gate(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(sakimori_bin())
        .arg("install-gate")
        .args(args)
        .output()
        .expect("spawn sakimori install-gate");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

const MARKER_BEGIN: &str = "# >>> sakimori install-gate >>>";
const MARKER_END: &str = "# <<< sakimori install-gate <<<";

fn count_blocks(contents: &str) -> usize {
    contents.matches(MARKER_BEGIN).count()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn install_then_install_again_is_idempotent_byte_for_byte() {
    let rc = tmp_rc("install-idem");
    std::fs::write(
        &rc,
        b"# my .zshrc\nalias gs='git status'\nexport EDITOR=vim\n",
    )
    .unwrap();

    let (code1, _, _) =
        run_install_gate(&["install", "--rc", rc.to_str().unwrap(), "--shell", "zsh"]);
    assert_eq!(code1, 0, "first install must succeed");
    let after_first = std::fs::read_to_string(&rc).unwrap();
    assert_eq!(
        count_blocks(&after_first),
        1,
        "first install must insert exactly one block"
    );
    assert!(after_first.contains(MARKER_BEGIN));
    assert!(after_first.contains(MARKER_END));
    assert!(
        after_first.contains("alias gs='git status'"),
        "existing rc lines must survive"
    );

    let (code2, stdout2, _) =
        run_install_gate(&["install", "--rc", rc.to_str().unwrap(), "--shell", "zsh"]);
    assert_eq!(code2, 0, "second install must also succeed");
    let after_second = std::fs::read_to_string(&rc).unwrap();
    assert_eq!(
        after_first, after_second,
        "second install must be byte-for-byte identical to first (idempotent)",
    );
    assert!(
        stdout2.contains("already present"),
        "second invocation should report the no-op, got: {stdout2}"
    );

    cleanup(&rc);
}

#[test]
fn uninstall_strips_block_and_restores_original_contents() {
    let rc = tmp_rc("uninstall-strip");
    let original = "# my .bashrc\nPATH=$PATH:/opt/local/bin\n";
    std::fs::write(&rc, original).unwrap();

    let (code, _, _) =
        run_install_gate(&["install", "--rc", rc.to_str().unwrap(), "--shell", "bash"]);
    assert_eq!(code, 0);
    assert!(std::fs::read_to_string(&rc).unwrap().contains(MARKER_BEGIN));

    let (code, _, _) =
        run_install_gate(&["uninstall", "--rc", rc.to_str().unwrap(), "--shell", "bash"]);
    assert_eq!(code, 0);
    let after = std::fs::read_to_string(&rc).unwrap();
    assert!(
        !after.contains(MARKER_BEGIN),
        "uninstall must remove the sentinel block",
    );
    assert!(
        after.contains("PATH=$PATH:/opt/local/bin"),
        "uninstall must leave user content intact",
    );

    cleanup(&rc);
}

#[test]
fn uninstall_when_no_block_present_is_noop() {
    let rc = tmp_rc("uninstall-noop");
    let original = "# nothing to see\n";
    std::fs::write(&rc, original).unwrap();

    let (code, stdout, _) =
        run_install_gate(&["uninstall", "--rc", rc.to_str().unwrap(), "--shell", "bash"]);
    assert_eq!(code, 0, "uninstall on a missing block must succeed");
    assert!(
        stdout.contains("no install-gate block found"),
        "stdout should report the missing block: {stdout}",
    );
    let after = std::fs::read_to_string(&rc).unwrap();
    assert_eq!(after, original, "rc file must be untouched on no-op");

    cleanup(&rc);
}

#[test]
fn uninstall_when_rc_does_not_exist_at_all_is_noop() {
    let rc = tmp_rc("uninstall-missing");
    // Don't create the file. Uninstall must succeed silently.
    assert!(!rc.exists(), "test precondition: rc must not exist");
    let (code, stdout, _) =
        run_install_gate(&["uninstall", "--rc", rc.to_str().unwrap(), "--shell", "bash"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("does not exist"));
    assert!(
        !rc.exists(),
        "uninstall must not create the rc file as a side effect"
    );

    cleanup(&rc);
}

#[test]
fn install_uninstall_install_cycles_back_to_one_block() {
    // Pathological pattern that catches "uninstall accidentally
    // removes the marker substring from a regex perspective but
    // leaves a stray line behind" failure modes.
    let rc = tmp_rc("cycle");
    std::fs::write(&rc, b"alpha\nbeta\n").unwrap();

    for _ in 0..3 {
        let (c1, _, _) =
            run_install_gate(&["install", "--rc", rc.to_str().unwrap(), "--shell", "zsh"]);
        assert_eq!(c1, 0);
        let mid = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(count_blocks(&mid), 1, "exactly one block mid-cycle");

        let (c2, _, _) =
            run_install_gate(&["uninstall", "--rc", rc.to_str().unwrap(), "--shell", "zsh"]);
        assert_eq!(c2, 0);
        let end = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(count_blocks(&end), 0, "zero blocks after uninstall");
        assert!(end.contains("alpha\nbeta\n"));
    }

    cleanup(&rc);
}

#[test]
fn shellenv_bash_outputs_expected_exports() {
    // No `--rc` needed; shellenv is pure stdout.
    let (code, stdout, _) =
        run_install_gate(&["shellenv", "--shell", "bash", "--listen", "127.0.0.1:9001"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("export HTTPS_PROXY='http://127.0.0.1:9001'"),
        "bash shellenv must export HTTPS_PROXY, got:\n{stdout}",
    );
    assert!(stdout.contains("export CARGO_HTTP_CAINFO="));
    assert!(stdout.contains("export NODE_EXTRA_CA_CERTS="));
    assert!(stdout.contains("export PIP_CERT="));
    assert!(stdout.contains("export REQUESTS_CA_BUNDLE="));
}

#[test]
fn shellenv_fish_uses_set_gx_syntax() {
    let (code, stdout, _) =
        run_install_gate(&["shellenv", "--shell", "fish", "--listen", "127.0.0.1:9002"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("set -gx HTTPS_PROXY 'http://127.0.0.1:9002'"),
        "fish shellenv must use `set -gx`, got:\n{stdout}",
    );
    // Bash-only syntax must NOT appear in the fish output.
    assert!(
        !stdout.contains("export HTTPS_PROXY"),
        "fish output must not contain bash-style `export`",
    );
}

fn cleanup(rc: &Path) {
    if let Some(parent) = rc.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}
