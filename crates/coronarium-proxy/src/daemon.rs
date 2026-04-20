//! Install / uninstall `coronarium proxy start` as a user-level
//! background service, so `install-gate` users don't have to
//! remember to launch the proxy manually in a spare terminal.
//!
//! Two backends:
//!
//! - **macOS** — writes a launchd plist under
//!   `~/Library/LaunchAgents/com.coronarium.proxy.plist` and runs
//!   `launchctl bootstrap gui/<uid>` on it. `launchctl bootout`
//!   reverses it.
//! - **Linux** — writes a systemd user unit under
//!   `~/.config/systemd/user/coronarium-proxy.service` and enables
//!   it via `systemctl --user enable --now`.
//!
//! Windows is intentionally not covered here: NT services need
//! elevation and a whole different lifecycle; telling the user to
//! use Task Scheduler themselves is cleaner than half-implementing.
//!
//! The rendered unit/plist text is **pure** and snapshot-testable;
//! the IO (writing files, shelling out to `launchctl`/`systemctl`) is
//! in one thin function at the end of this module.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Rendered daemon artefacts for the given invocation. Returned as
/// strings so the caller can write-and-shell-out, and so we can snapshot
/// the content in unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPlan {
    pub label: String,
    pub unit_path: PathBuf,
    pub unit_body: String,
    /// Exact shell command that activates the unit (for the install
    /// confirmation print).
    pub activate_command: String,
    /// Exact shell command that deactivates the unit (for `uninstall`).
    pub deactivate_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonBackend {
    Launchd,
    SystemdUser,
}

impl DaemonBackend {
    /// Best guess from the current OS. Callers can override.
    pub fn detect() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            return Some(DaemonBackend::Launchd);
        }
        #[cfg(target_os = "linux")]
        {
            return Some(DaemonBackend::SystemdUser);
        }
        #[allow(unreachable_code)]
        None
    }
}

/// Inputs needed to render a daemon unit. `binary_path` should be an
/// absolute path — the daemon has no shell-like `$PATH` lookup.
#[derive(Debug, Clone)]
pub struct DaemonInputs {
    pub binary_path: PathBuf,
    pub listen: SocketAddr,
    /// Same grammar as the `--min-age` CLI flag.
    pub min_age: String,
    /// `$HOME` — used to locate the user's LaunchAgents / systemd dir.
    pub home: PathBuf,
}

pub fn render(backend: DaemonBackend, inp: &DaemonInputs) -> DaemonPlan {
    match backend {
        DaemonBackend::Launchd => render_launchd(inp),
        DaemonBackend::SystemdUser => render_systemd(inp),
    }
}

const LABEL: &str = "com.coronarium.proxy";

fn render_launchd(inp: &DaemonInputs) -> DaemonPlan {
    let unit_path = inp
        .home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"));
    let log_dir = inp.home.join("Library/Logs/coronarium");
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>proxy</string>
        <string>start</string>
        <string>--listen</string>
        <string>{listen}</string>
        <string>--min-age</string>
        <string>{min_age}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{logs}/proxy.out.log</string>
    <key>StandardErrorPath</key>
    <string>{logs}/proxy.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        bin = inp.binary_path.display(),
        listen = inp.listen,
        min_age = inp.min_age,
        logs = log_dir.display(),
    );
    DaemonPlan {
        label: LABEL.into(),
        unit_path: unit_path.clone(),
        unit_body: body,
        // `bootstrap gui/<uid>` is the modern (macOS 10.10+)
        // equivalent of `launchctl load`; we keep the command in the
        // install hint so the user can re-run it manually if needed.
        activate_command: format!(
            "launchctl bootstrap gui/$(id -u) {unit}",
            unit = unit_path.display()
        ),
        deactivate_command: format!(
            "launchctl bootout gui/$(id -u)/{LABEL}; rm {unit}",
            unit = unit_path.display()
        ),
    }
}

fn render_systemd(inp: &DaemonInputs) -> DaemonPlan {
    let unit_path = inp
        .home
        .join(".config/systemd/user")
        .join("coronarium-proxy.service");
    let body = format!(
        r#"[Unit]
Description=coronarium registry proxy (minimumReleaseAge enforcement)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} proxy start --listen {listen} --min-age {min_age}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#,
        bin = inp.binary_path.display(),
        listen = inp.listen,
        min_age = inp.min_age,
    );
    DaemonPlan {
        label: "coronarium-proxy.service".into(),
        unit_path,
        unit_body: body,
        activate_command:
            "systemctl --user daemon-reload && systemctl --user enable --now coronarium-proxy.service".into(),
        deactivate_command:
            "systemctl --user disable --now coronarium-proxy.service".into(),
    }
}

/// Best-effort absolute path to the current binary. Callers should
/// pass this into [`DaemonInputs::binary_path`] so the daemon unit
/// doesn't need `$PATH`.
pub fn current_exe_canonical() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
}

/// Write the unit body to `plan.unit_path`, creating parent
/// directories as needed. Idempotent and doesn't try to run the
/// activation command — the caller does that after inspecting
/// `plan.activate_command`.
pub fn write_unit(plan: &DaemonPlan) -> std::io::Result<()> {
    if let Some(parent) = plan.unit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&plan.unit_path, &plan.unit_body)
}

pub fn remove_unit(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> DaemonInputs {
        DaemonInputs {
            binary_path: PathBuf::from("/opt/coronarium/bin/coronarium"),
            listen: "127.0.0.1:8910".parse().unwrap(),
            min_age: "7d".into(),
            home: PathBuf::from("/Users/example"),
        }
    }

    #[test]
    fn launchd_plist_has_required_keys_and_correct_label() {
        let plan = render(DaemonBackend::Launchd, &inputs());
        assert_eq!(plan.label, "com.coronarium.proxy");
        assert!(plan.unit_body.contains("<key>Label</key>"));
        assert!(
            plan.unit_body
                .contains("<string>com.coronarium.proxy</string>")
        );
        assert!(
            plan.unit_body
                .contains("<string>/opt/coronarium/bin/coronarium</string>")
        );
        assert!(plan.unit_body.contains("<string>--listen</string>"));
        assert!(plan.unit_body.contains("<string>127.0.0.1:8910</string>"));
        assert!(plan.unit_body.contains("<key>KeepAlive</key>"));
        assert!(plan.unit_body.contains("<key>RunAtLoad</key>"));
        assert!(
            plan.unit_path
                .ends_with("Library/LaunchAgents/com.coronarium.proxy.plist")
        );
        assert!(plan.activate_command.contains("launchctl bootstrap"));
        assert!(plan.deactivate_command.contains("launchctl bootout"));
    }

    #[test]
    fn systemd_unit_is_user_scoped_and_restart_on_failure() {
        let plan = render(DaemonBackend::SystemdUser, &inputs());
        assert!(plan.unit_body.starts_with("[Unit]"));
        assert!(plan.unit_body.contains("ExecStart=/opt/coronarium/bin/coronarium proxy start --listen 127.0.0.1:8910 --min-age 7d"));
        assert!(plan.unit_body.contains("Restart=on-failure"));
        // User scope — must NOT use multi-user.target.
        assert!(plan.unit_body.contains("WantedBy=default.target"));
        assert!(!plan.unit_body.contains("multi-user.target"));
        assert!(
            plan.unit_path
                .ends_with(".config/systemd/user/coronarium-proxy.service")
        );
        assert!(plan.activate_command.contains("systemctl --user"));
        assert!(plan.deactivate_command.contains("systemctl --user"));
    }

    #[test]
    fn different_listen_address_shows_up_in_unit() {
        let mut inp = inputs();
        inp.listen = "0.0.0.0:19999".parse().unwrap();
        let plist = render(DaemonBackend::Launchd, &inp);
        let unit = render(DaemonBackend::SystemdUser, &inp);
        assert!(plist.unit_body.contains("0.0.0.0:19999"));
        assert!(unit.unit_body.contains("0.0.0.0:19999"));
    }

    #[test]
    fn write_and_remove_unit_roundtrip() {
        let tmp =
            std::env::temp_dir().join(format!("coronarium-daemon-test-{}", std::process::id()));
        let mut inp = inputs();
        inp.home = tmp.clone();
        let plan = render(DaemonBackend::SystemdUser, &inp);

        write_unit(&plan).expect("write");
        assert!(plan.unit_path.exists());
        assert_eq!(
            std::fs::read_to_string(&plan.unit_path).unwrap(),
            plan.unit_body
        );

        remove_unit(&plan.unit_path).expect("remove");
        assert!(!plan.unit_path.exists());
        // Double-remove is a no-op.
        remove_unit(&plan.unit_path).expect("idempotent remove");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
