//! `coronarium-win` — Windows audit MVP.
//!
//! Uses the NT Kernel Logger ETW session (`ferrisetw` wraps the Win32 ETW
//! API) to count Process / TcpIp / FileIo events generated during a
//! supervised child command's lifetime, then writes a JSON summary.
//!
//! Requires Administrator — which is what `windows-latest` GitHub hosted
//! runners are by default. On non-elevated shells the kernel trace start
//! call fails with ERROR_ACCESS_DENIED.
//!
//! This is deliberately minimal: prove ETW works at all on the runner,
//! then grow the schema / field parsing / block-mode integration.

#![cfg(windows)]

use std::{
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use ferrisetw::{
    EventRecord,
    provider::Provider,
    schema_locator::SchemaLocator,
    trace::UserTrace,
};
use serde::Serialize;

// Modern public ETW providers (Windows 8+). Unlike the legacy "NT Kernel
// Logger" which is a Windows-wide singleton that the OS itself holds,
// these can be consumed by any number of named UserTrace sessions.
const PROVIDER_KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
const PROVIDER_KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const PROVIDER_KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

static N_PROCESS: AtomicU64 = AtomicU64::new(0);
static N_TCPIP: AtomicU64 = AtomicU64::new(0);
static N_FILEIO: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct Summary {
    process_events: u64,
    tcpip_events: u64,
    fileio_events: u64,
    child_exit: Option<i32>,
    notes: &'static str,
}

fn main() -> Result<()> {
    // Very small hand-rolled arg parsing so we don't pull clap in yet.
    //   coronarium-win [--json <path>] <cmd> [args...]
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut json_out: Option<String> = None;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--json" => {
                i += 1;
                json_out = Some(raw.get(i).cloned().unwrap_or_default());
                i += 1;
            }
            "--" => {
                i += 1;
                break;
            }
            _ => break,
        }
    }
    let argv: Vec<String> = raw[i..].to_vec();
    if argv.is_empty() {
        anyhow::bail!(
            "usage: coronarium-win [--json <path>] <cmd> [args...]\n\
             e.g.  coronarium-win --json out.json cmd /C dir"
        );
    }

    let process_cb = |_r: &EventRecord, _s: &SchemaLocator| {
        N_PROCESS.fetch_add(1, Ordering::Relaxed);
    };
    let tcpip_cb = |_r: &EventRecord, _s: &SchemaLocator| {
        N_TCPIP.fetch_add(1, Ordering::Relaxed);
    };
    let fileio_cb = |_r: &EventRecord, _s: &SchemaLocator| {
        N_FILEIO.fetch_add(1, Ordering::Relaxed);
    };

    // Modern public providers (by GUID) instead of the legacy NT Kernel
    // Logger. The legacy session is a Windows-wide singleton held by OS
    // services (perf counters, autologger, Defender), so we can't get a
    // clean start on it. These public providers expose the same events
    // via ETW's user-mode trace sessions, which can be uniquely named.
    let process_provider = Provider::by_guid(PROVIDER_KERNEL_PROCESS)
        .add_callback(process_cb)
        .build();
    let tcpip_provider = Provider::by_guid(PROVIDER_KERNEL_NETWORK)
        .add_callback(tcpip_cb)
        .build();
    let fileio_provider = Provider::by_guid(PROVIDER_KERNEL_FILE)
        .add_callback(fileio_cb)
        .build();

    // Process-unique session name — no singleton conflicts even if runs
    // overlap or a previous one crashed without cleanup.
    let session_name = format!("coronarium-{}", std::process::id());
    let _trace = UserTrace::new()
        .named(session_name.clone())
        .enable(process_provider)
        .enable(tcpip_provider)
        .enable(fileio_provider)
        .start_and_process()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to start ETW session '{session_name}': {e:?} \
                 (requires Administrator; hosted runners are elevated by default)"
            )
        })?;

    // Give the session a moment to warm up so we don't race the first
    // child events.
    thread::sleep(Duration::from_millis(150));

    eprintln!("coronarium-win: tracing {:?}", argv);
    let status = Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .with_context(|| format!("spawning {}", argv[0]))?;

    // Drain tail events.
    thread::sleep(Duration::from_millis(400));

    let summary = Summary {
        process_events: N_PROCESS.load(Ordering::Relaxed),
        tcpip_events: N_TCPIP.load(Ordering::Relaxed),
        fileio_events: N_FILEIO.load(Ordering::Relaxed),
        child_exit: status.code(),
        notes:
            "audit-only MVP. counts only — field-level parsing / JSON events / HTML report come next.",
    };
    let serialized = serde_json::to_string_pretty(&summary)?;
    match json_out {
        Some(path) => {
            std::fs::write(&path, &serialized)
                .with_context(|| format!("writing {path}"))?;
            eprintln!("coronarium-win: summary written to {path}");
        }
        None => {
            // No --json given: print to *stderr* so child stdout stays clean.
            eprintln!("{serialized}");
        }
    }

    std::process::exit(status.code().unwrap_or(1));
}
