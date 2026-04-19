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
    provider::{Provider, kernel_providers},
    schema_locator::SchemaLocator,
    trace::KernelTrace,
};
use serde::Serialize;

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
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        anyhow::bail!(
            "usage: coronarium-win <cmd> [args...]\n\
             e.g.  coronarium-win cmd /C dir"
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

    let process_provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(process_cb)
        .build();
    let tcpip_provider = Provider::kernel(&kernel_providers::TCP_IP_PROVIDER)
        .add_callback(tcpip_cb)
        .build();
    let fileio_provider = Provider::kernel(&kernel_providers::FILE_IO_PROVIDER)
        .add_callback(fileio_cb)
        .build();

    // `start_and_process` opens the NT Kernel Logger session and spawns
    // the ETW processing thread. Drop (or .stop()) ends the trace.
    // ferrisetw's TraceError doesn't impl std::error::Error, so convert
    // manually instead of using `.context`.
    let _trace = KernelTrace::new()
        .named("coronarium-win".to_string())
        .enable(process_provider)
        .enable(tcpip_provider)
        .enable(fileio_provider)
        .start_and_process()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to start NT Kernel Logger ETW session: {e:?} \
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
    println!("{}", serde_json::to_string_pretty(&summary)?);

    std::process::exit(status.code().unwrap_or(1));
}
