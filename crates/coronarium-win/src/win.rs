//! Windows-specific runtime.

use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use coronarium_core::{
    Event, Policy, Stats,
    matcher::{ExecMatcher, FileMatcher},
    policy::{self, Mode},
    report::ReportArgs,
};
use ferrisetw::{
    EventRecord, parser::Parser as EtwParser, provider::Provider,
    schema_locator::SchemaLocator, trace::UserTrace,
};

// Modern public ETW providers (Windows 8+). Each UserTrace session with a
// unique name can consume them concurrently — no singleton conflicts like
// the legacy NT Kernel Logger.
const PROVIDER_KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
const PROVIDER_KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const PROVIDER_KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

#[derive(Debug, Clone, ValueEnum)]
pub enum CliMode {
    Audit,
    Block,
}

#[derive(Debug, Parser)]
#[command(
    name = "coronarium-win",
    version,
    about = "Windows ETW-based audit for coronarium policies"
)]
pub struct Cli {
    /// Policy file (YAML or JSON). Optional — missing policy means a
    /// permissive audit run (log everything, deny nothing).
    #[arg(long, short = 'p', env = "CORONARIUM_POLICY")]
    pub policy: Option<PathBuf>,

    /// Override the policy's `mode`.
    #[arg(long, value_enum)]
    pub mode: Option<CliMode>,

    /// Where to write the JSON audit log. `-` for stdout.
    #[arg(long, default_value = "-")]
    pub log: String,

    /// Optional path to write a human-readable summary (suitable for
    /// `$GITHUB_STEP_SUMMARY`).
    #[arg(long, env = "GITHUB_STEP_SUMMARY")]
    pub summary: Option<PathBuf>,

    /// Optional path to write a self-contained HTML audit report.
    #[arg(long)]
    pub html: Option<PathBuf>,

    /// Command + args to execute under supervision. Prefix with `--` if
    /// your command starts with a dash.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub fn run() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    let policy = match &cli.policy {
        Some(p) => Policy::from_file(p).with_context(|| format!("loading {}", p.display()))?,
        None => Policy::permissive_audit(),
    };
    let mode = match cli.mode {
        Some(CliMode::Audit) => Mode::Audit,
        Some(CliMode::Block) => Mode::Block,
        None => policy.mode,
    };
    for w in policy.lint() {
        log::warn!("{w}");
    }

    let file_matcher = Arc::new(FileMatcher::from_policy(&policy.file));
    let exec_matcher = Arc::new(ExecMatcher::from_policy(&policy.process));
    let stats = Arc::new(Mutex::new(Stats::default()));

    // Callbacks need 'static + Send + Sync. Clone the Arcs into each closure.
    let process_cb = {
        let stats = Arc::clone(&stats);
        let exec_matcher = Arc::clone(&exec_matcher);
        move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_process_event(record, schema_locator, &stats, &exec_matcher);
        }
    };
    let network_cb = {
        let stats = Arc::clone(&stats);
        move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_network_event(record, schema_locator, &stats);
        }
    };
    let file_cb = {
        let stats = Arc::clone(&stats);
        let file_matcher = Arc::clone(&file_matcher);
        move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_file_event(record, schema_locator, &stats, &file_matcher);
        }
    };

    // `.any(0xFFFFFFFFFFFFFFFF)` = MatchAnyKeyword all-set, which enables
    // every event class the provider publishes. Without this, ETW treats
    // keyword=0 as "match nothing" for most providers and only the odd
    // event (e.g. one process start) leaks through.
    const ALL_KEYWORDS: u64 = u64::MAX;
    let process_provider = Provider::by_guid(PROVIDER_KERNEL_PROCESS)
        .any(ALL_KEYWORDS)
        .add_callback(process_cb)
        .build();
    let network_provider = Provider::by_guid(PROVIDER_KERNEL_NETWORK)
        .any(ALL_KEYWORDS)
        .add_callback(network_cb)
        .build();
    let file_provider = Provider::by_guid(PROVIDER_KERNEL_FILE)
        .any(ALL_KEYWORDS)
        .add_callback(file_cb)
        .build();

    let session_name = format!("coronarium-{}", std::process::id());
    let _trace = UserTrace::new()
        .named(session_name.clone())
        .enable(process_provider)
        .enable(network_provider)
        .enable(file_provider)
        .start_and_process()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to start ETW session '{session_name}': {e:?} \
                 (requires Administrator)"
            )
        })?;

    // Warm-up so the first child events aren't racing provider setup.
    // ETW takes ~300ms to actually start delivering events in practice.
    thread::sleep(Duration::from_millis(500));

    log::info!(
        "starting coronarium-win (mode={:?}, command={:?})",
        mode,
        cli.command
    );
    let (program, rest) = cli
        .command
        .split_first()
        .context("empty command after arg parse")?;
    let status = Command::new(program)
        .args(rest)
        .status()
        .with_context(|| format!("spawning {program}"))?;

    // Drain tail events. ETW is async; bursts take a second or so to
    // percolate through the buffering path into our callback.
    thread::sleep(Duration::from_millis(1000));

    let final_stats = stats.lock().unwrap().clone();

    let command_str = cli.command.join(" ");
    let report_args = ReportArgs {
        log: &cli.log,
        summary: cli.summary.as_deref(),
        html: cli.html.as_deref(),
        command: command_str.as_str(),
        mode,
        policy: &policy,
    };
    coronarium_core::report::write(&report_args, &final_stats)?;

    if final_stats.denied > 0 && matches!(mode, policy::Mode::Block) {
        eprintln!(
            "::error title=coronarium::policy violation: {} events denied in block mode",
            final_stats.denied
        );
        std::process::exit(1);
    }
    std::process::exit(status.code().unwrap_or(1));
}

// ---------------------------------------------------------------------------
// ETW event handlers
// ---------------------------------------------------------------------------

/// Microsoft-Windows-Kernel-Process "ProcessStart" event id.
const EVT_PROCESS_START: u16 = 1;
/// Microsoft-Windows-Kernel-Network TCP connect (IPv4 + IPv6 combined).
/// IDs 12/14 = connect v4/v6. We accept both.
const EVT_TCP_CONNECT_V4: u16 = 12;
const EVT_TCP_CONNECT_V6: u16 = 14;
/// Microsoft-Windows-Kernel-File Create/Open. IDs vary by OS build; 12 &
/// 30 are the common "NameCreate / Create" ones. Accept a small whitelist
/// so we're resilient across runner images.
const EVT_FILE_CREATE: u16 = 12;
const EVT_FILE_OPEN: u16 = 30;

fn handle_process_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    stats: &Mutex<Stats>,
    exec_matcher: &ExecMatcher,
) {
    if record.event_id() != EVT_PROCESS_START {
        return;
    }
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = EtwParser::create(record, &schema);

    let filename: String = parser.try_parse("ImageName").unwrap_or_default();
    let argv0: String = parser.try_parse("CommandLine").unwrap_or_default();
    let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);

    let denied = exec_matcher.is_denied(&filename, &argv0);
    let ev = Event::Exec {
        pid,
        uid: 0, // Windows doesn't have POSIX uid; keep field for schema compat.
        comm: basename(&filename),
        filename,
        argv0,
        denied,
    };
    stats.lock().unwrap().ingest(ev);
}

fn handle_network_event(record: &EventRecord, schema_locator: &SchemaLocator, stats: &Mutex<Stats>) {
    let id = record.event_id();
    if id != EVT_TCP_CONNECT_V4 && id != EVT_TCP_CONNECT_V6 {
        return;
    }
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = EtwParser::create(record, &schema);

    let pid: u32 = parser.try_parse("PID").unwrap_or(0);
    let dport: u16 = parser.try_parse("dport").unwrap_or(0);
    let daddr: String = parser
        .try_parse::<String>("daddr")
        .unwrap_or_else(|_| "unknown".into());

    let ev = Event::Connect {
        pid,
        uid: 0,
        comm: String::new(),
        daddr,
        dport,
        protocol: 6, // TCP — the network provider fires for TCP; UDP has a
                      // separate opcode range we don't subscribe to yet.
        denied: false,
    };
    stats.lock().unwrap().ingest(ev);
}

fn handle_file_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    stats: &Mutex<Stats>,
    file_matcher: &FileMatcher,
) {
    let id = record.event_id();
    if id != EVT_FILE_CREATE && id != EVT_FILE_OPEN {
        return;
    }
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = EtwParser::create(record, &schema);

    let filename: String = parser.try_parse("FileName").unwrap_or_default();
    let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);

    // Normalise Windows path to forward-slash so policy entries written
    // for Linux can optionally match (people using this cross-platform
    // tend to write POSIX-style rules in YAML).
    let filename_norm = filename.replace('\\', "/");
    let denied = file_matcher.is_denied(&filename_norm);

    let ev = Event::Open {
        pid,
        uid: 0,
        comm: String::new(),
        filename: filename_norm,
        flags: 0,
        denied,
    };
    stats.lock().unwrap().ingest(ev);
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}
