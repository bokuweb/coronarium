use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use coronarium_core::report::ReportArgs;
use std::time::Duration;

use crate::{loader, policy};

/// Resolve the CA directory either from the `--config-dir` override or
/// the default location. Centralised so every `proxy …` subcommand
/// uses the same layout.
fn ca_files_for(dir: Option<PathBuf>) -> anyhow::Result<coronarium_proxy::ca::CaFiles> {
    Ok(match dir {
        Some(d) => coronarium_proxy::ca::CaFiles::at(d.join("coronarium")),
        None => coronarium_proxy::ca::CaFiles::at_default_location()?,
    })
}

/// Parse a simple `<N><unit>` duration (e.g. `7d`, `12h`, `30m`, `3600s`).
/// Bare numbers default to days. Used by proxy/watch-style CLI flags
/// where pulling in humantime feels overkill.
fn parse_simple_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration");
    }
    let (num, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&s[..s.len() - 1], c),
        _ => (s, 'd'),
    };
    let n: u64 = num.parse()?;
    let secs = match unit {
        'd' | 'D' => n * 86400,
        'h' | 'H' => n * 3600,
        'm' | 'M' => n * 60,
        's' | 'S' => n,
        _ => anyhow::bail!("unknown duration unit {unit:?}"),
    };
    Ok(Duration::from_secs(secs))
}

#[derive(Debug, Parser)]
#[command(
    name = "coronarium",
    version,
    about = "eBPF-based audit & block for CI workloads"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Attach eBPF programs, run the given command under supervision, detach
    /// on exit.
    Run(RunArgs),
    /// Validate a policy file without attaching anything.
    CheckPolicy {
        #[arg(long, short = 'p')]
        policy: PathBuf,
    },
    /// Supply-chain hardening: fail if any package in the given lockfile(s)
    /// was published less than `--min-age` ago.
    Deps {
        #[command(subcommand)]
        cmd: DepsCommand,
    },
    /// Transparent HTTPS MITM proxy that enforces minimum-release-age
    /// at the registry fetch layer. Experimental — see CLAUDE.md.
    Proxy {
        #[command(subcommand)]
        cmd: ProxyCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Start the proxy. Prints the root CA's install instructions on
    /// first run.
    Start(ProxyStartArgs),
    /// Add the proxy's root CA to the OS trust store (sudo required on
    /// macOS/Linux; admin PowerShell on Windows). Prints the exact
    /// command when we can't run it ourselves.
    InstallCa(ProxyCaArgs),
    /// Remove the proxy's root CA from the OS trust store.
    UninstallCa(ProxyCaArgs),
}

#[derive(Debug, Parser)]
pub struct ProxyCaArgs {
    /// Override the CA/config directory.
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ProxyStartArgs {
    /// Address the proxy listens on. Clients set `HTTPS_PROXY` /
    /// `HTTP_PROXY` to this.
    #[arg(long, default_value = "127.0.0.1:8910")]
    pub listen: std::net::SocketAddr,
    /// Minimum age a package must have, same grammar as `deps check`.
    #[arg(long, default_value = "7d")]
    pub min_age: String,
    /// Treat unknown publish dates as a deny (default: fail-open /
    /// allow through).
    #[arg(long)]
    pub fail_on_missing: bool,
    /// Override the CA/config directory. Defaults to
    /// `$XDG_CONFIG_HOME/coronarium` (or `~/.config/coronarium`).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    /// Check publish ages against all dependencies in the given lockfile(s).
    Check(DepsCheckArgs),
    /// Stay resident: watch one or more workspace roots, run `check` on
    /// every lockfile change, and surface violations via a desktop
    /// notification. Designed for `launchd` / `systemd --user`.
    Watch(DepsWatchArgs),
}

#[derive(Debug, Parser)]
pub struct DepsWatchArgs {
    /// Workspace root(s) to watch recursively.
    #[arg(required = true)]
    pub roots: Vec<PathBuf>,
    /// Minimum age a package must have.
    #[arg(long, default_value = "7d")]
    pub min_age: String,
    #[arg(long)]
    pub ignore: Vec<String>,
    #[arg(long)]
    pub no_cache: bool,
    #[arg(long)]
    pub cache: Option<PathBuf>,
    /// How long to wait for a burst of edits to settle, in ms.
    #[arg(long, default_value_t = 800)]
    pub debounce_ms: u64,
    /// Poll interval for the FS-event source, in ms.
    #[arg(long, default_value_t = 250)]
    pub tick_ms: u64,
    /// Notification sink. `mac` uses osascript (macOS only), `stdout`
    /// prints to stderr — good for launchctl log redirects.
    #[arg(long, value_enum, default_value = "mac")]
    pub notifier: DepsNotifier,
    /// What to do when a violation is detected.
    ///
    /// - `notify` (default): just post a notification. The lockfile is
    ///   left as-is; nothing is blocked.
    /// - `prompt` (macOS only): show a Keep/Revert modal. Only useful
    ///   **after** the install has already completed, so this is
    ///   detection, not prevention — see README "Limitations".
    /// - `revert`: silently restore the lockfile to `HEAD` via git.
    ///   Destructive. Requires the lockfile to be git-tracked.
    #[arg(long, value_enum, default_value = "notify")]
    pub action: DepsAction,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DepsNotifier {
    Mac,
    Stdout,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DepsAction {
    Notify,
    Prompt,
    Revert,
}

#[derive(Debug, Parser)]
pub struct DepsCheckArgs {
    /// Lockfiles to inspect. Currently: package-lock.json, Cargo.lock.
    #[arg(required = true)]
    pub lockfiles: Vec<PathBuf>,
    /// Minimum age a package must have. Units: `d` (default), `h`, `m`, `s`.
    #[arg(long, default_value = "7d")]
    pub min_age: String,
    /// Don't check packages whose name matches this pattern. Accepts plain
    /// names, `prefix*`, `*suffix`, or scope globs like `@types/*`. Repeat.
    #[arg(long)]
    pub ignore: Vec<String>,
    /// Treat missing publish-date lookups as violations instead of warnings.
    #[arg(long)]
    pub fail_on_missing: bool,
    /// Skip the on-disk cache of publish dates entirely.
    #[arg(long)]
    pub no_cache: bool,
    /// Override the default cache path.
    #[arg(long)]
    pub cache: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: DepsFormat,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DepsFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    Audit,
    Block,
}

#[derive(Debug, Parser)]
pub struct RunArgs {
    /// Policy file (YAML or JSON).
    #[arg(long, short = 'p', env = "CORONARIUM_POLICY")]
    pub policy: Option<PathBuf>,

    /// Override the policy's `mode`.
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,

    /// Where to write the JSON audit log. `-` for stdout.
    #[arg(long, default_value = "-")]
    pub log: String,

    /// Optional path to write a human-readable summary (suitable for
    /// `$GITHUB_STEP_SUMMARY`).
    #[arg(long, env = "GITHUB_STEP_SUMMARY")]
    pub summary: Option<PathBuf>,

    /// Optional path to write a self-contained HTML audit report. Open
    /// directly in a browser; designed to be uploaded as a workflow
    /// artifact.
    #[arg(long)]
    pub html: Option<PathBuf>,

    /// Command + args to execute under supervision.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::CheckPolicy { policy } => {
            let p = policy::Policy::from_file(&policy)
                .with_context(|| format!("loading {}", policy.display()))?;
            for w in p.lint() {
                eprintln!("warning: {w}");
            }
            println!("{}", serde_json::to_string_pretty(&p)?);
            Ok(())
        }
        Command::Run(args) => run_supervised(args).await,
        Command::Deps {
            cmd: DepsCommand::Check(args),
        } => {
            let exit = coronarium_core::deps::cli::run(coronarium_core::deps::cli::CliArgs {
                lockfiles: args.lockfiles,
                min_age: args.min_age,
                ignore: args.ignore,
                fail_on_missing: args.fail_on_missing,
                no_cache: args.no_cache,
                cache_path: args.cache,
                format: match args.format {
                    DepsFormat::Text => coronarium_core::deps::cli::Format::Text,
                    DepsFormat::Json => coronarium_core::deps::cli::Format::Json,
                },
                user_agent: None,
            })?;
            std::process::exit(exit);
        }
        Command::Proxy {
            cmd: ProxyCommand::InstallCa(args),
        } => {
            let ca_files = ca_files_for(args.config_dir)?;
            // Ensure the CA exists first so the install command has
            // something to point at.
            coronarium_proxy::ca::ensure_ca(&ca_files)?;
            let r = coronarium_proxy::install::install_ca(&ca_files)?;
            use coronarium_proxy::install::InstallOutcome;
            match r.outcome {
                InstallOutcome::Installed => {
                    println!(
                        "✓ coronarium root CA installed into the system trust store\n  ({})",
                        ca_files.cert_pem.display()
                    );
                }
                InstallOutcome::NeedsPrivilege => {
                    println!(
                        "Need elevated privileges to install the CA. Run:\n\n  {}\n",
                        r.command_hint
                    );
                }
                InstallOutcome::Manual => {
                    println!("{}", r.command_hint);
                }
            }
            Ok(())
        }
        Command::Proxy {
            cmd: ProxyCommand::UninstallCa(args),
        } => {
            let ca_files = ca_files_for(args.config_dir)?;
            let r = coronarium_proxy::install::uninstall_ca(&ca_files)?;
            use coronarium_proxy::install::InstallOutcome;
            match r.outcome {
                InstallOutcome::Installed => {
                    println!("✓ coronarium root CA removed from the system trust store");
                }
                InstallOutcome::NeedsPrivilege => {
                    println!(
                        "Need elevated privileges to remove the CA. Run:\n\n  {}\n",
                        r.command_hint
                    );
                }
                InstallOutcome::Manual => {
                    println!("{}", r.command_hint);
                }
            }
            Ok(())
        }
        Command::Proxy {
            cmd: ProxyCommand::Start(args),
        } => {
            let min_age = parse_simple_duration(&args.min_age)?;
            let ca_files = ca_files_for(args.config_dir)?;
            let cfg = coronarium_proxy::ProxyConfig {
                listen: args.listen,
                min_age,
                fail_on_missing: args.fail_on_missing,
                ca_files,
                user_agent: format!("coronarium-proxy/{}", env!("CARGO_PKG_VERSION")),
                oracle: None,
            };
            coronarium_proxy::run(cfg).await?;
            Ok(())
        }
        Command::Deps {
            cmd: DepsCommand::Watch(args),
        } => {
            coronarium_core::deps::cli::run_watch(coronarium_core::deps::cli::WatchCliArgs {
                roots: args.roots,
                min_age: args.min_age,
                ignore: args.ignore,
                no_cache: args.no_cache,
                cache_path: args.cache,
                debounce_ms: args.debounce_ms,
                tick_ms: args.tick_ms,
                notifier: match args.notifier {
                    DepsNotifier::Mac => coronarium_core::deps::cli::WatchNotifierKind::Mac,
                    DepsNotifier::Stdout => coronarium_core::deps::cli::WatchNotifierKind::Stdout,
                },
                action: match args.action {
                    DepsAction::Notify => coronarium_core::deps::cli::WatchActionKind::Notify,
                    DepsAction::Prompt => coronarium_core::deps::cli::WatchActionKind::Prompt,
                    DepsAction::Revert => coronarium_core::deps::cli::WatchActionKind::Revert,
                },
                user_agent: None,
            })?;
            Ok(())
        }
    }
}

async fn run_supervised(args: RunArgs) -> Result<()> {
    let policy = match &args.policy {
        Some(p) => policy::Policy::from_file(p)?,
        None => policy::Policy::permissive_audit(),
    };
    let mode = match args.mode {
        Some(Mode::Audit) => policy::Mode::Audit,
        Some(Mode::Block) => policy::Mode::Block,
        None => policy.mode,
    };
    for w in policy.lint() {
        log::warn!("{w}");
    }
    log::info!(
        "starting coronarium (mode={:?}, command={:?})",
        mode,
        args.command
    );

    let supervised = loader::Supervisor::start(policy.clone(), mode).await?;
    let exit = supervised.run_child(&args.command).await?;
    let stats = supervised.shutdown().await?;

    let command_str = args.command.join(" ");
    let report_args = ReportArgs {
        log: &args.log,
        summary: args.summary.as_deref(),
        html: args.html.as_deref(),
        command: command_str.as_str(),
        mode,
        policy: &policy,
    };
    coronarium_core::report::write(&report_args, &stats)?;

    if stats.denied > 0 && matches!(mode, policy::Mode::Block) {
        // GitHub Actions error annotation — renders as a red banner on the
        // step UI so block-mode failures don't hide in the log.
        eprintln!(
            "::error title=coronarium::policy violation: {} events denied in block mode",
            stats.denied
        );
        std::process::exit(1);
    }
    std::process::exit(exit);
}
