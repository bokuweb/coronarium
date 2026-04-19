use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{loader, policy, report};

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

    report::write(&args, &stats)?;

    if let Some(path) = &args.html {
        let command_str = args.command.join(" ");
        let meta = crate::html::ReportMeta {
            title: command_str.as_str(),
            mode,
            command: command_str.as_str(),
        };
        let html = crate::html::render(&policy, &stats, meta);
        std::fs::write(path, html)
            .with_context(|| format!("writing HTML report to {}", path.display()))?;
        log::info!("HTML report written to {}", path.display());
    }

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
