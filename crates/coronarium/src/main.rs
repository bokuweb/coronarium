#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

mod cgroup;
mod cli;
mod enforcer;
mod events;
mod html;
mod loader;
mod matcher;
mod policy;
mod report;
mod resolve;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cli::Cli::parse();
    cli::run(args).await
}
