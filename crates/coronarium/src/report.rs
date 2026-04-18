use std::{
    fs::OpenOptions,
    io::{self, Write},
};

use anyhow::Result;

use crate::{cli::RunArgs, loader::Stats};

pub fn write(args: &RunArgs, stats: &Stats) -> Result<()> {
    let payload = serde_json::json!({
        "observed": stats.observed,
        "denied": stats.denied,
        "lost": stats.lost,
        "samples": stats.samples,
    });
    let serialized = serde_json::to_string_pretty(&payload)?;

    if args.log == "-" {
        writeln!(io::stdout(), "{serialized}")?;
    } else {
        let mut f = OpenOptions::new().create(true).append(true).open(&args.log)?;
        writeln!(f, "{serialized}")?;
    }

    if let Some(path) = &args.summary {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(
            f,
            "## coronarium\n\n- observed: **{}**\n- denied: **{}**\n- lost samples: {}\n",
            stats.observed, stats.denied, stats.lost
        )?;
    }
    Ok(())
}
