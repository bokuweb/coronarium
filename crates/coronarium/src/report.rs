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
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&args.log)?;
        writeln!(f, "{serialized}")?;
    }

    if stats.lost > 0 {
        // lost is usually harmless (ringbuf burst) but can hide a denied
        // event, so make it visible on stderr regardless of log mode.
        eprintln!(
            "warning: dropped {} events (ring buffer overflow). Numbers \
             in the summary may undercount activity.",
            stats.lost
        );
    }

    if let Some(path) = &args.summary {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        let lost_note = if stats.lost > 0 {
            format!(
                "\n> ⚠️ {} events were dropped due to ring-buffer overflow; \
                 totals may undercount.",
                stats.lost
            )
        } else {
            String::new()
        };
        writeln!(
            f,
            "## coronarium\n\n\
             | metric | count |\n\
             |---|---:|\n\
             | observed | **{}** |\n\
             | denied   | **{}** |\n\
             | lost     | {} |\n{lost_note}\n",
            stats.observed, stats.denied, stats.lost,
        )?;
    }
    Ok(())
}
