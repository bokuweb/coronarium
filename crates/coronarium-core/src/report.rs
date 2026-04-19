//! Writes the aggregate [`Stats`] out in three forms:
//! - JSON audit log (machine-readable)
//! - human-readable summary (suitable for `$GITHUB_STEP_SUMMARY`)
//! - optional HTML report (via [`crate::html`])

use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

use anyhow::Result;

use crate::{html, policy::Policy, stats::Stats};

pub struct ReportArgs<'a> {
    /// Destination for the JSON log. `"-"` means stdout.
    pub log: &'a str,
    /// Optional human-readable summary (markdown). Typically set to
    /// `$GITHUB_STEP_SUMMARY` so the line appears on the run page.
    pub summary: Option<&'a Path>,
    /// Optional self-contained HTML report.
    pub html: Option<&'a Path>,
    /// What the supervised process was — used as the report title.
    pub command: &'a str,
    /// Effective mode after any CLI override.
    pub mode: crate::policy::Mode,
    /// Policy passed through to the HTML "Effective policy" section.
    pub policy: &'a Policy,
}

pub fn write(args: &ReportArgs<'_>, stats: &Stats) -> Result<()> {
    // --- JSON ---
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
            .open(args.log)?;
        writeln!(f, "{serialized}")?;
    }

    // --- stderr warning on ringbuf overflow ---
    if stats.lost > 0 {
        eprintln!(
            "warning: dropped {} events (ring buffer overflow). Numbers \
             in the summary may undercount activity.",
            stats.lost
        );
    }

    // --- $GITHUB_STEP_SUMMARY markdown ---
    if let Some(path) = args.summary {
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

    // --- HTML ---
    if let Some(path) = args.html {
        let meta = html::ReportMeta {
            title: args.command,
            mode: args.mode,
            command: args.command,
        };
        let rendered = html::render(args.policy, stats, meta);
        std::fs::write(path, rendered)?;
    }

    Ok(())
}
