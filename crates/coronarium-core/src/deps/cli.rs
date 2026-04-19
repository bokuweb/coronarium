//! Shared CLI glue so the Linux and Windows binaries expose `deps check`
//! with identical flags, output, and exit codes.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;

use super::{CheckArgs, CheckReport, check};

pub struct CliArgs {
    pub lockfiles: Vec<PathBuf>,
    pub min_age: String,
    pub ignore: Vec<String>,
    pub fail_on_missing: bool,
    pub no_cache: bool,
    pub cache_path: Option<PathBuf>,
    pub format: Format,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Text,
    Json,
}

pub fn run(args: CliArgs) -> Result<i32> {
    let min_age = parse_duration(&args.min_age)?;
    let cache_path = if args.no_cache {
        None
    } else {
        Some(args.cache_path.unwrap_or_else(default_cache_path))
    };
    let user_agent = args.user_agent.unwrap_or_else(|| {
        format!(
            "coronarium/{} (https://github.com/bokuweb/coronarium)",
            env!("CARGO_PKG_VERSION")
        )
    });

    let report = check(CheckArgs {
        lockfiles: &args.lockfiles,
        min_age,
        ignore: &args.ignore,
        fail_on_missing: args.fail_on_missing,
        cache: cache_path.as_deref(),
        user_agent: &user_agent,
    })?;

    print_report(&report, args.format)?;
    Ok(if report.violations > 0 { 1 } else { 0 })
}

fn print_report(report: &CheckReport, format: Format) -> Result<()> {
    match format {
        Format::Json => {
            let out = serde_json::to_string_pretty(report)?;
            writeln!(std::io::stdout(), "{out}")?;
        }
        Format::Text => {
            let stdout = std::io::stdout();
            let mut w = stdout.lock();
            writeln!(
                w,
                "coronarium deps check — min-age {}h, checked {} package(s)",
                report.min_age_hours, report.checked
            )?;
            if report.violations == 0 {
                writeln!(w, "✓ all packages meet the minimum release age")?;
            } else {
                writeln!(
                    w,
                    "✗ {} package(s) younger than {}h (= {} days):",
                    report.violations,
                    report.min_age_hours,
                    report.min_age_hours as f64 / 24.0,
                )?;
            }
            for p in &report.packages {
                if !p.too_new && p.error.is_none() {
                    continue;
                }
                if let Some(err) = &p.error {
                    writeln!(
                        w,
                        "  ? {}/{}  @{}   ({err})",
                        p.ecosystem, p.name, p.version
                    )?;
                } else if p.too_new {
                    let age = p
                        .age_hours
                        .map(|h| format!("{}h", h))
                        .unwrap_or_else(|| "?".into());
                    let published = p
                        .published
                        .map(|d| d.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "?".into());
                    writeln!(
                        w,
                        "  ✗ {}/{} @{}  published {} ({} old)",
                        p.ecosystem, p.name, p.version, published, age
                    )?;
                }
            }
            if report.errors > 0 {
                writeln!(
                    w,
                    "{} package(s) had lookup errors — pass --fail-on-missing to treat as violations.",
                    report.errors
                )?;
            }
        }
    }
    Ok(())
}

/// Accepts `30d`, `12h`, `600m`, `3600s`, or a bare number of days.
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty --min-age");
    }
    let (num, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&s[..s.len() - 1], c),
        _ => (s, 'd'),
    };
    let n: u64 = num
        .parse()
        .with_context(|| format!("parsing --min-age {s}: not a number"))?;
    let secs = match unit {
        'd' | 'D' => n * 24 * 3600,
        'h' | 'H' => n * 3600,
        'm' | 'M' => n * 60,
        's' | 'S' => n,
        _ => bail!("unknown --min-age unit {unit:?} (expected d/h/m/s)"),
    };
    Ok(Duration::from_secs(secs))
}

fn default_cache_path() -> PathBuf {
    // $XDG_CACHE_HOME / $HOME/.cache on Unix, %LOCALAPPDATA% on Windows.
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".cache");
                p
            })
        })
        .unwrap_or_else(|| PathBuf::from("."));

    // Silence the "now" import warning if chrono isn't used elsewhere in
    // this fn; we just touch it to ensure the cache file dir exists.
    let _ = Utc::now;
    base.join("coronarium").join("deps-cache.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(
            parse_duration("7d").unwrap(),
            Duration::from_secs(7 * 86400)
        );
        assert_eq!(parse_duration("7").unwrap(), Duration::from_secs(7 * 86400));
        assert_eq!(
            parse_duration("12h").unwrap(),
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("3600s").unwrap(), Duration::from_secs(3600));
        assert!(parse_duration("7x").is_err());
        assert!(parse_duration("").is_err());
    }
}
