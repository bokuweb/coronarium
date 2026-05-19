//! NuGet registration index client.
//!
//! Endpoint family: `https://api.nuget.org/v3/registration5-semver1/<name-lower>/<version>.json`.
//! The response's `catalogEntry` is either inline (has `.published`) or a
//! URL pointing at the catalog entry — both shapes are valid NuGet
//! responses, so handle both.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

/// Extract the host (case-preserving) from a `scheme://host[:port][/...]`
/// URL. Returns `None` for malformed input — the caller treats
/// `None` as "can't compare", which biases to allowing the
/// follow-up (today's behaviour for unparseable URLs).
fn parse_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if host_port.is_empty() {
        None
    } else {
        Some(host_port.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct Leaf {
    #[serde(rename = "catalogEntry")]
    catalog_entry: CatalogEntryRef,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CatalogEntryRef {
    Inline(CatalogEntry),
    Url(String),
}

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    #[serde(default)]
    published: Option<String>,
}

pub fn published(
    name: &str,
    version: &str,
    user_agent: &str,
    base_url: &str,
) -> Result<Option<DateTime<Utc>>> {
    let lower = name.to_ascii_lowercase();
    let version = version.trim_start_matches('v');

    let urls = [
        format!("{base_url}/v3/registration5-semver1/{lower}/{version}.json"),
        format!("{base_url}/v3/registration5-gz-semver2/{lower}/{version}.json"),
    ];

    // For the `catalogEntry: Url(...)` indirection branch we
    // restrict the follow-up GET to a URL whose host matches the
    // configured `base_url`. NuGet v3 technically allows the
    // catalog to live on a different host, but for the trust-
    // boundary use case (`--nuget-registry` against an internal
    // mirror that mustn't escape to public NuGet) the conservative
    // fail-open path is preferable. `--fail-on-missing` catches
    // skipped lookups in CI. Documented as a known limitation in
    // CLAUDE.md.
    let base_host = parse_host(base_url);

    let agent = super::agent();
    for url in &urls {
        let resp = agent
            .get(url)
            .set("User-Agent", user_agent)
            .set("Accept", "application/json")
            .call();
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => continue,
            Err(e) => return Err(e).with_context(|| format!("GET {url}")),
        };

        let leaf: Leaf = resp
            .into_json()
            .with_context(|| format!("parsing nuget leaf for {name}@{version}"))?;

        let entry = match leaf.catalog_entry {
            CatalogEntryRef::Inline(e) => e,
            CatalogEntryRef::Url(catalog_url) => {
                // Host-match guard against the configured base.
                // A mismatch could mean a legitimate split-host
                // NuGet feed OR a compromised mirror redirecting
                // to attacker infrastructure. We fail-open
                // (`Ok(None)`) rather than follow the indirection
                // — the result is "publish date unknown", which
                // `--fail-on-missing` can escalate to Deny in CI.
                let catalog_host = parse_host(&catalog_url);
                if let (Some(base), Some(catalog)) = (base_host.as_deref(), catalog_host.as_deref())
                    && !catalog.eq_ignore_ascii_case(base)
                {
                    log::warn!(
                        "nuget: catalogEntry URL host `{catalog}` differs from configured base `{base}`; treating as missing publish-date (fail-open). Set --fail-on-missing to deny in CI."
                    );
                    return Ok(None);
                }
                // Follow the indirection once.
                let r = agent
                    .get(&catalog_url)
                    .set("User-Agent", user_agent)
                    .set("Accept", "application/json")
                    .call()
                    .with_context(|| format!("GET {catalog_url}"))?;
                r.into_json::<CatalogEntry>()
                    .with_context(|| format!("parsing nuget catalog entry {catalog_url}"))?
            }
        };

        let Some(ts) = entry.published else {
            return Ok(None);
        };
        let dt = DateTime::parse_from_rfc3339(&ts)
            .with_context(|| format!("parsing nuget timestamp {ts}"))?;
        return Ok(Some(dt.with_timezone(&Utc)));
    }
    Ok(None)
}
