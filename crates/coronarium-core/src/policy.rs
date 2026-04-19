use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Audit,
    Block,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultDecision {
    Allow,
    /// Implicit default: if `default:` is omitted, everything not on the
    /// allow list is denied. Combine with `--mode audit` the first time
    /// you write a policy to see what *would* break before enforcing.
    #[default]
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub file: FilePolicy,
    #[serde(default)]
    pub process: ProcessPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub default: DefaultDecision,
    #[serde(default)]
    pub allow: Vec<NetRule>,
    #[serde(default)]
    pub deny: Vec<NetRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetRule {
    /// Either a hostname, an IPv4/IPv6 literal, or a CIDR string.
    pub target: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilePolicy {
    #[serde(default)]
    pub default: DefaultDecision,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessPolicy {
    #[serde(default)]
    pub deny_exec: Vec<String>,
}

impl Policy {
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let policy: Policy = match ext {
            "yaml" | "yml" => serde_yaml::from_slice(&bytes)?,
            "json" => serde_json::from_slice(&bytes)?,
            other => bail!("unsupported policy extension: {other:?}"),
        };
        Ok(policy)
    }

    /// Policy used when no `--policy` argument is passed: audit everything,
    /// deny nothing. Handy for "what would this job do?" dry-runs.
    pub fn permissive_audit() -> Self {
        Self {
            mode: Mode::Audit,
            network: NetworkPolicy {
                default: DefaultDecision::Allow,
                ..Default::default()
            },
            file: FilePolicy {
                default: DefaultDecision::Allow,
                ..Default::default()
            },
            process: ProcessPolicy::default(),
        }
    }

    /// Spot obviously-redundant policy shapes. Kept small on purpose —
    /// prefer clear docs over implicit behaviour.
    pub fn lint(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.network.deny.is_empty() && matches!(self.network.default, DefaultDecision::Deny) {
            out.push(
                "network.deny is non-empty but network.default is already 'deny' — \
                 the deny list is redundant."
                    .to_string(),
            );
        }
        if !self.file.deny.is_empty() && matches!(self.file.default, DefaultDecision::Deny) {
            out.push(
                "file.deny is non-empty but file.default is already 'deny' — \
                 the deny list is redundant."
                    .to_string(),
            );
        }
        out
    }
}
