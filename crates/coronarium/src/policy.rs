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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultDecision {
    Allow,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default = "allow")]
    pub default: DefaultDecision,
    #[serde(default)]
    pub allow: Vec<NetRule>,
    #[serde(default)]
    pub deny: Vec<NetRule>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            default: DefaultDecision::Allow,
            allow: vec![],
            deny: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetRule {
    /// Either a hostname, an IPv4/IPv6 literal, or a CIDR string.
    pub target: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePolicy {
    #[serde(default = "allow")]
    pub default: DefaultDecision,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for FilePolicy {
    fn default() -> Self {
        Self {
            default: DefaultDecision::Allow,
            allow: vec![],
            deny: vec![],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessPolicy {
    #[serde(default)]
    pub deny_exec: Vec<String>,
}

fn allow() -> DefaultDecision {
    DefaultDecision::Allow
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

    pub fn permissive_audit() -> Self {
        Self {
            mode: Mode::Audit,
            network: NetworkPolicy::default(),
            file: FilePolicy::default(),
            process: ProcessPolicy::default(),
        }
    }

    /// Returns human-readable warnings about likely-misconfigured shapes.
    /// The most common one: writing an `allow:` list but leaving
    /// `default: allow`, which makes the allow list a no-op.
    pub fn lint(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.network.allow.is_empty() && matches!(self.network.default, DefaultDecision::Allow)
        {
            out.push(
                "network.allow is non-empty but network.default is 'allow' — \
                 the allow list has no effect. Did you mean `network.default: deny`?"
                    .to_string(),
            );
        }
        if !self.file.deny.is_empty() && matches!(self.file.default, DefaultDecision::Deny) {
            out.push(
                "file.deny is non-empty but file.default is already 'deny' — \
                 the deny list is redundant. Did you mean `file.default: allow`?"
                    .to_string(),
            );
        }
        out
    }
}
