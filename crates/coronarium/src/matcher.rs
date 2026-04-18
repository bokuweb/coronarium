//! Userspace-side policy matching for events that reach the aggregator.
//!
//! The eBPF tracepoint ships the filename (and the connect programs ship
//! daddr / dport), but doesn't apply file policy itself — doing the scan
//! in-kernel blew the verifier's complexity budget. We stamp the verdict
//! here, just before the event is counted.

use crate::policy::{DefaultDecision, FilePolicy};

pub struct FileMatcher {
    pub default: DefaultDecision,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl FileMatcher {
    pub fn from_policy(p: &FilePolicy) -> Self {
        Self {
            default: p.default,
            allow: p.allow.clone(),
            deny: p.deny.clone(),
        }
    }

    /// Returns true when opening `path` should be treated as denied.
    /// Deny entries win over allow entries (same precedence as the
    /// network map).
    pub fn is_denied(&self, path: &str) -> bool {
        for pat in &self.deny {
            if prefix_match(path, pat) {
                return true;
            }
        }
        for pat in &self.allow {
            if prefix_match(path, pat) {
                return false;
            }
        }
        matches!(self.default, DefaultDecision::Deny)
    }
}

fn prefix_match(path: &str, pattern: &str) -> bool {
    // Exact prefix, with a boundary check so `/etc/shadow` doesn't match
    // `/etc/shadowed`. A trailing slash in the pattern forces directory
    // semantics explicitly.
    if !path.starts_with(pattern) {
        return false;
    }
    match path.as_bytes().get(pattern.len()) {
        None => true,                              // exact match
        Some(b'/') => true,                        // directory boundary
        Some(_) if pattern.ends_with('/') => true, // explicit dir pattern
        _ => path.len() == pattern.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(default: DefaultDecision, allow: &[&str], deny: &[&str]) -> FileMatcher {
        FileMatcher {
            default,
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn exact_and_child_prefix_matches() {
        let fm = m(DefaultDecision::Allow, &[], &["/etc/shadow", "/root/.ssh"]);
        assert!(fm.is_denied("/etc/shadow"));
        assert!(fm.is_denied("/root/.ssh/id_rsa"));
        assert!(!fm.is_denied("/etc/shadowed")); // boundary check
        assert!(!fm.is_denied("/etc/passwd"));
    }

    #[test]
    fn allow_list_with_default_deny() {
        let fm = m(DefaultDecision::Deny, &["/usr", "/lib", "/proc"], &[]);
        assert!(!fm.is_denied("/usr/bin/curl"));
        assert!(!fm.is_denied("/proc/self/maps"));
        assert!(fm.is_denied("/etc/passwd"));
    }

    #[test]
    fn deny_wins_over_allow() {
        let fm = m(DefaultDecision::Allow, &["/etc"], &["/etc/shadow"]);
        assert!(fm.is_denied("/etc/shadow"));
        assert!(!fm.is_denied("/etc/hostname"));
    }
}
