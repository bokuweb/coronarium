//! "Given this (ecosystem, name, version), should we let the fetch
//! through or return 403?"
//!
//! The trait exists so tests can inject a deterministic age-lookup
//! function instead of hitting the real registry.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use coronarium_core::deps::Ecosystem;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let the request through.
    Allow,
    /// Return 403 to the client with `reason` in the body.
    Deny { reason: String },
}

/// Plug-in point so the MITM proxy doesn't have to know where publish
/// dates come from. Production wires this to the existing
/// `coronarium-core::deps::registry` HTTP clients; tests pass a
/// canned-response implementation.
pub trait AgeOracle: Send + Sync {
    fn published(&self, eco: Ecosystem, name: &str, version: &str)
    -> Result<Option<DateTime<Utc>>>;
}

pub struct Decider<O: AgeOracle + ?Sized> {
    pub oracle: Box<O>,
    pub min_age: Duration,
    /// If `true`, treat lookup failures (network error, unknown crate,
    /// …) as Deny. If `false`, fail-open and Allow so a flaky registry
    /// doesn't brick the developer's install flow.
    pub fail_on_missing: bool,
}

impl<O: AgeOracle + ?Sized> Decider<O> {
    pub fn decide(
        &self,
        eco: Ecosystem,
        name: &str,
        version: &str,
        now: DateTime<Utc>,
    ) -> Decision {
        match self.oracle.published(eco, name, version) {
            Ok(Some(published)) => {
                let age = now - published;
                let cutoff = chrono::Duration::from_std(self.min_age).unwrap_or_default();
                if age < cutoff {
                    Decision::Deny {
                        reason: format!(
                            "coronarium: {}/{}@{} was published {} ago (< min-age {}h)",
                            eco.label(),
                            name,
                            version,
                            human_duration(age),
                            self.min_age.as_secs() / 3600,
                        ),
                    }
                } else {
                    Decision::Allow
                }
            }
            Ok(None) => {
                if self.fail_on_missing {
                    Decision::Deny {
                        reason: format!(
                            "coronarium: {}/{}@{} publish date unknown (--fail-on-missing)",
                            eco.label(),
                            name,
                            version
                        ),
                    }
                } else {
                    Decision::Allow
                }
            }
            Err(e) => {
                log::warn!(
                    "age lookup for {}/{}@{} failed: {e:#}",
                    eco.label(),
                    name,
                    version
                );
                if self.fail_on_missing {
                    Decision::Deny {
                        reason: "coronarium: age lookup failed (--fail-on-missing)".into(),
                    }
                } else {
                    Decision::Allow
                }
            }
        }
    }
}

fn human_duration(d: chrono::Duration) -> String {
    let h = d.num_hours();
    if h < 48 {
        format!("{h}h")
    } else {
        format!("{}d", d.num_days())
    }
}

/// Production oracle: delegates to the existing per-ecosystem registry
/// clients in `coronarium-core::deps::registry`. The proxy sits in
/// front of the same registries these clients query, so for the MITM
/// case we need to reach the real registry via an OS socket that
/// bypasses the proxy — done here simply by calling into the blocking
/// `ureq` clients which don't honour `HTTPS_PROXY`.
pub struct RegistryOracle {
    pub user_agent: String,
}

impl RegistryOracle {
    pub fn new(user_agent: String) -> Self {
        Self { user_agent }
    }
}

impl AgeOracle for RegistryOracle {
    fn published(
        &self,
        eco: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Option<DateTime<Utc>>> {
        use coronarium_core::deps::registry;
        match eco {
            Ecosystem::Crates => registry::crates::published(name, version, &self.user_agent),
            Ecosystem::Npm => registry::npm::published(name, version, &self.user_agent),
            Ecosystem::Pypi => registry::pypi::published(name, version, &self.user_agent),
            Ecosystem::Nuget => registry::nuget::published(name, version, &self.user_agent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    struct FixedOracle(Option<DateTime<Utc>>);
    impl AgeOracle for FixedOracle {
        fn published(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<DateTime<Utc>>> {
            Ok(self.0)
        }
    }

    struct ErrOracle;
    impl AgeOracle for ErrOracle {
        fn published(&self, _: Ecosystem, _: &str, _: &str) -> Result<Option<DateTime<Utc>>> {
            Err(anyhow::anyhow!("network is down"))
        }
    }

    fn decider(
        oracle: impl AgeOracle + 'static,
        min_age_hours: u64,
        fail_on_missing: bool,
    ) -> Decider<dyn AgeOracle> {
        Decider {
            oracle: Box::new(oracle) as Box<dyn AgeOracle>,
            min_age: Duration::from_secs(min_age_hours * 3600),
            fail_on_missing,
        }
    }

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn too_new_is_denied_with_reason() {
        // Published 2h ago, cutoff = 168h (7d).
        let now = utc(2025, 1, 10);
        let pub_time = now - chrono::Duration::hours(2);
        let d = decider(FixedOracle(Some(pub_time)), 168, false);
        match d.decide(Ecosystem::Crates, "serde", "99.99.99", now) {
            Decision::Deny { reason } => {
                assert!(reason.contains("crates/serde@99.99.99"));
                assert!(reason.contains("2h ago"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn old_enough_is_allowed() {
        let now = utc(2025, 1, 10);
        let pub_time = now - chrono::Duration::days(30);
        let d = decider(FixedOracle(Some(pub_time)), 168, false);
        assert_eq!(
            d.decide(Ecosystem::Crates, "serde", "1.0.0", now),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_publish_date_fails_open_by_default() {
        let d = decider(FixedOracle(None), 168, false);
        assert_eq!(
            d.decide(Ecosystem::Crates, "mystery", "0.1.0", utc(2025, 1, 1)),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_publish_date_fails_closed_when_requested() {
        let d = decider(FixedOracle(None), 168, true);
        match d.decide(Ecosystem::Crates, "mystery", "0.1.0", utc(2025, 1, 1)) {
            Decision::Deny { reason } => {
                assert!(reason.contains("fail-on-missing"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn network_error_follows_fail_on_missing_flag() {
        // fail_on_missing=false → allow
        let d = decider(ErrOracle, 168, false);
        assert_eq!(
            d.decide(Ecosystem::Npm, "x", "1.0.0", utc(2025, 1, 1)),
            Decision::Allow
        );
        // fail_on_missing=true → deny
        let d = decider(ErrOracle, 168, true);
        assert!(matches!(
            d.decide(Ecosystem::Npm, "x", "1.0.0", utc(2025, 1, 1)),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn exactly_at_cutoff_is_allowed() {
        let now = utc(2025, 1, 10);
        // published exactly min_age ago
        let pub_time = now - chrono::Duration::hours(168);
        let d = decider(FixedOracle(Some(pub_time)), 168, false);
        assert_eq!(d.decide(Ecosystem::Crates, "x", "1", now), Decision::Allow);
    }
}
