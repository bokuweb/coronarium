//! Aggregate stats + sample buffer populated by the event drain loop.

use crate::events::Event;

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub observed: u64,
    pub denied: u64,
    pub lost: u64,
    pub samples: Vec<Event>,
}

/// How many samples per kind we keep in the buffer so a flood of one
/// kind (e.g. openat) doesn't crowd the others out of the UI.
pub const PER_KIND_CAP: usize = 64;
/// Overall cap on the sample buffer to bound memory.
pub const TOTAL_SAMPLE_CAP: usize = 256;

impl Stats {
    /// Merge an already-parsed event into the stats. Returns whether the
    /// event was kept in the sample buffer (for callers that want to know).
    pub fn ingest(&mut self, ev: Event) -> bool {
        self.observed += 1;
        if ev.denied() {
            self.denied += 1;
        }
        let existing = self
            .samples
            .iter()
            .filter(|s| s.kind_tag() == ev.kind_tag())
            .count();
        if existing < PER_KIND_CAP && self.samples.len() < TOTAL_SAMPLE_CAP {
            self.samples.push(ev);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(filename: &str, denied: bool) -> Event {
        Event::Open {
            pid: 1,
            uid: 0,
            comm: "x".into(),
            filename: filename.into(),
            flags: 0,
            denied,
        }
    }
    fn exec() -> Event {
        Event::Exec {
            pid: 2,
            uid: 0,
            comm: "x".into(),
            filename: "/bin/x".into(),
            argv0: "x".into(),
            denied: false,
        }
    }

    #[test]
    fn ingest_increments_observed_and_denied() {
        let mut s = Stats::default();
        s.ingest(open("/a", false));
        s.ingest(open("/b", true));
        s.ingest(exec());
        assert_eq!(s.observed, 3);
        assert_eq!(s.denied, 1);
        assert_eq!(s.samples.len(), 3);
    }

    #[test]
    fn per_kind_cap_prevents_flood_by_one_kind() {
        let mut s = Stats::default();
        for i in 0..1000 {
            s.ingest(open(&format!("/f{i}"), false));
        }
        // All 1000 are observed, but samples are capped.
        assert_eq!(s.observed, 1000);
        assert_eq!(s.samples.len(), PER_KIND_CAP);
        // Later-kind events can still get a sample slot up to their cap.
        s.ingest(exec());
        assert_eq!(s.samples.len(), PER_KIND_CAP + 1);
    }

    #[test]
    fn total_sample_cap_respected_across_kinds() {
        let mut s = Stats::default();
        // Fill with just-enough of each kind to exceed the total cap.
        for _ in 0..PER_KIND_CAP {
            s.ingest(open("/x", false));
        }
        for _ in 0..PER_KIND_CAP {
            s.ingest(exec());
        }
        // Connect samples then. open + exec = 2 * PER_KIND_CAP = 128.
        // TOTAL_SAMPLE_CAP = 256 > 128, so all connect can join.
        for _ in 0..PER_KIND_CAP {
            s.ingest(Event::Connect {
                pid: 3,
                uid: 0,
                comm: "x".into(),
                daddr: "1.2.3.4".into(),
                dport: 80,
                protocol: 6,
                denied: false,
                hostname: None,
            });
        }
        assert_eq!(s.samples.len(), 3 * PER_KIND_CAP);
        assert!(s.samples.len() <= TOTAL_SAMPLE_CAP);
    }
}
