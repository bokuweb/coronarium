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
