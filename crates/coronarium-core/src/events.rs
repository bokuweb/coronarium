//! Event enum shared between Linux eBPF decoder and Windows ETW parser.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Exec {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
        argv0: String,
        denied: bool,
    },
    Connect {
        pid: u32,
        uid: u32,
        comm: String,
        daddr: String,
        dport: u16,
        protocol: u16,
        denied: bool,
    },
    Open {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
        flags: u32,
        denied: bool,
    },
}

impl Event {
    pub fn denied(&self) -> bool {
        match self {
            Event::Exec { denied, .. }
            | Event::Connect { denied, .. }
            | Event::Open { denied, .. } => *denied,
        }
    }

    /// Compact discriminant used to bucket events by kind for sampling.
    pub fn kind_tag(&self) -> u8 {
        match self {
            Event::Exec { .. } => 0,
            Event::Connect { .. } => 1,
            Event::Open { .. } => 2,
        }
    }
}
