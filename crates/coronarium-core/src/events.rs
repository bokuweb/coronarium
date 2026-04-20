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
        /// Reverse-DNS of `daddr` (PTR record) when known. Populated
        /// best-effort by the userspace supervisor after all events
        /// are collected — the kernel decoder doesn't know it.
        /// `None` means either "lookup not attempted" or "no PTR".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_and_kind_tag_variant_mapping() {
        let exec = Event::Exec {
            pid: 1,
            uid: 0,
            comm: "".into(),
            filename: "".into(),
            argv0: "".into(),
            denied: true,
        };
        let connect = Event::Connect {
            pid: 1,
            uid: 0,
            comm: "".into(),
            daddr: "".into(),
            dport: 0,
            protocol: 6,
            denied: false,
            hostname: None,
        };
        let open = Event::Open {
            pid: 1,
            uid: 0,
            comm: "".into(),
            filename: "".into(),
            flags: 0,
            denied: true,
        };
        assert_eq!(exec.kind_tag(), 0);
        assert_eq!(connect.kind_tag(), 1);
        assert_eq!(open.kind_tag(), 2);
        assert!(exec.denied());
        assert!(!connect.denied());
        assert!(open.denied());
    }

    #[test]
    fn serialises_tag_field_as_snake_case() {
        let e = Event::Exec {
            pid: 1,
            uid: 2,
            comm: "cmd".into(),
            filename: "/x".into(),
            argv0: "x".into(),
            denied: false,
        };
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["kind"], "exec");
        let o = Event::Open {
            pid: 1,
            uid: 2,
            comm: "".into(),
            filename: "/x".into(),
            flags: 0,
            denied: false,
        };
        assert_eq!(serde_json::to_value(&o).unwrap()["kind"], "open");
    }
}
