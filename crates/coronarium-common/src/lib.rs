//! Shared, `#[repr(C)]` POD types exchanged between the eBPF programs and the
//! userspace loader through a ring buffer.
//!
//! The crate is `no_std` so it can be used from `aya-ebpf` programs (which are
//! compiled to `bpfel-unknown-none`). When built with the default `user`
//! feature, it additionally derives `bytemuck::Pod` / `Zeroable` and `serde`
//! traits used by the userspace side.

#![cfg_attr(not(feature = "user"), no_std)]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const ARGV0_LEN: usize = 128;

/// Maximum bytes of a path prefix the kernel will match against. Keep in
/// sync with eBPF-side stack bounds — longer values hit verifier limits.
pub const FILE_PREFIX_LEN: usize = 64;
/// How many prefix entries fit in the FILE_PREFIX array map.
pub const FILE_PREFIX_ENTRIES: u32 = 256;

pub const EVENT_KIND_EXEC: u32 = 1;
pub const EVENT_KIND_CONNECT4: u32 = 2;
pub const EVENT_KIND_CONNECT6: u32 = 3;
pub const EVENT_KIND_OPEN: u32 = 4;

pub const VERDICT_ALLOW: u32 = 0;
pub const VERDICT_DENY: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct EventHeader {
    pub kind: u32,
    pub verdict: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub _pad: u32,
    pub comm: [u8; COMM_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct ExecEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub argv0: [u8; ARGV0_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct Connect4Event {
    pub header: EventHeader,
    pub saddr: u32,
    pub daddr: u32,
    pub dport: u16,
    pub protocol: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct Connect6Event {
    pub header: EventHeader,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub dport: u16,
    pub protocol: u16,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct OpenEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub flags: u32,
    pub _pad: u32,
}

/// Key for the IPv4 allow/deny map: (daddr_be, dport_be). A dport of 0 means
/// "any port".
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct Ipv4Key {
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct Ipv6Key {
    pub addr: [u8; 16],
    pub port: u16,
    pub _pad: [u8; 6],
}

/// Values stored in policy maps.
pub const POLICY_ALLOW: u8 = 1;
pub const POLICY_DENY: u8 = 2;

/// Globally-scoped knobs readable from eBPF via an `Array` map at index 0.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(
    feature = "user",
    derive(
        bytemuck::Pod,
        bytemuck::Zeroable,
        Debug,
        serde::Serialize,
        serde::Deserialize
    )
)]
pub struct Settings {
    /// 0 = audit (log only), 1 = block.
    pub mode: u32,
    /// Default verdict for unmatched events. `POLICY_ALLOW` or `POLICY_DENY`.
    pub net_default: u32,
    pub file_default: u32,
    pub exec_default: u32,
}

/// One prefix entry for the FILE_PREFIX array: the first `len` bytes of
/// `bytes` form the prefix to match. `verdict` is [`POLICY_ALLOW`] or
/// [`POLICY_DENY`]. `active == 0` means the slot is empty (skipped during
/// matching).
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable, Debug))]
pub struct FilePrefix {
    pub bytes: [u8; FILE_PREFIX_LEN],
    pub len: u32,
    pub verdict: u8,
    pub active: u8,
    pub _pad: [u8; 2],
}

impl FilePrefix {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; FILE_PREFIX_LEN],
            len: 0,
            verdict: 0,
            active: 0,
            _pad: [0; 2],
        }
    }
}

// aya requires its own marker trait `aya::Pod` on map key/value types. Our
// structs are `#[repr(C)]` POD, so implementing it is safe. We do it here
// (rather than in the userspace crate) because the orphan rule bans impls
// for foreign types from downstream crates.
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for Ipv4Key {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for Ipv6Key {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for Settings {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for FilePrefix {}
