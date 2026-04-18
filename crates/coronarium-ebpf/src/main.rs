//! Kernel-side eBPF programs for coronarium.
//!
//! Compiled with:
//!   cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release
//!
//! Programs:
//!   - `coronarium_execve`   tracepoint:syscalls:sys_enter_execve
//!   - `coronarium_openat`   tracepoint:syscalls:sys_enter_openat
//!   - `coronarium_connect4` cgroup/connect4
//!   - `coronarium_connect6` cgroup/connect6
//!
//! Design notes
//! ------------
//! - We reserve the event directly inside the ring buffer and write into that
//!   memory (no large stack structs). This keeps us well under the 512-byte
//!   eBPF stack limit.
//! - Filename / argv are *not* copied from userspace in this version — doing
//!   that safely requires `bpf_probe_read_user_str` with tight bounds that
//!   vary by kernel. The userspace `comm` is enough to correlate events; full
//!   path capture is a follow-up once the programs load cleanly.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext},
};
use coronarium_common::{
    COMM_LEN, Connect4Event, Connect6Event, EVENT_KIND_CONNECT4, EVENT_KIND_CONNECT6,
    EVENT_KIND_EXEC, EVENT_KIND_OPEN, EventHeader, ExecEvent, Ipv4Key, Ipv6Key, OpenEvent,
    POLICY_ALLOW, POLICY_DENY, Settings, VERDICT_ALLOW, VERDICT_DENY,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

#[map]
static NET4: HashMap<Ipv4Key, u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[map]
static NET6: HashMap<Ipv6Key, u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[inline(always)]
fn settings() -> Settings {
    unsafe { SETTINGS.get(0) }.copied().unwrap_or(Settings {
        mode: 0,
        net_default: POLICY_ALLOW as u32,
        file_default: POLICY_ALLOW as u32,
        exec_default: POLICY_ALLOW as u32,
    })
}

#[inline(always)]
fn make_header(kind: u32, verdict: u32) -> EventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let mut comm = [0u8; COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        // bpf_get_current_comm returns exactly 16 bytes.
        let n = if c.len() < COMM_LEN { c.len() } else { COMM_LEN };
        let mut i = 0;
        while i < n {
            comm[i] = c[i];
            i += 1;
        }
    }
    EventHeader {
        kind,
        verdict,
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        _pad: 0,
        comm,
    }
}

// ---------------------------------------------------------------------------
// execve tracepoint — emits a header-only exec event with zeroed filename/argv0
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn coronarium_execve(_ctx: TracePointContext) -> u32 {
    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            // Zero the whole record first (the ringbuf gives us uninit memory).
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<ExecEvent>());
            (*ptr).header = make_header(EVENT_KIND_EXEC, VERDICT_ALLOW);
        }
        entry.submit(0);
    }
    0
}

// ---------------------------------------------------------------------------
// openat tracepoint — header-only open event
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn coronarium_openat(_ctx: TracePointContext) -> u32 {
    if let Some(mut entry) = EVENTS.reserve::<OpenEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<OpenEvent>());
            (*ptr).header = make_header(EVENT_KIND_OPEN, VERDICT_ALLOW);
        }
        entry.submit(0);
    }
    0
}

// ---------------------------------------------------------------------------
// cgroup connect4
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn coronarium_connect4(ctx: SockAddrContext) -> i32 {
    let (daddr, dport) = unsafe {
        let sa = &*ctx.sock_addr;
        (sa.user_ip4, sa.user_port as u16)
    };
    let verdict = lookup_net4(daddr, dport);

    if let Some(mut entry) = EVENTS.reserve::<Connect4Event>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Connect4Event>());
            (*ptr).header = make_header(
                EVENT_KIND_CONNECT4,
                if verdict == POLICY_DENY {
                    VERDICT_DENY
                } else {
                    VERDICT_ALLOW
                },
            );
            (*ptr).daddr = daddr;
            (*ptr).dport = dport;
        }
        entry.submit(0);
    }

    if settings().mode == 1 && verdict == POLICY_DENY {
        0 // EPERM to the userspace caller
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// cgroup connect6
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect6)]
pub fn coronarium_connect6(ctx: SockAddrContext) -> i32 {
    let (daddr_words, dport) = unsafe {
        let sa = &*ctx.sock_addr;
        (sa.user_ip6, sa.user_port as u16)
    };
    // Transmute [u32;4] → [u8;16] in one shot instead of looping (smaller
    // program, easier on the verifier).
    let daddr: [u8; 16] = unsafe { core::mem::transmute(daddr_words) };

    let verdict = lookup_net6(&daddr, dport);

    if let Some(mut entry) = EVENTS.reserve::<Connect6Event>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Connect6Event>());
            (*ptr).header = make_header(
                EVENT_KIND_CONNECT6,
                if verdict == POLICY_DENY {
                    VERDICT_DENY
                } else {
                    VERDICT_ALLOW
                },
            );
            (*ptr).daddr = daddr;
            (*ptr).dport = dport;
        }
        entry.submit(0);
    }

    if settings().mode == 1 && verdict == POLICY_DENY {
        0
    } else {
        1
    }
}

#[inline(always)]
fn lookup_net4(addr_be: u32, port_be: u16) -> u8 {
    let key = Ipv4Key {
        addr: addr_be,
        port: port_be,
        _pad: 0,
    };
    if let Some(v) = unsafe { NET4.get(&key) } {
        return *v;
    }
    let wildcard = Ipv4Key {
        addr: addr_be,
        port: 0,
        _pad: 0,
    };
    if let Some(v) = unsafe { NET4.get(&wildcard) } {
        return *v;
    }
    settings().net_default as u8
}

#[inline(always)]
fn lookup_net6(addr: &[u8; 16], port_be: u16) -> u8 {
    let key = Ipv6Key {
        addr: *addr,
        port: port_be,
        _pad: [0; 6],
    };
    if let Some(v) = unsafe { NET6.get(&key) } {
        return *v;
    }
    let wildcard = Ipv6Key {
        addr: *addr,
        port: 0,
        _pad: [0; 6],
    };
    if let Some(v) = unsafe { NET6.get(&wildcard) } {
        return *v;
    }
    settings().net_default as u8
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
