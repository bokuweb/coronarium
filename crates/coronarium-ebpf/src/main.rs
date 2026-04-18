//! Kernel-side eBPF programs for coronarium.
//!
//! Compiled with:
//!   cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release
//!
//! Programs:
//!   - `coronarium_execve`  (tracepoint:syscalls:sys_enter_execve)
//!   - `coronarium_openat`  (tracepoint:syscalls:sys_enter_openat)
//!   - `coronarium_connect4` (cgroup/connect4)
//!   - `coronarium_connect6` (cgroup/connect6)
//!
//! Shared maps:
//!   - `EVENTS`   ring buffer to userspace
//!   - `SETTINGS` mode + defaults
//!   - `NET4` / `NET6` allow/deny
//!   - `FILE_PREFIX` allow/deny by path prefix

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext},
};
use coronarium_common::{
    ARGV0_LEN, COMM_LEN, Connect4Event, Connect6Event, EVENT_KIND_CONNECT4, EVENT_KIND_CONNECT6,
    EVENT_KIND_EXEC, EVENT_KIND_OPEN, EventHeader, ExecEvent, Ipv4Key, Ipv6Key, OpenEvent, PATH_LEN,
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

fn settings() -> Settings {
    unsafe { SETTINGS.get(0) }
        .copied()
        .unwrap_or(Settings { mode: 0, net_default: POLICY_ALLOW as u32, file_default: POLICY_ALLOW as u32, exec_default: POLICY_ALLOW as u32 })
}

fn fill_header(kind: u32, verdict: u32) -> EventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let mut comm = [0u8; COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        let len = c.len().min(COMM_LEN);
        comm[..len].copy_from_slice(&c[..len]);
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
// execve tracepoint
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn coronarium_execve(ctx: TracePointContext) -> u32 {
    let _ = try_execve(&ctx);
    0
}

fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    // struct trace_event_raw_sys_enter { ... u64 args[6]; } -- we read args[0]
    // (filename pointer) at offset 16.
    let filename_ptr: *const u8 = unsafe { ctx.read_at::<*const u8>(16)? };
    let argv_ptr: *const *const u8 = unsafe { ctx.read_at::<*const *const u8>(24)? };

    let mut ev = ExecEvent {
        header: fill_header(EVENT_KIND_EXEC, VERDICT_ALLOW),
        filename: [0; PATH_LEN],
        argv0: [0; ARGV0_LEN],
    };
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut ev.filename);
        let first: *const u8 = ctx.read_at(argv_ptr as usize).unwrap_or(core::ptr::null());
        if !first.is_null() {
            let _ = bpf_probe_read_user_str_bytes(first, &mut ev.argv0);
        }
    }

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        entry.write(ev);
        entry.submit(0);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// openat tracepoint
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn coronarium_openat(ctx: TracePointContext) -> u32 {
    let _ = try_openat(&ctx);
    0
}

fn try_openat(ctx: &TracePointContext) -> Result<(), i64> {
    // args[0]=dfd (i32), args[1]=filename (const char*), args[2]=flags (i32)
    let filename_ptr: *const u8 = unsafe { ctx.read_at::<*const u8>(24)? };
    let flags: u32 = unsafe { ctx.read_at::<u32>(32).unwrap_or(0) };

    let mut ev = OpenEvent {
        header: fill_header(EVENT_KIND_OPEN, VERDICT_ALLOW),
        filename: [0; PATH_LEN],
        flags,
        _pad: 0,
    };
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut ev.filename);
    }

    if let Some(mut entry) = EVENTS.reserve::<OpenEvent>(0) {
        entry.write(ev);
        entry.submit(0);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cgroup connect4 / connect6
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn coronarium_connect4(ctx: SockAddrContext) -> i32 {
    let user = unsafe { &*ctx.sock_addr };
    let daddr = unsafe { (*user).user_ip4 };
    let dport = unsafe { (*user).user_port as u16 };

    let verdict = lookup_net4(daddr, dport);
    let mut ev = Connect4Event {
        header: fill_header(
            EVENT_KIND_CONNECT4,
            if verdict == POLICY_DENY {
                VERDICT_DENY
            } else {
                VERDICT_ALLOW
            },
        ),
        saddr: 0,
        daddr,
        dport,
        protocol: 0,
    };
    if let Some(mut entry) = EVENTS.reserve::<Connect4Event>(0) {
        entry.write(ev);
        entry.submit(0);
    }
    let _ = &mut ev;

    if settings().mode == 1 && verdict == POLICY_DENY { 0 } else { 1 }
}

#[cgroup_sock_addr(connect6)]
pub fn coronarium_connect6(ctx: SockAddrContext) -> i32 {
    let user = unsafe { &*ctx.sock_addr };
    let mut daddr = [0u8; 16];
    unsafe {
        let raw = (*user).user_ip6;
        for (i, w) in raw.iter().enumerate() {
            let b = w.to_ne_bytes();
            daddr[i * 4..i * 4 + 4].copy_from_slice(&b);
        }
    }
    let dport = unsafe { (*user).user_port as u16 };

    let verdict = lookup_net6(&daddr, dport);
    let ev = Connect6Event {
        header: fill_header(
            EVENT_KIND_CONNECT6,
            if verdict == POLICY_DENY {
                VERDICT_DENY
            } else {
                VERDICT_ALLOW
            },
        ),
        saddr: [0; 16],
        daddr,
        dport,
        protocol: 0,
        _pad: 0,
    };
    if let Some(mut entry) = EVENTS.reserve::<Connect6Event>(0) {
        entry.write(ev);
        entry.submit(0);
    }
    if settings().mode == 1 && verdict == POLICY_DENY { 0 } else { 1 }
}

fn lookup_net4(addr_be: u32, port_be: u16) -> u8 {
    // Try exact (addr, port), then wildcard port, then default.
    let key = Ipv4Key { addr: addr_be, port: port_be, _pad: 0 };
    if let Some(v) = unsafe { NET4.get(&key) } {
        return *v;
    }
    let wildcard = Ipv4Key { addr: addr_be, port: 0, _pad: 0 };
    if let Some(v) = unsafe { NET4.get(&wildcard) } {
        return *v;
    }
    settings().net_default as u8
}

fn lookup_net6(addr: &[u8; 16], port_be: u16) -> u8 {
    let key = Ipv6Key { addr: *addr, port: port_be, _pad: [0; 6] };
    if let Some(v) = unsafe { NET6.get(&key) } {
        return *v;
    }
    let wildcard = Ipv6Key { addr: *addr, port: 0, _pad: [0; 6] };
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
