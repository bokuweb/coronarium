//! Bridge parsed [`Policy`] → eBPF maps and attach kernel programs.
//! Linux-only; other targets compile a placeholder.

use crate::{cgroup::Cgroup, policy::Policy, resolve::Resolver};

#[allow(dead_code)]
pub struct Enforcer;

#[cfg(target_os = "linux")]
impl Enforcer {
    pub async fn attach(
        bpf: &mut aya::Ebpf,
        policy: &Policy,
        cgroup: Option<&Cgroup>,
        resolver: &Resolver,
    ) -> anyhow::Result<()> {
        use anyhow::Context as _;

        if let Some(prog) = bpf.program_mut("coronarium_execve") {
            let tp: &mut aya::programs::TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("syscalls", "sys_enter_execve")
                .context("attaching sys_enter_execve")?;
        }

        if let Some(prog) = bpf.program_mut("coronarium_openat") {
            let tp: &mut aya::programs::TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("syscalls", "sys_enter_openat")
                .context("attaching sys_enter_openat")?;
        }

        if let Some(cgroup) = cgroup {
            let fd = cgroup.as_file()?;
            for name in ["coronarium_connect4", "coronarium_connect6"] {
                if let Some(prog) = bpf.program_mut(name) {
                    let cg: &mut aya::programs::CgroupSockAddr = prog.try_into()?;
                    cg.load()?;
                    cg.attach(&fd, aya::programs::CgroupAttachMode::Single)
                        .with_context(|| format!("attaching {name}"))?;
                }
            }
        }

        populate_network_maps(bpf, policy, resolver).await?;
        populate_file_maps(bpf, policy)?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl Enforcer {
    pub async fn attach(
        _bpf: &mut (),
        _policy: &Policy,
        _cgroup: Option<&Cgroup>,
        _resolver: &Resolver,
    ) -> anyhow::Result<()> {
        anyhow::bail!("Enforcer::attach only runs on Linux")
    }
}

#[cfg(target_os = "linux")]
async fn populate_network_maps(
    bpf: &mut aya::Ebpf,
    policy: &Policy,
    resolver: &Resolver,
) -> anyhow::Result<()> {
    use std::net::IpAddr;

    use coronarium_common::{Ipv4Key, Ipv6Key, POLICY_ALLOW, POLICY_DENY};

    // Pre-resolve every rule's endpoints *before* touching the maps so that a
    // transient DNS failure doesn't leave half-populated state.
    let allow = resolve_all(resolver, &policy.network.allow).await;
    let deny = resolve_all(resolver, &policy.network.deny).await;

    // deny wins if the same (addr, port) appears on both lists.
    if let Some(map) = bpf.map_mut("NET4") {
        let mut m: aya::maps::HashMap<_, Ipv4Key, u8> = aya::maps::HashMap::try_from(map)?;
        for (ep, verdict) in allow
            .iter()
            .map(|e| (e, POLICY_ALLOW))
            .chain(deny.iter().map(|e| (e, POLICY_DENY)))
        {
            if let IpAddr::V4(v4) = ep.addr {
                let key = Ipv4Key {
                    addr: u32::from(v4).to_be(),
                    port: ep.port.to_be(),
                    _pad: 0,
                };
                m.insert(key, verdict, 0)?;
            }
        }
    }

    if let Some(map) = bpf.map_mut("NET6") {
        let mut m: aya::maps::HashMap<_, Ipv6Key, u8> = aya::maps::HashMap::try_from(map)?;
        for (ep, verdict) in allow
            .iter()
            .map(|e| (e, POLICY_ALLOW))
            .chain(deny.iter().map(|e| (e, POLICY_DENY)))
        {
            if let IpAddr::V6(v6) = ep.addr {
                let key = Ipv6Key {
                    addr: v6.octets(),
                    port: ep.port.to_be(),
                    _pad: [0; 6],
                };
                m.insert(key, verdict, 0)?;
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn resolve_all(
    resolver: &Resolver,
    rules: &[crate::policy::NetRule],
) -> Vec<crate::resolve::Endpoint> {
    let mut out = Vec::new();
    for rule in rules {
        match resolver.expand(rule).await {
            Ok(mut eps) => out.append(&mut eps),
            Err(err) => log::warn!("resolving {}: {err:#}", rule.target),
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn populate_file_maps(bpf: &mut aya::Ebpf, policy: &Policy) -> anyhow::Result<()> {
    use coronarium_common::{FILE_DENY_MAX_ENTRIES, FILE_DENY_PREFIX_LEN, FileDenyPrefix};

    // Mirror the first `FILE_DENY_MAX_ENTRIES` policy.file.deny entries
    // into the kernel-side FILE_DENY_PREFIX map. Matches there trigger
    // bpf_send_signal(SIGKILL) on the offending process (in block mode).
    // Beyond this cap, entries still fire `denied: true` tags via the
    // userspace FileMatcher but won't kill the child.
    let Some(map) = bpf.map_mut("FILE_DENY_PREFIX") else {
        // Older BPF ELFs may not include this map; skip silently.
        return Ok(());
    };
    let mut m: aya::maps::Array<_, FileDenyPrefix> = aya::maps::Array::try_from(map)?;

    // Pre-compute zero'd entries for every slot so stale rules from a
    // re-used map don't match.
    let empty = FileDenyPrefix {
        len: 0,
        bytes: [0; FILE_DENY_PREFIX_LEN],
    };
    for i in 0..FILE_DENY_MAX_ENTRIES {
        m.set(i, empty, 0)?;
    }

    let mut idx: u32 = 0;
    for pat in &policy.file.deny {
        if idx >= FILE_DENY_MAX_ENTRIES {
            log::warn!(
                "file.deny has more than {FILE_DENY_MAX_ENTRIES} entries — remaining are \
                 audit-tagged only, not kernel-blocked."
            );
            break;
        }
        let bytes = pat.as_bytes();
        if bytes.len() > FILE_DENY_PREFIX_LEN {
            log::warn!(
                "file.deny entry {:?} exceeds kernel prefix cap ({} bytes); only the first \
                 {} bytes are enforced in-kernel (userspace match still covers the full string).",
                pat,
                bytes.len(),
                FILE_DENY_PREFIX_LEN
            );
        }
        let n = bytes.len().min(FILE_DENY_PREFIX_LEN);
        let mut entry = FileDenyPrefix {
            len: n as u32,
            bytes: [0; FILE_DENY_PREFIX_LEN],
        };
        entry.bytes[..n].copy_from_slice(&bytes[..n]);
        m.set(idx, entry, 0)?;
        idx += 1;
    }
    log::info!(
        "populated {idx}/{FILE_DENY_MAX_ENTRIES} file-deny prefix slots for kernel-side block"
    );
    Ok(())
}
