//! Userspace supervisor: loads the eBPF object, attaches programs, creates a
//! cgroup, spawns the child inside it, and drains the shared ring buffer.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{process::Command, sync::Mutex};

use crate::{
    cgroup::Cgroup,
    events::{self, Event},
    policy::{Mode, Policy},
    resolve::Resolver,
};

#[cfg(target_os = "linux")]
use crate::enforcer::Enforcer;

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub observed: u64,
    pub denied: u64,
    pub lost: u64,
    pub samples: Vec<Event>,
}

pub struct Supervisor {
    policy: Policy,
    mode: Mode,
    stats: Arc<Mutex<Stats>>,
    stop: Arc<AtomicBool>,
    cgroup: Option<Cgroup>,

    // On Linux we keep the loaded BPF object alive so maps + links persist
    // for the lifetime of the supervisor.
    #[cfg(target_os = "linux")]
    bpf: Option<Arc<Mutex<aya::Ebpf>>>,
}

impl Supervisor {
    pub async fn start(policy: Policy, mode: Mode) -> Result<Self> {
        let stats = Arc::new(Mutex::new(Stats::default()));
        let stop = Arc::new(AtomicBool::new(false));

        let cgroup = match Cgroup::create() {
            Ok(c) => Some(c),
            Err(err) => {
                log::warn!("cgroup creation failed ({err:#}); network policy will be degraded");
                None
            }
        };

        #[cfg(target_os = "linux")]
        let bpf = {
            let resolver = Resolver::from_system()?;
            match load_bpf(&policy, mode, cgroup.as_ref(), &resolver).await {
                Ok(b) => Some(Arc::new(Mutex::new(b))),
                Err(err) => {
                    log::warn!("eBPF attach failed, running in passthrough: {err:#}");
                    None
                }
            }
        };

        #[cfg(not(target_os = "linux"))]
        let _ = Resolver::from_system; // silence unused warning

        let this = Self {
            policy,
            mode,
            stats: stats.clone(),
            stop: stop.clone(),
            cgroup,
            #[cfg(target_os = "linux")]
            bpf: bpf.clone(),
        };

        #[cfg(target_os = "linux")]
        if let Some(bpf) = bpf {
            spawn_ringbuf_drain(bpf, stats, stop);
        }

        Ok(this)
    }

    pub async fn run_child(&self, argv: &[String]) -> Result<i32> {
        let (program, rest) = argv
            .split_first()
            .context("internal error: empty command after clap parse")?;

        let cgroup_path = self.cgroup.as_ref().map(|c| c.path.clone());

        let mut cmd = Command::new(program);
        cmd.args(rest);

        // Enroll the child into our cgroup *before* it execs. On Linux we use
        // pre_exec; other platforms just run the command unconfined.
        #[cfg(target_os = "linux")]
        if let Some(path) = cgroup_path.clone() {
            // tokio::process::Command re-exports pre_exec directly — no trait
            // import needed.
            unsafe {
                cmd.pre_exec(move || {
                    let procs = path.join("cgroup.procs");
                    let pid = std::process::id();
                    std::fs::write(&procs, pid.to_string().as_bytes())?;
                    Ok(())
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cgroup_path;

        let status = cmd
            .status()
            .await
            .with_context(|| format!("spawning {program}"))?;
        Ok(status.code().unwrap_or(1))
    }

    pub async fn shutdown(self) -> Result<Stats> {
        self.stop.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(self.stats.lock().await.clone())
    }

    #[allow(dead_code)]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    #[allow(dead_code)]
    pub fn mode(&self) -> Mode {
        self.mode
    }
}

// aya requires its own marker trait `aya::Pod` on map key/value types; the
// trait is unsafe and only implemented for primitives by default. Our shared
// structs are `#[repr(C)]` POD (already `bytemuck::Pod`), so it is safe.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for coronarium_common::Ipv4Key {}
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for coronarium_common::Ipv6Key {}
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for coronarium_common::Settings {}

#[cfg(target_os = "linux")]
async fn load_bpf(
    policy: &Policy,
    mode: Mode,
    cgroup: Option<&Cgroup>,
    resolver: &Resolver,
) -> Result<aya::Ebpf> {
    let path = std::env::var("CORONARIUM_BPF_OBJ")
        .context("CORONARIUM_BPF_OBJ is not set; build the eBPF crate and point to the .o")?;
    let mut bpf = aya::Ebpf::load_file(&path).with_context(|| format!("loading {path}"))?;

    if let Err(err) = aya_log::EbpfLogger::init(&mut bpf) {
        log::debug!("aya_log init skipped: {err}");
    }

    if let Some(map) = bpf.map_mut("SETTINGS") {
        let mut settings_map: aya::maps::Array<_, coronarium_common::Settings> =
            aya::maps::Array::try_from(map)?;
        let encoded = coronarium_common::Settings {
            mode: match mode {
                Mode::Audit => 0,
                Mode::Block => 1,
            },
            net_default: default_to_u32(policy.network.default),
            file_default: default_to_u32(policy.file.default),
            exec_default: coronarium_common::POLICY_ALLOW as u32,
        };
        settings_map.set(0, encoded, 0)?;
    }

    Enforcer::attach(&mut bpf, policy, cgroup, resolver)
        .await
        .context("attaching programs")?;
    Ok(bpf)
}

#[cfg(target_os = "linux")]
fn default_to_u32(d: crate::policy::DefaultDecision) -> u32 {
    match d {
        crate::policy::DefaultDecision::Allow => coronarium_common::POLICY_ALLOW as u32,
        crate::policy::DefaultDecision::Deny => coronarium_common::POLICY_DENY as u32,
    }
}

#[cfg(target_os = "linux")]
fn spawn_ringbuf_drain(
    bpf: Arc<Mutex<aya::Ebpf>>,
    stats: Arc<Mutex<Stats>>,
    stop: Arc<AtomicBool>,
) {
    tokio::task::spawn(async move {
        // Take the ring buffer out of the map collection exactly once.
        let ring = {
            let mut guard = bpf.lock().await;
            match guard.take_map("EVENTS") {
                Some(m) => aya::maps::RingBuf::try_from(m).ok(),
                None => None,
            }
        };
        let Some(mut ring) = ring else {
            log::warn!("EVENTS ringbuf not found; drain task exiting");
            return;
        };

        while !stop.load(Ordering::SeqCst) {
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                let mut s = stats.lock().await;
                ingest(&mut s, bytes);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

pub(crate) fn ingest(stats: &mut Stats, raw: &[u8]) {
    match events::decode(raw) {
        Some(ev) => {
            stats.observed += 1;
            if ev.denied() {
                stats.denied += 1;
            }
            if stats.samples.len() < 256 {
                stats.samples.push(ev);
            }
        }
        None => {
            stats.lost += 1;
        }
    }
}
