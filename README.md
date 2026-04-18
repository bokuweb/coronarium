# coronarium

eBPF-based audit & block for CI workloads, written in Rust with [aya].

`coronarium` wraps a build/test command and, via eBPF programs attached to a
dedicated cgroup v2, observes (and optionally denies) its:

- **Network** — outbound `connect(2)` on IPv4 and IPv6
- **File** — `openat(2)` (audit; deny is on the roadmap)
- **Process** — `execve(2)` (audit; deny is on the roadmap)

It can run locally as a CLI, or be installed into a GitHub Actions workflow
as a composite action.

> **Platform:** Linux only (eBPF). macOS / Windows builds compile as a
> passthrough supervisor for development convenience.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ user command (your build / test step)                            │
│         │                                                        │
│         │ enrolled via pre_exec into                             │
│         ▼                                                        │
│ /sys/fs/cgroup/coronarium.slice/<uuid>                           │
│         │                                                        │
│  attach │ cgroup/connect4, cgroup/connect6                       │
│         │                                                        │
│  attach │ tracepoint:syscalls:sys_enter_execve                   │
│         │ tracepoint:syscalls:sys_enter_openat                   │
└─────────┼────────────────────────────────────────────────────────┘
          │  ring buffer (EVENTS)
          ▼
  coronarium (userspace)  ──►  JSON audit log + $GITHUB_STEP_SUMMARY
```

Crates:

- `coronarium` — userspace CLI and supervisor
- `coronarium-ebpf` — kernel programs, built for `bpfel-unknown-none`
- `coronarium-common` — POD structs shared across both sides

## Installation

### Pre-built release (Linux x86_64)

```bash
curl -fsSL https://github.com/bokuweb/coronarium/releases/latest/download/coronarium-x86_64-unknown-linux-musl.tar.gz \
  | sudo tar -xz -C /usr/local/bin
```

The archive contains the `coronarium` binary and the `coronarium.bpf.o` ELF.

### From source

Userspace:

```bash
cargo build --release -p coronarium
```

eBPF object (requires nightly + `bpf-linker`):

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd crates/coronarium-ebpf
RUSTUP_TOOLCHAIN=nightly cargo build --release \
  --target bpfel-unknown-none -Z build-std=core
```

Export `CORONARIUM_BPF_OBJ` to the resulting ELF before running:

```bash
export CORONARIUM_BPF_OBJ=$(pwd)/target/bpfel-unknown-none/release/coronarium
```

## Usage

```bash
coronarium run \
  --policy .github/coronarium.yml \
  --mode audit \
  --log coronarium.log.json \
  -- cargo test
```

Validate a policy without attaching anything:

```bash
coronarium check-policy -p .github/coronarium.yml
```

Flags:

| flag | env | default | description |
|---|---|---|---|
| `--policy` / `-p` | `CORONARIUM_POLICY` | — | policy file (YAML or JSON) |
| `--mode` | — | from policy | `audit` or `block` — overrides the policy's `mode:` |
| `--log` | — | `-` (stdout) | JSON audit log destination |
| `--summary` | `GITHUB_STEP_SUMMARY` | — | markdown summary output |

Exit code: the child's exit code, unless `mode=block` and at least one
event was denied, in which case coronarium exits `1`.

## Policy format

YAML or JSON. Fields are optional; missing sections default to
"allow-everything, audit-only".

```yaml
# .github/coronarium.yml
mode: block                    # audit | block

network:
  default: deny                # allow | deny
  allow:
    - target: api.github.com   # hostname resolved at startup
      ports: [443]
    - target: 140.82.112.0/20  # CIDR expanded (up to /16 for v4)
      ports: [22, 443]
    - target: 2606:4700::/48   # IPv6 CIDRs work too
      ports: [443]
  deny:
    - target: 169.254.169.254  # metadata service
      ports: [80, 443]

file:
  default: allow
  deny:
    - /etc/shadow
    - /root/.ssh

process:
  deny_exec:
    - /usr/bin/nc
```

Rule resolution:

- `target` can be a **hostname** (A + AAAA both expanded), an **IPv4 or IPv6
  literal**, or a **CIDR block**
- `ports` is optional; empty list means "any port"
- `deny` overrides `allow` when the same (addr, port) appears on both lists
- `default` decides unmatched traffic

The full parsed shape is what `coronarium check-policy` prints.

## GitHub Actions

Reference the composite action directly:

```yaml
# .github/workflows/build.yml
name: build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bokuweb/coronarium@v0  # installs coronarium + starts daemon
        with:
          policy: .github/coronarium.yml
          mode: audit
      - run: cargo test
```

Inputs:

| input | default | description |
|---|---|---|
| `policy` | `.github/coronarium.yml` | path to the policy file |
| `mode`   | `audit` | overrides `mode:` in the policy |
| `version`| `latest` | coronarium release tag to install |
| `log`    | `coronarium.log.json` | JSON log destination |

A human-readable summary is automatically appended to
`$GITHUB_STEP_SUMMARY`. Full JSON events are written to `log` and can be
uploaded as an artifact.

> `ubuntu-latest` runners have `CAP_BPF` / `CAP_SYS_ADMIN` via `sudo`, which
> the action uses internally. Container / self-hosted runners need the
> same privileges.

## Modes

**`audit`** — everything is allowed; denied events are logged but the
program is not interrupted. Use this first to validate the rule set
without breaking builds.

**`block`** — the cgroup program returns `EPERM` for denied connects, so
the child sees `Connection refused`. File / exec block requires
`bpf_override_return` and is on the roadmap.

## Development

```bash
# userspace tests + lint
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# eBPF object
cd crates/coronarium-ebpf
RUSTUP_TOOLCHAIN=nightly cargo build --release \
  --target bpfel-unknown-none -Z build-std=core
```

On macOS everything except the `bpfel-unknown-none` target compiles, so you
can iterate on the userspace CLI locally; the supervisor just runs the
child process without attaching BPF.

See [PLAN.md](PLAN.md) for the design and current roadmap.

## Roadmap

- File path prefix map + kernel-side deny
- `bpf_override_return` for exec / openat deny
- `cargo-dist` release pipeline (musl static + bpf.o)
- LSM BPF variant for distros that ship it

## License

MIT OR Apache-2.0.

[aya]: https://github.com/aya-rs/aya
