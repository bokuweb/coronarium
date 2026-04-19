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
  # default is `deny`, so only listed destinations can be reached.
  allow:
    - target: api.github.com   # hostname resolved at startup
      ports: [443]
    - target: 140.82.112.0/20  # CIDR expanded (up to /16 for v4)
      ports: [22, 443]
    - target: 2606:4700::/48   # IPv6 CIDRs work too
      ports: [443]

file:
  # Most builds open hundreds of files; flip to allow-by-default and
  # use `deny` for the handful of things you want to protect.
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

### Defaults

**Every section defaults to `deny`.** If you omit `default:`, anything not
listed under `allow:` is denied. `file.default` likewise defaults to `deny`
— but because most builds touch hundreds of files, you almost certainly
want `file.default: allow` explicitly and use `file.deny:` for secrets.

First-time setup pattern:

1. Start with `mode: audit` (or pass `--mode audit` on the CLI). Nothing is
   blocked; everything is logged.
2. Run your real job once and inspect the JSON log / step summary.
3. Add the destinations / paths you actually need to `allow:`.
4. Flip to `mode: block` once the log is clean.

The full parsed shape is what `coronarium check-policy` prints.

## GitHub Actions

The action works on Linux **and** Windows runners — same inputs, same
env contract, OS-specific binary picked automatically:

```yaml
# .github/workflows/build.yml
name: build
on: [push]

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      # Installs the right binary for this runner's OS. `@v0` is a floating
      # tag that tracks the newest v0.x.y across platforms.
      - uses: bokuweb/coronarium@v0
        with:
          policy: .github/coronarium.yml
          mode: audit

      # Wrap your real command with `coronarium run`. The install step
      # exported CORONARIUM_BIN / CORONARIUM_POLICY / CORONARIUM_MODE /
      # CORONARIUM_LOG so you don't need to repeat them here.
      # Linux (needs sudo for CAP_BPF):
      - if: runner.os == 'Linux'
        run: |
          sudo -E "$CORONARIUM_BIN" run \
            --policy  "$CORONARIUM_POLICY" \
            --mode    "$CORONARIUM_MODE" \
            --log     "$CORONARIUM_LOG" \
            --summary "$GITHUB_STEP_SUMMARY" \
            -- cargo test

      # Windows (already elevated; no sudo):
      - if: runner.os == 'Windows'
        shell: pwsh
        run: |
          & $env:CORONARIUM_BIN `
            --policy  $env:CORONARIUM_POLICY `
            --mode    $env:CORONARIUM_MODE `
            --log     $env:CORONARIUM_LOG `
            --summary $env:GITHUB_STEP_SUMMARY `
            -- cargo test

      # Optional: attach the JSON log as an artifact for later inspection.
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: coronarium-log-${{ runner.os }}
          path: coronarium.log.json
```

Install step inputs:

| input     | default                    | description |
|---         |---                         |--- |
| `policy`   | `.github/coronarium.yml`   | policy file path |
| `mode`     | `audit`                    | overrides `mode:` in the policy |
| `version`  | the action ref (e.g. `v0`) | release tag to download |
| `log`      | `coronarium.log.json`      | where the subsequent `coronarium run` step should log |

Install step outputs:

| output | description |
|---|---|
| `bin`  | path to the installed `coronarium` binary |
| `bpf`  | path to the installed `coronarium.bpf.o` |

A human-readable summary is appended to `$GITHUB_STEP_SUMMARY` when you
pass `--summary`. Full JSON events go to `--log`.

### HTML report (modern, self-contained)

Pass `--html <path>` to `coronarium run` and you get a single-file HTML
report — no external CSS/JS, dark-mode aware, with a filter box and
tabs for Exec / Open / Connect / Denied-only. Upload it as a workflow
artifact and open straight from `file://`.

```yaml
- run: |
    sudo -E "$CORONARIUM_BIN" run \
      --policy .github/coronarium.yml \
      --log coronarium.log.json \
      --html coronarium-report.html \
      -- cargo test

- uses: actions/upload-artifact@v4
  with:
    name: coronarium-report
    path: |
      coronarium-report.html
      coronarium.log.json
```

### Posting the report as a PR comment

`bokuweb/coronarium/comment@v0` reads the JSON log and upserts a single
pull-request comment (keyed by an HTML marker, so re-runs edit in place
instead of appending). Pass the artifact name and it also embeds a
ready-to-paste `gh` one-liner that downloads + opens the HTML report on
your machine:

```yaml
- uses: bokuweb/coronarium/comment@v0
  if: github.event_name == 'pull_request'
  with:
    log: coronarium.log.json
    artifact-name: coronarium-report        # same name used in upload-artifact
    html-filename: coronarium-report.html   # inside the artifact
    # fail-on-denied: "true"                # optional: exit non-zero when denied > 0
```

The resulting PR comment looks like:

> ### coronarium report
>
> | metric | count |
> |---|---:|
> | observed | **91** |
> | denied   | **1**  |
> | lost     | 0      |
>
> <details><summary>📊 <b>Open the full HTML report locally</b></summary>
>
> ```bash
> rm -rf /tmp/coronarium-12345678 && gh run download 12345678 -R owner/repo -n coronarium-report -D /tmp/coronarium-12345678 && (open /tmp/coronarium-12345678/coronarium-report.html 2>/dev/null || xdg-open /tmp/coronarium-12345678/coronarium-report.html 2>/dev/null || echo "open file:///tmp/coronarium-12345678/coronarium-report.html")
> ```
>
> The destination is scoped by run-id and cleared first, so re-running the
> same line doesn't trip on `file exists` and different PRs don't clobber
> each other.
>
> </details>

Comment step inputs:

| input | default | description |
|---|---|---|
| `log` | `coronarium.log.json` | JSON log written by `coronarium run` |
| `marker` | `<!-- coronarium-report -->` | HTML marker used for upsert |
| `fail-on-denied` | `false` | if `true`, exit non-zero after posting when `denied > 0` |
| `title` | `coronarium report` | heading shown at the top of the comment |
| `artifact-name` | *(empty)* | name of the HTML artifact; when set, the comment embeds a `gh` download one-liner |
| `html-filename` | `coronarium-report.html` | file name inside the artifact |

The step needs `pull-requests: write` in `permissions:` (or the default
`GITHUB_TOKEN` with that scope).

### Runner requirements

| runner | supported | notes |
|---|---|---|
| `ubuntu-latest`, `ubuntu-22.04`, `ubuntu-24.04` | ✅ | eBPF (cgroup/connect, tracepoints, ringbuf); canonical target |
| `ubuntu-24.04-arm` | ✅ | same featureset, aarch64 binary ships in each release |
| `windows-latest` | ✅ | ETW public providers; runs elevated by default |
| `windows-2022`, `windows-2019` | ⚠️ | probably works but not smoke-tested yet |
| container jobs (`container:` key on Linux) | ⚠️ | needs `--privileged` + host cgroup mount |
| self-hosted Linux | ⚠️ | requires passwordless `sudo`, kernel ≥ 5.13, tracepoints + bpf exposed |
| self-hosted Windows | ⚠️ | requires Administrator (for ETW kernel provider subscription) |
| macOS | ❌ | action exits early on any non-Linux/Windows runner |

Linux path needs: kernel ≥ 5.13 (cgroup v2, ringbuf), `CAP_BPF` +
`CAP_SYS_ADMIN` via `sudo`, cgroup v2 unified hierarchy at
`/sys/fs/cgroup`.

Windows path needs: Administrator (hosted runners are elevated by
default). Uses the `Microsoft-Windows-Kernel-Process`,
`-Kernel-Network`, and `-Kernel-File` public ETW providers — no kernel
driver install, no signing.

If the BPF programs fail to attach (typically a kernel-config or
capabilities issue), `coronarium run` logs a warning and falls through to
**passthrough mode** — the supervised command still runs, but no
events are captured. Watch for `eBPF attach failed, running in passthrough`
in the step log.

## Supply-chain: `deps check` (minimum release age)

Supply-chain attacks typically live in the gap between a malicious
version being published to a registry and the community detecting + yanking
it (usually 24–72 hours). If your CI only ever installs packages older
than N days, you dodge most of that window.

`pnpm` has [`minimumReleaseAge`](https://pnpm.io/next/settings#minimumreleaseage)
for exactly this. coronarium offers the same idea, **cross-ecosystem**
and **cross-platform** (Linux + Windows), as a lockfile-level check you
can run before `npm install` / `cargo build` / etc.

```bash
# Fail if any resolved dep was published less than 7 days ago.
coronarium deps check --min-age 7d Cargo.lock package-lock.json

# Different thresholds per ecosystem? Run twice.
coronarium deps check --min-age 14d Cargo.lock
coronarium deps check --min-age  3d package-lock.json

# Ignore first-party packages you publish yourself.
coronarium deps check --min-age 7d --ignore '@my-org/*' package-lock.json

# Machine-readable output for CI gating.
coronarium deps check --min-age 7d --format json Cargo.lock
```

| ecosystem | lockfile | registry |
|---|---|---|
| cargo | `Cargo.lock` | crates.io `/api/v1/crates/<name>` |
| npm | `package-lock.json` (lockfileVersion ≥ 2) | registry.npmjs.org |
| pypi | `uv.lock`, `poetry.lock`, `requirements.txt` (exact `==` pins only) | pypi.org `/pypi/<name>/<version>/json` |
| nuget | `packages.lock.json` (central-package-management) | api.nuget.org `/v3/registration5-{semver1,gz-semver2}/…` |

Exit codes: `0` = all packages meet the threshold, `1` = at least one
violation, `2` = parse/I/O error. A single on-disk cache at
`$XDG_CACHE_HOME/coronarium/deps-cache.json` (or `%LOCALAPPDATA%\coronarium\…`
on Windows) keeps repeated runs fast; publish dates are immutable so
there's no TTL.

Typical GitHub Actions shape:

```yaml
- uses: bokuweb/coronarium@v0
- run: $CORONARIUM_BIN deps check --min-age 7d Cargo.lock
- run: cargo test   # only reached if the check passed
```

## Limitations

Honesty about what this does and doesn't do — per-OS:

### Linux

- **Network block works at the kernel**: `default: deny` makes
  `connect(2)` return `EPERM` via a `cgroup/connect4|6` BPF program.
- **File block is "tripwire"**: the first `file.deny` entries
  (up to 8, up to 60 bytes each) are installed into a kernel-side
  prefix map. A matching `openat(2)` in `mode: block` triggers
  `bpf_send_signal(SIGKILL)` on the offending process — the file
  descriptor may briefly exist but the process dies before consuming
  it, and coronarium exits non-zero. Entries beyond the cap (or
  patterns longer than 60 bytes) fall through to userspace-only
  audit tagging.
- **Exec block is audit-only**: `process.deny_exec` tags matching
  events as `denied: true` in the JSON log and makes `mode: block`
  exit non-zero, but the child is not prevented from exec'ing.
  Kernel-side exec block would need `bpf_override_return` (kernel
  config dependent); roadmap.

### Windows

- **Network deny is kernel-enforced** for IP literals / CIDRs /
  hostnames via dynamic Windows Defender Firewall rules created by
  `New-NetFirewallRule -Program <child.exe> -Direction Outbound
  -Action Block`. Rules are scoped by child-exe path and by a per-PID
  display-name prefix, and cleaned up via RAII on exit.
- **Network `default: deny` with `allow: [...]` is audit-only on
  Windows.** Windows FW's rule evaluation is "block wins over allow",
  so an allowlist pattern can't be expressed without flipping the
  system-wide default outbound to `Block`, which would affect the
  rest of the runner. Use `network.deny: [...]` for enforcement.
- **File / exec block is audit-only** (same as Linux).

### Both

- **Hostname resolution is one-shot** at startup. DNS rebinds during
  the run won't be tracked.
- **Ring-buffer / ETW overflow** is counted as `lost`; the summary
  surfaces a warning when `lost > 0`.

## Troubleshooting

**`eBPF attach failed, running in passthrough`**
: The verifier rejected a program or you don't have `CAP_BPF`. Check
  that the job runs as root (or has the caps) and the kernel exposes
  `CONFIG_BPF_SYSCALL=y`. The full verifier log goes to stderr.

**`observed: 0` in the JSON log**
: Either (a) BPF didn't load (see above), or (b) the child exited so
  quickly that the ringbuf drain missed events. Try a longer-running
  command first to isolate the cause.

**`cgroup creation failed (…); network policy will be degraded`**
: The runner doesn't have cgroup v2 at the expected path. Network
  policy won't apply; file/exec audit will still work because those
  are attached globally via tracepoints.

**Child exits 0 but `denied > 0`**
: Expected in `mode: audit` — events are tagged denied but not
  enforced. Switch to `mode: block` to make the wrapper exit non-zero
  (the child itself still runs for file/exec; see Limitations).

## Modes

**`audit`** — everything is allowed; denied events are logged but the
program is not interrupted. Use this first to validate the rule set
without breaking builds. If eBPF programs fail to attach (kernel /
capability issue), coronarium falls back to passthrough and prints a
warning, but the child still runs.

**`block`** — the cgroup program returns `EPERM` for denied connects,
so the child sees `Connection refused`. File / exec block requires
`bpf_override_return` and is on the roadmap (see Limitations).

### How block mode fails CI

`coronarium run --mode block` exits non-zero and emits a GitHub Actions
`::error::` annotation in **two** situations, either of which fails the
step (and therefore the job):

1. **Policy violation observed.** `denied > 0` → exit 1. Works even
   when the denial is audit-only (file / exec), so forgotten `file.deny`
   rules still break the build.
2. **eBPF programs couldn't attach.** In block mode coronarium refuses
   to run unprotected; it returns an error instead of silently falling
   back to passthrough. This prevents a misconfigured kernel / missing
   `CAP_BPF` from giving you a false sense of security. (Audit mode
   still passes through in this case, by design — so you can at least
   run the diagnostic.)

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
