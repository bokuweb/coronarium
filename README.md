# coronarium

**Stop your team from pulling a 2-hour-old crate.** A cross-ecosystem
supply-chain guard, written in Rust, that gives every package manager
on your machine pnpm's `minimumReleaseAge` semantics — transparently,
without any resolver integration.

```bash
$ coronarium proxy install-ca              # trust the proxy's root CA
$ coronarium proxy install-daemon          # run the proxy in the background
$ coronarium install-gate install          # route your shell through it

# Open a new shell. Business as usual.
$ npm install react
# → proxy silently drops versions < 7d old, npm picks the newest older version
# → no error, no broken build, just a measurably safer dependency.
```

Four ecosystems are covered today, end-to-end:

| ecosystem | silent auto-fallback via proxy | tarball hard-deny |
|---|---|---|
| **crates.io** | ✅ sparse-index rewrite | ✅ |
| **npm** | ✅ packument rewrite (+ `dist-tags.latest` retargeted) | ✅ |
| **pypi** | ✅ JSON API + PEP 691 Simple JSON | ✅ |
| **nuget** | ✅ registration-page rewrite | ✅ |

Supply-chain attacks typically live in the 24–72h gap between a
malicious version being published and the community catching it. If
your installs only ever see versions older than that window, you dodge
most of them. [pnpm 10.x ships this](https://pnpm.io/next/settings#minimumreleaseage)
for npm only — coronarium brings the same thing to every major
ecosystem, as a single HTTPS proxy the package managers already trust.

## Quick start (desktop — macOS / Linux)

```bash
# 1. Install (prebuilt binary). Replace $TRIPLE with your platform, e.g.
#    aarch64-apple-darwin / x86_64-apple-darwin / x86_64-unknown-linux-musl.
curl -fsSL "https://github.com/bokuweb/coronarium/releases/latest/download/coronarium-$TRIPLE.tar.gz" \
  | sudo tar -xz -C /usr/local/bin

# 2. Generate the proxy's root CA, install into the system trust store.
coronarium proxy install-ca
# (prompts for sudo — we use the OS `security` / `update-ca-certificates`
#  CLI, auditable and reversible with the same commands.)

# 3. Run the proxy as a background daemon (launchd on macOS, systemd
#    --user on Linux) so it's always up.
coronarium proxy install-daemon
# Follow the printed `launchctl bootstrap …` / `systemctl --user enable --now`
# line.

# 4. Wire your shell so every new terminal picks up HTTPS_PROXY + the CA.
coronarium install-gate install

# 5. Open a new shell. Done.
$ env | grep HTTPS_PROXY
HTTPS_PROXY=http://127.0.0.1:8910
```

From here, `npm install` / `pnpm add` / `yarn add` / `cargo add` /
`cargo build` / `pip install` / `uv add` / `poetry add` / `dotnet add
package` / `dotnet restore` all go through the proxy and silently get
the fallback treatment.

## What "silent fallback" actually means

Concretely, for `crates.io` the proxy rewrites the sparse-index
response to drop JSONL lines whose `pubtime` is younger than
`--min-age`:

```
$ curl -s https://index.crates.io/se/rd/serde | wc -l           # direct
315
$ coronarium proxy start --min-age 365d &
$ curl -s -x http://127.0.0.1:8910 https://index.crates.io/se/rd/serde | wc -l
306     # the 9 most recent versions are now invisible to cargo's resolver
```

cargo then picks the newest remaining in-range version — **no error**,
just a slightly older (and harder-to-attack) dependency. Same shape
for npm's packument (where `dist-tags.latest` is also retargeted to
the highest remaining semver so bare `npm install <pkg>` doesn't
resolve to a removed version), PyPI's JSON API + PEP 691 Simple JSON,
and NuGet's registration pages.

For unhandled paths (direct tarball pinning, etc.) the proxy returns
`403` with an `x-coronarium-deny` header so the install stops loudly.

## In CI (GitHub Actions)

```yaml
# .github/workflows/build.yml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Route every HTTPS request from later steps through the proxy.
      # Versions published less than 7 days ago are invisible to your
      # resolver, so `cargo build` / `npm install` / `pip install` /
      # `dotnet restore` silently pick the newest older version.
      - uses: bokuweb/coronarium/proxy@v0
        with:
          min-age: 7d

      - run: cargo test      # flows through the proxy
      - run: npm ci          # ditto
```

Prefer running the proxy yourself (Kubernetes, docker-compose,
internal infra)? A prebuilt image lives on GHCR:

```bash
docker run --rm -p 8910:8910 ghcr.io/bokuweb/coronarium-proxy:v0 \
    --listen 0.0.0.0:8910 --min-age 7d
# Then point your package managers at http://<host>:8910 as HTTPS_PROXY.
```

## When to use what

| situation | reach for |
|---|---|
| Dev machine, want every `npm install` to auto-fallback | `install-gate` + `proxy install-daemon` (Quick start above) |
| CI job, want the build to fail loudly on too-young deps | `coronarium deps check` ([CI features](#ci-features)) |
| CI job, want kernel-level audit of what the build does | `coronarium run` + a policy file ([CI features](#ci-features)) |
| macOS user who wants background lockfile monitoring | `coronarium deps watch` (see [desktop watch](#desktop-watch-mode-macos)) |

---

## Platforms

- **Linux** — proxy ✅, eBPF supervisor ✅ (network kernel-block,
  file kernel-kill, exec audit).
- **macOS** — proxy ✅, `deps check` + `deps watch` (supply-chain
  guard). The supervised-child runtime is Linux/Windows only; macOS
  is the developer-desktop home.
- **Windows** — proxy ✅, ETW supervisor ✅ (ETW audit, kernel network
  deny via dynamic Defender Firewall rules).

---

## CI features

Everything below predates the proxy and is still fully supported. For
CI the proxy story is usually overkill; `deps check` as a pre-install
step + optional `coronarium run` supervisor is a simpler shape.

`coronarium` wraps a build/test command and, via eBPF programs
attached to a dedicated cgroup v2, observes (and optionally denies) its:

- **Network** — outbound `connect(2)` on IPv4 and IPv6
- **File** — `openat(2)` (audit + kernel-kill on deny)
- **Process** — `execve(2)` (audit; deny is on the roadmap)

It can run locally as a CLI, or be installed into a GitHub Actions workflow
as a composite action.

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

## Supply-chain: `deps check` + `deps watch` (minimum release age)

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

### Comparison with pnpm's `minimumReleaseAge`

pnpm 10.x ships a built-in setting of the same name, but with
meaningfully different semantics:

| | pnpm `minimumReleaseAge` | `coronarium deps check` |
|---|---|---|
| Ecosystems | npm only (pnpm's own resolver) | npm, cargo, pypi, nuget |
| When it runs | Inside the resolver, during install | Before or after install, as a separate CLI step |
| On violation | Filters too-young versions out of the candidate set, silently picks the newest in-range version that's old enough. **Install succeeds on an older dep.** | Prints the violation and exits 1. **Your install step fails.** You edit the version range or wait. |
| On "no acceptable version" | `ERR_PNPM_NO_MATCHING_VERSION_FOUND` | Same effect — the CI step that would have installed never runs. |
| Requires a proxy / extra tooling | No (built into pnpm) | No (CLI + registry HTTP GET) |

**Practical upshot**: pnpm's flavour is nicer UX (builds don't
break, they just use older deps) but locked to npm. coronarium's
flavour is strictly more noisy but covers the other three major
ecosystems. Auto-fallback for coronarium is a roadmap item — see
[CLAUDE.md § "Known limitations"](CLAUDE.md#we-do-not-auto-fallback-like-pnpms-minimumreleaseage)
— it would require writing a custom resolver for each ecosystem.

### Desktop watch mode (macOS)

`coronarium deps watch <dir>` runs as a long-lived daemon, typically
under launchd at login. It subscribes to FS events on lockfiles in
`<dir>` and reruns `deps check` after each change settles. See
[packaging/macos/README.md](packaging/macos/README.md) for the
launchd plist install.

```bash
# One-off (Ctrl-C to quit)
coronarium deps watch ~/code --min-age 7d

# With modal prompts (Keep / Revert via osascript)
coronarium deps watch ~/code --min-age 7d --action prompt

# Stdout logging, e.g. for tmux / screen
coronarium deps watch ~/code --min-age 7d --notifier stdout
```

`--action` controls what happens on violation:

| value | behaviour |
|---|---|
| `notify` (default) | Post a desktop notification. Lockfile untouched. Nothing blocked. |
| `prompt` (macOS only) | Show a modal "Keep / Revert" dialog via osascript. On **Revert**, run `git checkout HEAD -- <lockfile>`. On **Keep** or timeout, do nothing. |
| `revert` | Silently restore the lockfile to `HEAD` via git. Destructive; the file must be tracked. |

> **Important — watch is detection, not prevention.** The FS event
> fires *after* the package manager finishes writing the lockfile,
> which means `preinstall` / `install` / `postinstall` scripts
> (npm, pip) have already run. Reverting the lockfile cannot undo
> side effects from those scripts (stolen SSH keys, modified
> crontab, etc.). Even on cargo / nuget, auto-build tools like
> rust-analyzer or OmniSharp often close the "between add and
> build" window automatically.
>
> The **only** way to reliably prevent install-time attacks is to
> check *before* `install` is invoked. Two options:
>
> 1. In CI, run `coronarium deps check` **before** the install step
>    (see example above).
> 2. On desktop, use the pre-commit / pre-push hook at
>    [packaging/git-hooks/pre-commit](packaging/git-hooks/pre-commit)
>    to refuse commits whose lockfile has too-young deps. A future
>    release will ship a `coronarium install-gate` wrapper that sits
>    in front of `npm install` / `cargo add` / `pip install`.

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
