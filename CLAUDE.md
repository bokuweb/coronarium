# CLAUDE.md — project context for Claude

This file exists so future Claude sessions (or other LLM agents) can
pick up work on this repo without re-deriving context from scratch.
Human readers may find it useful too — it's deliberately written in
plain English, no agent-only jargon.

## What this project is

**coronarium** is a cross-platform supply-chain guard with two main
surfaces:

1. **A supervised-run mode** for CI (`coronarium run -- <cmd>`):
   wraps your build/test command with an eBPF (Linux) or ETW (Windows)
   agent that audits and optionally blocks network / file / exec
   syscalls.
2. **A lockfile supply-chain guard** (`coronarium deps check` and
   `coronarium deps watch`): runs a "minimum release age" check across
   4 ecosystems (npm, cargo, pypi, nuget), flagging recently-published
   dependencies so you can sit out the window in which malicious
   releases typically live.

## Known limitations (read these before changing behaviour)

These are **accepted** limitations — not bugs. The architecture
has them on purpose, and the docs are honest about each.

### `deps watch` is detection, not prevention

The watch mode subscribes to FS events on lockfiles. It fires
*after* the package manager has finished writing the lockfile,
which means:

- **npm / pnpm / yarn**: `preinstall` / `install` / `postinstall`
  scripts have already executed by the time the lockfile changes.
  Any .ssh / env / crontab / launchd-service mischief from a
  malicious package **cannot be undone** by reverting the lockfile.
- **pypi (pip / uv / poetry)**: `setup.py` / build-backend hooks
  execute during install. Same story as npm.
- **cargo / dotnet**: the initial `add`/`restore` just updates
  the lockfile and extracts the crate — code doesn't run until
  the next `cargo build` / `dotnet build`. In principle watch has
  a window between those two points… **but** rust-analyzer,
  OmniSharp, file-save hooks in IDEs, and other background
  tooling often invoke the build automatically, closing that
  window quickly. In practice: treat cargo/dotnet the same as
  npm/pypi for threat-model purposes.

**Practical consequence**: `deps watch` is most useful as a
passive audit alarm ("hey, you just pulled in a 2-hour-old crate")
rather than as a wall against script-based attacks. The only way
to reliably *prevent* those is to check BEFORE install happens
(see `deps check` in CI, or the planned `install-gate` wrapper).

### Auto-fallback (pnpm-style): crates.io only, via the proxy

pnpm 10.x's `minimumReleaseAge` teaches its resolver to **filter
versions younger than the threshold out of its candidate set**,
silently resolving to the newest in-range version that also meets
the age requirement. Builds don't break; they just use slightly
older deps.

**Status (v0.17):**
- **crates.io** — ✅ implemented via the proxy. `coronarium
  proxy serve` rewrites `index.crates.io` sparse-index responses on
  the fly, dropping JSONL lines whose `(name, vers)` publish time is
  < `--min-age`. cargo's resolver sees only acceptable versions and
  naturally picks the newest older-in-range.
- **npm** — ✅ implemented. The proxy rewrites the packument
  endpoint (`registry.npmjs.org/<pkg>`): too-young entries are
  removed from both `versions` and `time`, and any `dist-tags`
  (notably `latest`) that pointed at a removed version is
  retargeted to the highest remaining semver. npm's resolver then
  picks the newest in-range surviving version — no error.
- **pypi** — ✅ implemented for the two JSON endpoints modern pip
  and uv actually consult:
  - Warehouse JSON API (`pypi.org/pypi/<pkg>/json`) — drops version
    keys from `releases` whose earliest `upload_time_iso_8601` is
    too young, plus stripping the `urls` shortcut.
  - PEP 691 Simple JSON (`pypi.org/simple/<pkg>/` with
    `Accept: application/vnd.pypi.simple.v1+json`) — drops
    too-young `files[]`, prunes `versions[]` to only those with
    surviving files.

  The legacy HTML Simple index (PEP 503) carries no upload time in
  the response; it passes through unchanged. pip fall-back to
  tarball-level `files.pythonhosted.org` deny still catches those
  installs fail-hard.
- **nuget** — still fail-hard. NuGet uses versioned flat-container
  URLs (`api.nuget.org/v3-flatcontainer/<id>/index.json`); same
  pattern as the others, just one more ecosystem to wire.

For ecosystems without rewriting, `deps check` (CI) or the proxy's
hard-deny (desktop) is still the defense — just not silent.

### file block is "tripwire", not pre-open block

On Linux, `file.deny` in `mode: block` triggers
`bpf_send_signal(SIGKILL)` on the process that opened a
matching file. The file descriptor may briefly exist; the
process dies before it can consume its contents. This is
honest "after-the-open block" — for a truly pre-open block we
need `bpf_override_return` on a kprobe'd `do_sys_openat2`, which
is CONFIG_BPF_KPROBE_OVERRIDE dependent. Roadmap.

### exec block is audit-only

`process.deny_exec` stamps `denied: true` on matching events and
makes block-mode exit non-zero, but the child process does exec.
See above about `bpf_override_return`.

### Windows network default:deny is audit-only

Windows Defender Firewall evaluates block rules as winning over
allow. An "allowlist" pattern (`default: deny` + `allow: […]`)
would require flipping the system-wide default-outbound to Block,
which we won't do silently on a shared runner. `network.deny` is
kernel-enforced; `network.default: deny` is audit-only + warn.

## Roadmap (what to build next, in priority order)

1. **`coronarium install-gate` wrapper** — shell alias intercepts
   `npm install X` / `cargo add X` / `pip install X`, runs the
   registry-query portion of `deps check` BEFORE invoking the real
   tool, refuses on violations. This closes the script-attack
   window on desktop.
2. **HTTPS registry proxy** — same idea but transparent: set
   `HTTPS_PROXY` system-wide, filter fetch traffic. No shell
   aliasing required, but MITM cert management is a UX chore.
3. **pnpm-style auto-fallback for nuget** — crates.io (v0.15),
   npm (v0.16) and pypi (v0.17) already work. NuGet's
   flat-container index is the last of the four to wire.
4. **Linux file/exec block via `bpf_override_return`** — clean
   pre-syscall block, requires runtime detection of
   CONFIG_BPF_KPROBE_OVERRIDE and a well-timed kprobe.
5. **macOS live block** — either a Network Extension (heavy, needs
   signing) or an HTTPS proxy (see #2).

## Crate layout

```
crates/
├── coronarium-common/   no_std + std types shared with eBPF (ring
│                        buffer records, map keys, POD structs).
├── coronarium-core/     Platform-neutral Rust: events, policy,
│                        matcher, stats, html, report, deps::*, watch.
├── coronarium-ebpf/     Linux kernel programs (tracepoint / cgroup
│                        hooks). Compiled to bpfel-unknown-none with
│                        nightly; excluded from the main workspace.
├── coronarium/          Linux userspace binary (eBPF loader +
│                        supervisor).
└── coronarium-win/      Windows binary (ETW subscriber, Defender
│                        Firewall driver). Its own workspace so
│                        ferrisetw doesn't pollute the Linux side.
```

`coronarium-core::deps` houses the per-ecosystem lockfile parsers
and registry clients. To add a new ecosystem:

1. `deps::lockfile::<name>` parser (input: path → `Vec<Package>`).
2. `deps::registry::<name>` client (input: `(name, version)` →
   `DateTime<Utc>`).
3. Add the variant to `deps::Ecosystem` + label.
4. Extend `deps::lockfile::detect` for the basename.
5. Fixture under `tests/fixtures/` and CI assertion in
   `.github/workflows/ci.yml`.
6. Bump the "supported" table in README.

## Testing conventions

- **Test-first whenever possible.** Handler traits are specifically
  designed to be mockable (see `action::Prompter`, `watch::Notifier`,
  `watch::EventSource`) so the interesting logic sits behind a
  deterministic fake and doesn't need real IO.
- Use `cargo test -p coronarium-core` for fast iteration; the full
  workspace runs eBPF + aya code that only builds meaningfully on
  Linux.
- Use real `git` in tests (not a mock) when that's cheaper than
  faking. `GitRevert` tests set up a real tmp repo — fast enough.
- Don't assert on exact error messages; search for substrings. CI
  runs across kernels and libc versions that differ in phrasing.

## Release process

Any push of a `v*` tag triggers `.github/workflows/release.yml`:
cross-compiles Linux (musl x86_64 + aarch64), macOS (both archs on
a single macos-14 runner), and Windows, then publishes a GitHub
Release with SHA-256 sidecars. The `v<MAJOR>` floating tag is
force-pushed to the newest release so consumers can pin `@v0`.

If you need to skip the floating tag update (e.g. for a prerelease
containing a hyphen like `v0.13.0-rc1`), the `moving-tag` job is
already gated on `!contains(github.ref_name, '-')`.

## Never do these

- Don't add `println!`/`eprintln!` on the hot event-ingest path
  — it serialises on the stdout mutex and tanks throughput.
- Don't put secrets in `log::` output. The JSON log is routinely
  uploaded as an artifact and surfaced in PR comments.
- Don't quietly change semantics (eg. make `watch` destructive by
  default). If the behaviour is potentially surprising, require
  an explicit `--action=…` opt-in and document the rationale.
- Don't auto-update the `v0` tag from a human workflow. Let
  `release.yml`'s `moving-tag` job own that.
