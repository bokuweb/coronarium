//! Classify HTTP traffic to git hosting providers (GitHub today;
//! GitLab / Bitbucket as follow-ups) so the proxy can record direct
//! git-source installs in `installs.jsonl`.
//!
//! Three URL shapes are recognised:
//!
//! 1. **codeload tarball/zipball** — `https://codeload.github.com/
//!    <owner>/<repo>/{tar.gz,zip,legacy.tar.gz,legacy.zip}/<ref>`.
//!    What `npm install github:owner/repo` actually fetches; ref in
//!    the last path segment is a 40-hex SHA, a tag, or a branch.
//! 2. **GitHub REST tarball/zipball** — `https://api.github.com/
//!    repos/<owner>/<repo>/{tarball,zipball}[/<ref>]`. Used by `go
//!    get` and various script downloaders; ref optional (defaults to
//!    the repo's default branch when absent).
//! 3. **smart-HTTP clone discovery** — `GET /<owner>/<repo>.git/
//!    info/refs?service=git-upload-pack` on `github.com`. The first
//!    request of every `git clone` over HTTPS, which means
//!    `cargo`'s `git = "..."` deps, `pip install git+https://...`,
//!    and `git submodule update`. The follow-up `POST
//!    /<owner>/<repo>.git/git-upload-pack` carries the resolved
//!    SHAs but is intentionally NOT classified here — logging both
//!    would double-count the same install. The info/refs hit is
//!    enough to record "this repo was cloned"; resolving the
//!    specific commit needs pkt-line parsing of the upload-pack
//!    body, which is a follow-up.
//!
//! Fail-quiet: any URL the patterns don't recognise returns `None`
//! and the caller skips logging. The classifier never errors — a
//! mis-classification just means a missed log line, not a broken
//! install.

/// A classified git fetch. `requested_ref` is `None` for endpoints
/// that default to the repository's default branch (today: only
/// `api.github.com` tarball/zipball without a trailing ref).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitFetch {
    pub host: String,
    pub owner: String,
    pub repo: String,
    pub requested_ref: Option<String>,
    /// Canonical `host + path` for the `GitProvenance.url` field.
    /// Query string is stripped because (a) tokens may be embedded
    /// in it and (b) the path alone is enough to reconstruct the
    /// fetch.
    pub url: String,
    /// What the proxy is observing — drives whether the version
    /// field on the emitted InstallEvent should be the ref (tarball
    /// pulls) or `"HEAD"` (clone-protocol discovery, which doesn't
    /// yet bind to a specific ref).
    pub kind: GitFetchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitFetchKind {
    /// Single-archive download — codeload or REST tarball/zipball.
    Archive,
    /// `info/refs?service=git-upload-pack` — clone is starting.
    CloneDiscovery,
}

impl GitFetch {
    /// `<host>/<owner>/<repo>` — the Go-module-style identifier we
    /// store as `InstallEvent::name`. Lowercased so `Github.com` and
    /// `github.com` collapse into the same entry.
    pub fn name(&self) -> String {
        format!(
            "{}/{}/{}",
            self.host.to_ascii_lowercase(),
            self.owner,
            self.repo
        )
    }

    /// `true` when [`Self::requested_ref`] is a 40-character lower-
    /// hex string. The proxy treats that ref as the resolved commit
    /// SHA and populates `GitProvenance::resolved_commit`
    /// accordingly.
    pub fn ref_is_commit_sha(&self) -> bool {
        self.requested_ref
            .as_deref()
            .map(is_full_sha)
            .unwrap_or(false)
    }
}

/// Best-effort classification. Returns `None` when the URL doesn't
/// match any of the three recognised shapes.
pub fn classify(host: &str, path_and_query: &str) -> Option<GitFetch> {
    let host_lc = host.to_ascii_lowercase();
    // Strip query string — kept separately if a future caller wants
    // it but never folded into the recorded URL.
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    match host_lc.as_str() {
        "codeload.github.com" => parse_codeload(&host_lc, path),
        "api.github.com" => parse_api_github(&host_lc, path),
        "github.com" => parse_github_clone(&host_lc, path),
        _ => None,
    }
}

fn parse_codeload(host: &str, path: &str) -> Option<GitFetch> {
    // /<owner>/<repo>/{tar.gz,zip,legacy.tar.gz,legacy.zip}/<ref>
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segs.len() < 4 {
        return None;
    }
    let (owner, repo, kind) = (segs[0], segs[1], segs[2]);
    if !matches!(kind, "tar.gz" | "zip" | "legacy.tar.gz" | "legacy.zip") {
        return None;
    }
    // ref may itself contain `/` (branch like `feat/x`). Re-join the
    // tail.
    let r = segs[3..].join("/");
    if owner.is_empty() || repo.is_empty() || r.is_empty() {
        return None;
    }
    Some(GitFetch {
        host: host.to_string(),
        owner: owner.to_string(),
        repo: strip_git_suffix(repo).to_string(),
        requested_ref: Some(r),
        url: format!("{host}{path}"),
        kind: GitFetchKind::Archive,
    })
}

fn parse_api_github(host: &str, path: &str) -> Option<GitFetch> {
    // /repos/<owner>/<repo>/{tarball,zipball}[/<ref>]
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segs.len() < 4 || segs[0] != "repos" {
        return None;
    }
    let (owner, repo, kind) = (segs[1], segs[2], segs[3]);
    if !matches!(kind, "tarball" | "zipball") {
        return None;
    }
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    let r = if segs.len() > 4 {
        let tail = segs[4..].join("/");
        if tail.is_empty() { None } else { Some(tail) }
    } else {
        None
    };
    Some(GitFetch {
        host: host.to_string(),
        owner: owner.to_string(),
        repo: strip_git_suffix(repo).to_string(),
        requested_ref: r,
        url: format!("{host}{path}"),
        kind: GitFetchKind::Archive,
    })
}

fn parse_github_clone(host: &str, path: &str) -> Option<GitFetch> {
    // /<owner>/<repo>.git/info/refs (query has already been stripped)
    let rest = path.trim_start_matches('/');
    let info_refs_suffix = ".git/info/refs";
    let prefix = rest.strip_suffix(info_refs_suffix)?;
    let mut parts = prefix.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    // Extra segments → not the smart-HTTP discovery endpoint we want.
    if parts.next().is_some() {
        return None;
    }
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(GitFetch {
        host: host.to_string(),
        owner: owner.to_string(),
        repo: repo.to_string(),
        // Ref is not yet bound at info/refs time — the server
        // advertises every ref and the client chooses afterward.
        requested_ref: None,
        url: format!("{host}{path}"),
        kind: GitFetchKind::CloneDiscovery,
    })
}

fn strip_git_suffix(s: &str) -> &str {
    s.strip_suffix(".git").unwrap_or(s)
}

fn is_full_sha(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codeload_targz_with_sha_ref() {
        let g = classify(
            "codeload.github.com",
            "/octocat/Hello-World/tar.gz/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
        )
        .unwrap();
        assert_eq!(g.host, "codeload.github.com");
        assert_eq!(g.owner, "octocat");
        assert_eq!(g.repo, "Hello-World");
        assert_eq!(
            g.requested_ref.as_deref(),
            Some("7fd1a60b01f91b314f59955a4e4d4e80d8edf11d")
        );
        assert!(g.ref_is_commit_sha());
        assert_eq!(g.kind, GitFetchKind::Archive);
        assert_eq!(g.name(), "codeload.github.com/octocat/Hello-World");
    }

    #[test]
    fn codeload_zip_with_branch_ref_containing_slash() {
        let g = classify("codeload.github.com", "/o/r/zip/feat/new-thing").unwrap();
        assert_eq!(g.requested_ref.as_deref(), Some("feat/new-thing"));
        assert!(!g.ref_is_commit_sha());
    }

    #[test]
    fn codeload_strips_dot_git_from_repo() {
        let g = classify("codeload.github.com", "/o/r.git/tar.gz/main").unwrap();
        assert_eq!(g.repo, "r");
    }

    #[test]
    fn codeload_rejects_unknown_archive_type() {
        assert!(classify("codeload.github.com", "/o/r/bz2/main").is_none());
    }

    #[test]
    fn codeload_rejects_missing_ref() {
        assert!(classify("codeload.github.com", "/o/r/tar.gz/").is_none());
        assert!(classify("codeload.github.com", "/o/r/tar.gz").is_none());
    }

    #[test]
    fn api_github_tarball_with_ref() {
        let g = classify("api.github.com", "/repos/o/r/tarball/v1.2.3").unwrap();
        assert_eq!(g.host, "api.github.com");
        assert_eq!(g.requested_ref.as_deref(), Some("v1.2.3"));
        assert!(!g.ref_is_commit_sha());
    }

    #[test]
    fn api_github_zipball_without_ref_defaults_to_default_branch() {
        let g = classify("api.github.com", "/repos/o/r/zipball").unwrap();
        assert_eq!(g.requested_ref, None);
    }

    #[test]
    fn api_github_ignores_non_archive_paths() {
        assert!(classify("api.github.com", "/repos/o/r/contents/foo").is_none());
        assert!(classify("api.github.com", "/users/o").is_none());
    }

    #[test]
    fn github_clone_discovery_endpoint() {
        let g = classify(
            "github.com",
            "/rust-lang/cargo.git/info/refs?service=git-upload-pack",
        )
        .unwrap();
        assert_eq!(g.host, "github.com");
        assert_eq!(g.owner, "rust-lang");
        assert_eq!(g.repo, "cargo");
        assert_eq!(g.requested_ref, None);
        assert_eq!(g.kind, GitFetchKind::CloneDiscovery);
        // Query string is intentionally stripped from the stored URL
        // — tokens may be embedded there and the path alone is
        // enough to reconstruct the fetch.
        assert_eq!(g.url, "github.com/rust-lang/cargo.git/info/refs");
    }

    #[test]
    fn github_post_upload_pack_is_not_classified() {
        // Intentionally skipped — see module comment. Logging both
        // info/refs (GET) and git-upload-pack (POST) would
        // double-count the same clone.
        assert!(classify("github.com", "/o/r.git/git-upload-pack").is_none());
    }

    #[test]
    fn github_rejects_non_clone_paths() {
        assert!(classify("github.com", "/o/r").is_none());
        assert!(classify("github.com", "/o/r/info/refs").is_none()); // missing .git
        assert!(classify("github.com", "/o/r.git/info/packs").is_none());
    }

    #[test]
    fn classify_is_case_insensitive_on_host() {
        assert!(classify("Codeload.GitHub.com", "/o/r/tar.gz/main").is_some());
        assert!(classify("API.github.com", "/repos/o/r/tarball/main").is_some());
    }

    #[test]
    fn unknown_host_returns_none() {
        assert!(classify("gitlab.com", "/o/r/-/archive/main/r-main.tar.gz").is_none());
        assert!(classify("bitbucket.org", "/o/r/get/main.tar.gz").is_none());
    }

    #[test]
    fn full_sha_detection_rejects_short_and_mixed_case() {
        assert!(is_full_sha("abcdef0123456789abcdef0123456789abcdef01"));
        assert!(!is_full_sha("abcdef")); // too short
        assert!(!is_full_sha("ABCDEF0123456789ABCDEF0123456789ABCDEF01")); // uppercase
        assert!(!is_full_sha("g".repeat(40).as_str())); // non-hex
    }

    #[test]
    fn query_string_is_stripped_from_url() {
        let g = classify("codeload.github.com", "/o/r/tar.gz/main?token=abc").unwrap();
        // The classifier folds query-bearing URLs the same way as
        // bare ones — the stored URL has no `?…` suffix.
        assert!(!g.url.contains('?'));
    }
}
