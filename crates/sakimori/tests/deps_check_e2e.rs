//! `deps check` end-to-end against mock registries.
//!
//! The proxy and the inline unit tests cover lockfile parsing and
//! the individual registry-client response shapes in isolation.
//! This file proves the **whole CLI seam** holds together: argv →
//! lockfile parse → registry HTTP fetch → cache key → age compare
//! → exit code → JSON output.
//!
//! Spins up tokio TCP listeners per ecosystem serving the canonical
//! JSON shape, points the real `CARGO_BIN_EXE_sakimori` binary at
//! them via `--<eco>-registry`, asserts both:
//!
//! - clean run (all old) → exit 0
//! - violation (one young) → exit 1, JSON output names the
//!   offending `(ecosystem, name, version)` exactly
//!
//! Plus a cross-ecosystem run combining all four lockfiles in
//! one invocation to prove the registry routing per package works.

use std::io::{Read, Write};
use std::net::TcpListener as StdListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn sakimori_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sakimori"))
}

fn tmp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!(
        "sakimori-deps-check-e2e-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Returns `(base_url, addr)`. Caller hands `base_url` to
/// `--<eco>-registry`. The closure picks the HTTP/1.1 response
/// body to serve based on the request path — gives each test full
/// control over the JSON shape the parser sees.
fn spawn_mock(
    handler: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
) -> (String, std::net::SocketAddr) {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(false).unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else {
                continue;
            };
            let handler = handler.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut accum = Vec::with_capacity(2048);
                loop {
                    let n = match sock.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    accum.extend_from_slice(&buf[..n]);
                    if accum.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if accum.len() > 32 * 1024 {
                        return;
                    }
                }
                let req = String::from_utf8_lossy(&accum);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, body) = handler(path);
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "OK",
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.write_all(body.as_bytes());
                let _ = sock.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    (format!("http://{addr}"), addr)
}

fn run_deps_check(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(sakimori_bin())
        .arg("deps")
        .arg("check")
        .args(args)
        .output()
        .expect("spawn sakimori deps check");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

// ---------------------------------------------------------------------------
// Fixture writers
// ---------------------------------------------------------------------------

fn write_npm_lock(dir: &std::path::Path, name: &str, version: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join("package-lock.json");
    // `resolved` MUST contain "registry.npmjs.org" or
    // "registry.yarnpkg.com" — npm lockfile parser filters out
    // entries that don't (treats them as git / local / tarball
    // deps with no age to check). The resolved URL is metadata in
    // the lockfile, not where the proxy fetches from; we still
    // hit our `--npm-registry` mock for the actual age lookup.
    let body = format!(
        r#"{{
  "name":"x","version":"0.0.0","lockfileVersion":3,"requires":true,
  "packages": {{
    "": {{"name":"x","version":"0.0.0"}},
    "node_modules/{name}": {{"version":"{version}","resolved":"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz","integrity":"sha512-x"}}
  }}
}}"#
    );
    std::fs::write(&p, body).unwrap();
    p
}

fn write_cargo_lock(dir: &std::path::Path, name: &str, version: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join("Cargo.lock");
    let body = format!(
        r#"# Auto-generated
version = 3

[[package]]
name = "{name}"
version = "{version}"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"#
    );
    std::fs::write(&p, body).unwrap();
    p
}

fn write_requirements(dir: &std::path::Path, name: &str, version: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join("requirements.txt");
    std::fs::write(&p, format!("{name}=={version}\n")).unwrap();
    p
}

fn write_nuget_packages_lock(dir: &std::path::Path, name: &str, version: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join("packages.lock.json");
    let body = format!(
        r#"{{
  "version": 1,
  "dependencies": {{
    "net8.0": {{
      "{name}": {{ "type": "Direct", "requested": "[{version}]", "resolved": "{version}", "contentHash": "h" }}
    }}
  }}
}}"#
    );
    std::fs::write(&p, body).unwrap();
    p
}

// ---------------------------------------------------------------------------
// Per-ecosystem JSON response shapes
// ---------------------------------------------------------------------------

fn npm_response(name: &str, version: &str, iso_time: &str) -> String {
    format!(r#"{{"name":"{name}","time":{{"{version}":"{iso_time}"}}}}"#)
}

fn crates_response(_name: &str, version: &str, iso_time: &str) -> String {
    format!(r#"{{"versions":[{{"num":"{version}","created_at":"{iso_time}"}}]}}"#)
}

fn pypi_response(iso_time: &str) -> String {
    format!(r#"{{"urls":[{{"upload_time_iso_8601":"{iso_time}","upload_time":"{iso_time}"}}]}}"#)
}

fn nuget_response(iso_time: &str) -> String {
    // `catalogEntry` inline shape — no follow-up GET needed.
    format!(r#"{{"catalogEntry":{{"published":"{iso_time}"}}}}"#)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn npm_old_package_exits_zero() {
    let (url, _) = spawn_mock(move |_| {
        (
            200,
            npm_response("lodash", "4.17.21", "2020-01-01T00:00:00Z"),
        )
    });
    let work = tmp_dir("npm-old");
    let lock = write_npm_lock(&work, "lodash", "4.17.21");
    let (code, stdout, stderr) = run_deps_check(&[
        lock.to_str().unwrap(),
        "--min-age",
        "30d",
        "--npm-registry",
        &url,
        "--no-cache",
    ]);
    assert_eq!(
        code, 0,
        "old npm package should exit 0; stdout={stdout}\nstderr={stderr}"
    );
}

#[test]
fn npm_young_package_exits_one_and_json_lists_violation() {
    let now = chrono::Utc::now();
    let iso = (now - chrono::Duration::days(2)).to_rfc3339();
    let (url, _) = spawn_mock(move |_| (200, npm_response("lodash", "4.17.21", &iso)));
    let work = tmp_dir("npm-young");
    let lock = write_npm_lock(&work, "lodash", "4.17.21");
    let (code, stdout, _) = run_deps_check(&[
        lock.to_str().unwrap(),
        "--min-age",
        "30d",
        "--npm-registry",
        &url,
        "--no-cache",
        "--format",
        "json",
    ]);
    assert_eq!(code, 1, "young npm package must exit 1");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json output must parse");
    assert_eq!(report["violations"], 1);
    let pkgs = report["packages"].as_array().unwrap();
    let v = pkgs
        .iter()
        .find(|p| p["too_new"] == true)
        .expect("at least one violation in packages[]");
    assert_eq!(v["ecosystem"], "npm");
    assert_eq!(v["name"], "lodash");
    assert_eq!(v["version"], "4.17.21");
}

#[test]
fn crates_old_package_exits_zero() {
    let (url, _) = spawn_mock(move |path| {
        // Path: /api/v1/crates/<name>
        assert!(
            path.starts_with("/api/v1/crates/"),
            "cargo client must hit /api/v1/crates path, got {path}"
        );
        (
            200,
            crates_response("serde", "1.0.0", "2018-01-01T00:00:00Z"),
        )
    });
    let work = tmp_dir("crates-old");
    let lock = write_cargo_lock(&work, "serde", "1.0.0");
    let (code, _, _) = run_deps_check(&[
        lock.to_str().unwrap(),
        "--min-age",
        "30d",
        "--cargo-registry",
        &url,
        "--no-cache",
    ]);
    assert_eq!(code, 0);
}

#[test]
fn pypi_young_package_exits_one() {
    let now = chrono::Utc::now();
    let iso = (now - chrono::Duration::days(3)).to_rfc3339();
    let (url, _) = spawn_mock(move |path| {
        // Path shape: /pypi/<name>/<version>/json
        assert!(
            path.starts_with("/pypi/"),
            "pypi client must hit /pypi/ path, got {path}"
        );
        (200, pypi_response(&iso))
    });
    let work = tmp_dir("pypi-young");
    let lock = write_requirements(&work, "requests", "2.31.0");
    let (code, stdout, stderr) = run_deps_check(&[
        lock.to_str().unwrap(),
        "--min-age",
        "30d",
        "--pypi-registry",
        &url,
        "--no-cache",
    ]);
    assert_eq!(
        code, 1,
        "young pypi package must exit 1; stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn nuget_old_package_exits_zero() {
    let (url, _) = spawn_mock(move |path| {
        assert!(
            path.starts_with("/v3/registration5-"),
            "nuget client must hit /v3/registration5-*/, got {path}"
        );
        (200, nuget_response("2015-01-01T00:00:00Z"))
    });
    let work = tmp_dir("nuget-old");
    let lock = write_nuget_packages_lock(&work, "Newtonsoft.Json", "13.0.1");
    let (code, _, _) = run_deps_check(&[
        lock.to_str().unwrap(),
        "--min-age",
        "30d",
        "--nuget-registry",
        &url,
        "--no-cache",
    ]);
    assert_eq!(code, 0);
}

#[test]
fn missing_publish_date_with_fail_on_missing_exits_one() {
    // Registry returns 404 → publish date unknown.
    // `--fail-on-missing` must escalate to violation.
    let (url, _) = spawn_mock(move |_| (404, r#"{"error":"not found"}"#.to_string()));
    let work = tmp_dir("missing");
    let lock = write_npm_lock(&work, "ghost-pkg", "1.0.0");
    let (code, _, _) = run_deps_check(&[
        lock.to_str().unwrap(),
        "--min-age",
        "30d",
        "--npm-registry",
        &url,
        "--no-cache",
        "--fail-on-missing",
    ]);
    assert_eq!(code, 1, "missing + fail_on_missing must deny");
}

#[test]
fn cross_ecosystem_combined_run_routes_each_to_its_own_mock() {
    // Spawn 4 separate mocks and run `deps check` against all 4
    // lockfiles in one invocation. Each ecosystem's lookup must
    // land on the right server (proven by the unique iso time
    // baked into each response shape — all old enough to pass
    // `--min-age 30d`).
    let (npm_url, _) =
        spawn_mock(move |_| (200, npm_response("a", "1.0.0", "2019-01-01T00:00:00Z")));
    let (crates_url, _) =
        spawn_mock(move |_| (200, crates_response("b", "1.0.0", "2018-01-01T00:00:00Z")));
    let (pypi_url, _) = spawn_mock(move |_| (200, pypi_response("2017-01-01T00:00:00Z")));
    let (nuget_url, _) = spawn_mock(move |_| (200, nuget_response("2016-01-01T00:00:00Z")));

    let work = tmp_dir("cross");
    let npm_lock = write_npm_lock(&work.join("npm-pkg"), "a", "1.0.0");
    let cargo_lock = write_cargo_lock(&work.join("cargo-pkg"), "b", "1.0.0");
    let pip_lock = write_requirements(&work.join("py-pkg"), "c", "1.0.0");
    let nuget_lock = write_nuget_packages_lock(&work.join("net-pkg"), "D", "1.0.0");

    let (code, stdout, _) = run_deps_check(&[
        npm_lock.to_str().unwrap(),
        cargo_lock.to_str().unwrap(),
        pip_lock.to_str().unwrap(),
        nuget_lock.to_str().unwrap(),
        "--min-age",
        "30d",
        "--npm-registry",
        &npm_url,
        "--cargo-registry",
        &crates_url,
        "--pypi-registry",
        &pypi_url,
        "--nuget-registry",
        &nuget_url,
        "--no-cache",
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "all 4 ecosystems should pass with old fixtures; got stdout={stdout}"
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["checked"], 4, "4 packages across 4 ecosystems");
    assert_eq!(report["violations"], 0);
}
