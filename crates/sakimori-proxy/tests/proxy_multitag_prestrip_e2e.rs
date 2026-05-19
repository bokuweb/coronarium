//! Multi-tag speculative pre-strip e2e.
//!
//! Pins the contract added when `speculative_pre_strip_packument`
//! grew past `dist-tags.latest` to cover **every entry in
//! `dist-tags`**, deduped by target version, capped at
//! `MAX_PRE_STRIP_TAGS`. The motivating limitation in CLAUDE.md
//! roadmap #15: `npm install pkg@next` / `pkg@beta` for a non-
//! `latest` version used to hit the tarball handler's lazy strip
//! path, fail the first attempt with `EINTEGRITY` (because the
//! packument advertised the original hash), and succeed on retry
//! after the cache warmed. With multi-tag pre-strip, the packument
//! that npm sees already carries the rewritten integrity for every
//! tagged version, so first-attempt installs succeed.
//!
//! Plan reviewed by Codex (one round). Key guarantees the test
//! enforces:
//!
//! 1. Pre-strip runs for **all** dist-tags, not just `latest`.
//! 2. The packument response carries rewritten
//!    `dist.integrity` / `dist.shasum` for each tagged version.
//! 3. Subsequent tarball fetches through the proxy return the
//!    *stripped* body whose sha512 equals the rewritten integrity
//!    — i.e. npm's first install attempt would now succeed.
//! 4. `dist.attestations` is dropped for stripped entries (the
//!    provenance signature is over the original bytes; keeping it
//!    would mislead `npm install --provenance`).
//! 5. Two tags pointing at the same version are deduped: only one
//!    pre-strip fires for that version.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use flate2::Compression;
use flate2::write::GzEncoder;
use sakimori_proxy::ca::CaFiles;
use sakimori_proxy::lifecycle::LifecyclePolicy;
use sakimori_proxy::{ProxyConfig, RegistryHosts};
use sha2::{Digest, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sakimori-multitag-e2e-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

/// Build a minimal `package/<pkg>` tarball whose `package.json` ships
/// a `postinstall` script — i.e. the strip path will rewrite it.
fn malicious_tarball(name: &str, version: &str, script_body: &str) -> Vec<u8> {
    let pkg_json = format!(
        r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":"{script_body}","test":"jest"}}}}"#
    );
    let index_js = format!("// {name}@{version}\nconsole.log('hi');\n");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, body) in [
            ("package/package.json", pkg_json.as_bytes()),
            ("package/index.js", index_js.as_bytes()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, path, body).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

fn sri_sha512(bytes: &[u8]) -> String {
    let mut h = Sha512::new();
    h.update(bytes);
    format!("sha512-{}", B64.encode(h.finalize()))
}

/// Synthetic packument shaped enough like an npm response for the
/// rewriter + speculative pre-strip path to fire. Three dist-tags,
/// two distinct target versions (`latest` and `dup` both point at
/// `2.0.0`; `next` points at `1.0.0`). Both versions ship a
/// `dist.attestations` block so we can prove it gets dropped post-
/// strip. Publish times are old enough to survive the default
/// `min_age = 30d`.
fn synthetic_packument(upstream_origin: &str, tgz_v1: &[u8], tgz_v2: &[u8]) -> Vec<u8> {
    let int_v1 = sri_sha512(tgz_v1);
    let int_v2 = sri_sha512(tgz_v2);
    serde_json::to_vec(&serde_json::json!({
        "name": "demo",
        "dist-tags": {
            "latest": "2.0.0",
            "next": "1.0.0",
            // Same version as latest — must dedupe so we don't
            // fire pre-strip twice for 2.0.0.
            "dup": "2.0.0",
        },
        "versions": {
            "1.0.0": {
                "name": "demo",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{upstream_origin}/demo/-/demo-1.0.0.tgz"),
                    "integrity": int_v1,
                    "shasum": "deadbeef0000000000000000000000000000beef",
                    "attestations": {
                        "url": "https://example.invalid/attestation-1",
                        "provenance": {"predicateType": "x"},
                    },
                },
            },
            "2.0.0": {
                "name": "demo",
                "version": "2.0.0",
                "dist": {
                    "tarball": format!("{upstream_origin}/demo/-/demo-2.0.0.tgz"),
                    "integrity": int_v2,
                    "shasum": "deadbeef0000000000000000000000000000cafe",
                    "attestations": {
                        "url": "https://example.invalid/attestation-2",
                        "provenance": {"predicateType": "x"},
                    },
                },
            },
        },
        "time": {
            "1.0.0": "2025-01-15T00:00:00Z",
            "2.0.0": "2025-08-15T00:00:00Z",
        }
    }))
    .unwrap()
}

/// Per-test mock upstream that:
///   * routes `GET /demo`         → packument bytes
///   * routes `GET /demo/-/demo-1.0.0.tgz` → v1 tarball
///   * routes `GET /demo/-/demo-2.0.0.tgz` → v2 tarball
///
/// Counts each tarball fetch in a returned atomic so the test can
/// assert dedup ("2.0.0 fetched exactly once even though it's
/// pointed at by two dist-tags").
struct UpstreamHandles {
    addr: std::net::SocketAddr,
    fetch_count_v1: Arc<AtomicUsize>,
    fetch_count_v2: Arc<AtomicUsize>,
}

async fn spawn_mock_upstream(
    packument: Arc<Vec<u8>>,
    tgz_v1: Arc<Vec<u8>>,
    tgz_v2: Arc<Vec<u8>>,
) -> UpstreamHandles {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fetch_count_v1 = Arc::new(AtomicUsize::new(0));
    let fetch_count_v2 = Arc::new(AtomicUsize::new(0));
    let c1 = fetch_count_v1.clone();
    let c2 = fetch_count_v2.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let packument = packument.clone();
            let tgz_v1 = tgz_v1.clone();
            let tgz_v2 = tgz_v2.clone();
            let c1 = c1.clone();
            let c2 = c2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(2048);
                let mut tmp = [0u8; 1024];
                loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                            if buf.len() > 64 * 1024 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let request_line = std::str::from_utf8(&buf)
                    .ok()
                    .and_then(|s| s.lines().next())
                    .unwrap_or("")
                    .to_string();
                let path = request_line.split_whitespace().nth(1).unwrap_or("/");

                let (body, ct): (Arc<Vec<u8>>, &str) = if path.ends_with("/demo-1.0.0.tgz") {
                    c1.fetch_add(1, Ordering::Relaxed);
                    (tgz_v1, "application/octet-stream")
                } else if path.ends_with("/demo-2.0.0.tgz") {
                    c2.fetch_add(1, Ordering::Relaxed);
                    (tgz_v2, "application/octet-stream")
                } else if path == "/demo" || path.ends_with("/demo") {
                    (packument, "application/json")
                } else {
                    let resp =
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                    return;
                };
                let resp_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp_head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    UpstreamHandles {
        addr,
        fetch_count_v1,
        fetch_count_v2,
    }
}

async fn spawn_proxy(persist_dir: std::path::PathBuf) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config_dir = tmp_dir("proxy");
    std::fs::create_dir_all(&config_dir).unwrap();
    let mut cfg = ProxyConfig::default_dev().unwrap();
    cfg.listen = addr;
    cfg.ca_files = CaFiles::at(config_dir);
    cfg.install_log_enabled = false;
    cfg.registries = RegistryHosts {
        npm: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    cfg.lifecycle_policy = Some(LifecyclePolicy::Strip);
    cfg.lifecycle_strip_cache_dir = Some(persist_dir);

    tokio::spawn(async move {
        if let Err(e) = sakimori_proxy::run(cfg).await {
            eprintln!("proxy exited: {e:#}");
        }
    });

    let ready = Arc::new(Notify::new());
    let ready2 = ready.clone();
    tokio::spawn(async move {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready2.notify_one();
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    tokio::time::timeout(Duration::from_secs(6), ready.notified())
        .await
        .expect("proxy did not come up");
    addr
}

fn http_get(proxy: std::net::SocketAddr, url: &str) -> (u16, Vec<u8>) {
    let proxy_spec = format!("http://{proxy}");
    let agent = ureq::AgentBuilder::new()
        .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
        .timeout(Duration::from_secs(15))
        .build();
    let resp = agent.get(url).call().expect("proxy GET");
    let status = resp.status();
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(8 * 1024 * 1024)
        .read_to_end(&mut buf)
        .unwrap();
    (status, buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pre_strip_rewrites_all_dist_tag_versions_in_packument() {
    let tgz_v1 = malicious_tarball("demo", "1.0.0", "echo evil-v1");
    let tgz_v2 = malicious_tarball("demo", "2.0.0", "echo evil-v2");
    let orig_int_v1 = sri_sha512(&tgz_v1);
    let orig_int_v2 = sri_sha512(&tgz_v2);

    let persist_dir = tmp_dir("cache");
    let proxy = spawn_proxy(persist_dir.clone()).await;

    let upstream = spawn_mock_upstream(
        Arc::new(Vec::new()), // placeholder; filled in below once we know the origin
        Arc::new(tgz_v1.clone()),
        Arc::new(tgz_v2.clone()),
    )
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.addr.port());

    // The packument has to embed the upstream's port in its
    // tarball URLs — re-spawn the upstream with the real packument
    // now that we know the origin. (Spawning twice is simpler than
    // threading the origin into the synthetic_packument call site
    // before the listener binds, and the second upstream replaces
    // the first on its own socket without conflict.)
    let packument = synthetic_packument(&origin, &tgz_v1, &tgz_v2);
    let upstream = spawn_mock_upstream(
        Arc::new(packument),
        Arc::new(tgz_v1.clone()),
        Arc::new(tgz_v2.clone()),
    )
    .await;
    let origin = format!("http://127.0.0.1:{}", upstream.addr.port());

    // Fetch the packument through the proxy. The npm rewriter +
    // speculative pre-strip both run in `handle_response`.
    let url = format!("{origin}/demo");
    let (status, body) = tokio::task::spawn_blocking(move || http_get(proxy, &url))
        .await
        .unwrap();
    assert_eq!(status, 200);

    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("packument response must parse as JSON");

    // ---- Assertion 1: both tagged versions had their integrity rewritten.
    let versions = parsed["versions"]
        .as_object()
        .expect("versions object survives rewrite");
    for ver in ["1.0.0", "2.0.0"] {
        let meta = versions
            .get(ver)
            .unwrap_or_else(|| panic!("version {ver} missing from rewritten packument"));
        let new_int = meta["dist"]["integrity"]
            .as_str()
            .unwrap_or_else(|| panic!("version {ver} missing dist.integrity"));
        let orig = if ver == "1.0.0" {
            &orig_int_v1
        } else {
            &orig_int_v2
        };
        assert_ne!(
            new_int, orig,
            "dist.integrity for {ver} must be rewritten post-strip (original was {orig}, response still says {new_int})",
        );
        assert!(
            new_int.starts_with("sha512-"),
            "rewritten integrity must keep the sha512- SRI prefix, got {new_int}",
        );

        // ---- Assertion 4: attestations dropped for stripped entries.
        assert!(
            meta["dist"].get("attestations").is_none(),
            "dist.attestations for {ver} must be removed post-strip (signature is over the original bytes; keeping it would mislead `npm install --provenance`)",
        );
    }

    // ---- Assertion 2: dist-tags survive (all three).
    let tags = parsed["dist-tags"]
        .as_object()
        .expect("dist-tags survive rewrite");
    assert_eq!(tags["latest"], "2.0.0");
    assert_eq!(tags["next"], "1.0.0");
    assert_eq!(tags["dup"], "2.0.0");

    // ---- Assertion 3: subsequent tarball fetches return stripped
    // bytes whose sha512 equals the rewritten integrity. This is
    // the bit that proves npm's first-attempt install would now
    // succeed without an EINTEGRITY retry.
    for (ver, expected_new_int) in [
        (
            "1.0.0",
            versions["1.0.0"]["dist"]["integrity"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        (
            "2.0.0",
            versions["2.0.0"]["dist"]["integrity"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
    ] {
        let url = format!("{origin}/demo/-/demo-{ver}.tgz");
        let (status, body) = tokio::task::spawn_blocking(move || http_get(proxy, &url))
            .await
            .unwrap();
        assert_eq!(status, 200, "tarball fetch for {ver}");
        let actual = sri_sha512(&body);
        assert_eq!(
            actual, expected_new_int,
            "tarball body for {ver} must hash to the integrity the rewritten packument advertised",
        );
        // Confirm body is actually stripped (postinstall removed
        // from the embedded package.json).
        let pkg_json_str = extract_root_package_json(&body);
        let v: serde_json::Value = serde_json::from_str(&pkg_json_str).unwrap();
        let scripts = v["scripts"].as_object().expect("scripts present");
        assert!(
            !scripts.contains_key("postinstall"),
            "tarball for {ver} must have postinstall stripped",
        );
        assert_eq!(scripts["test"], "jest", "non-lifecycle script must survive");
    }

    // ---- Assertion 5: dedup. Two dist-tags (`latest`, `dup`) both
    // pointed at 2.0.0. The upstream should have served exactly
    // one *speculative* fetch for 2.0.0 plus one client-driven
    // tarball fetch later = 2 total. v1 was tagged once → 1
    // speculative + 1 client-driven = 2 total. So we should never
    // see >2 fetches per version. Catches a regression where
    // dedup gets dropped and every dist-tag spawns its own
    // pre-strip task.
    assert!(
        upstream.fetch_count_v1.load(Ordering::Relaxed) <= 2,
        "v1 was fetched too many times — dedup or extra speculative fetch regression",
    );
    assert!(
        upstream.fetch_count_v2.load(Ordering::Relaxed) <= 2,
        "v2 was fetched too many times — `latest`+`dup` should dedupe, not double-fetch",
    );
}

/// Pull the root `package/package.json` body out of a gzipped tar
/// without depending on the strip-path internals.
fn extract_root_package_json(tgz: &[u8]) -> String {
    use flate2::read::GzDecoder;
    let mut archive = tar::Archive::new(GzDecoder::new(tgz));
    for entry in archive.entries().unwrap() {
        let mut e = entry.unwrap();
        let p = e.path().unwrap();
        if p.to_str() == Some("package/package.json") {
            let mut s = String::new();
            use std::io::Read;
            e.read_to_string(&mut s).unwrap();
            return s;
        }
    }
    panic!("package/package.json not found in tarball");
}
