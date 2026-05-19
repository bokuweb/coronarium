//! OTLP exporter end-to-end. Spins up a mock OTLP/HTTP collector,
//! drives a real install through the proxy, and asserts the
//! resulting log record carries the documented `package.*`
//! attributes in the right shape.
//!
//! Unit tests in `src/otlp.rs::tests` exercise `build_payload`
//! against a synthetic `InstallEvent`. This file proves the
//! exporter is actually wired into the install-decision path —
//! a regression that stopped firing on `Decision::Allow` would
//! pass the unit tests and silently lose every install record.
//!
//! Why plain HTTP (not HTTPS): OTLP is JSON over HTTP/1.1; the
//! exporter doesn't care about TLS. The proxy itself does need
//! to MITM HTTPS for real npm traffic, but the *install record
//! fan-out* is a separate code path that runs on the proxy host,
//! not on the wire to the package registry. We test that exact
//! path here by using the same plain-HTTP fixture
//! `proxy_http_e2e.rs` already uses (custom npm host = 127.0.0.1).

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use sakimori_core::deps::Ecosystem;
use sakimori_proxy::ca::CaFiles;
use sakimori_proxy::{AgeOracle, ProxyConfig, RegistryHosts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Test harness
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
        "sakimori-otlp-e2e-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

/// A minimal HTTP/1.1 server. Body is read until end-of-headers,
/// then `Content-Length` more bytes if present. Each request +
/// body is shoved into the shared `Vec<Vec<u8>>` so the test can
/// inspect what arrived. Always returns 200.
async fn spawn_capturing_http_server() -> (std::net::SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let records: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let r2 = records.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let records = r2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(8 * 1024);
                let mut tmp = [0u8; 4096];
                // Read until end-of-headers.
                let hdr_end = loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break pos + 4;
                            }
                            if buf.len() > 256 * 1024 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                };
                // Pull Content-Length out of headers.
                let header_str = std::str::from_utf8(&buf[..hdr_end]).unwrap_or("");
                let content_len = header_str
                    .lines()
                    .find_map(|line| {
                        let mut parts = line.splitn(2, ':');
                        let k = parts.next()?.trim();
                        let v = parts.next()?.trim();
                        if k.eq_ignore_ascii_case("content-length") {
                            v.parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                while buf.len() - hdr_end < content_len {
                    match sock.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                {
                    let mut g = records.lock().unwrap();
                    g.push(buf.clone());
                }
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, records)
}

/// Mock npm tarball upstream — same shape as
/// `proxy_http_e2e.rs::spawn_mock_upstream`, simplified.
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

/// Deterministic AgeOracle for tests. `None` means "unknown" —
/// useful for forcing the `fail_on_missing` deny path without
/// reaching the real registry.
struct FixedOracle(Option<DateTime<Utc>>);
impl AgeOracle for FixedOracle {
    fn published(
        &self,
        _eco: Ecosystem,
        _name: &str,
        _version: &str,
    ) -> anyhow::Result<Option<DateTime<Utc>>> {
        Ok(self.0)
    }
}

async fn spawn_proxy_with_otlp(otlp_endpoint: String) -> std::net::SocketAddr {
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
    // Inject a deterministic "always old enough" oracle so the
    // decision is `Allow` without reaching the real registry —
    // OTLP must fire on Allow.
    cfg.oracle = Some(Box::new(FixedOracle(Some(
        "2010-01-01T00:00:00Z".parse().unwrap(),
    ))));
    cfg.otlp_endpoint = Some(otlp_endpoint);

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

fn split_request(captured: &[u8]) -> (String, Vec<u8>) {
    let pos = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("captured request must have end-of-headers");
    let headers = String::from_utf8_lossy(&captured[..pos]).to_string();
    let body = captured[pos + 4..].to_vec();
    (headers, body)
}

fn find_attr<'a>(attrs: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    attrs
        .as_array()?
        .iter()
        .find(|a| a["key"] == key)
        .map(|a| &a["value"])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn otlp_exporter_fires_on_allowed_install() {
    let (otlp_addr, captured) = spawn_capturing_http_server().await;
    let tarball_body = b"not a real tarball, but fine for routing".to_vec();
    let upstream = spawn_mock_tarball_upstream(tarball_body).await;
    let proxy = spawn_proxy_with_otlp(format!("http://{otlp_addr}/v1/logs")).await;

    // Plain HTTP GET through the proxy for a pinned npm tarball.
    // The decision path: pinned npm host → age lookup (fails on
    // mock upstream) → `fail_on_missing = false` (default_dev) →
    // Decision::Allow → OTLP dispatch.
    let url = format!(
        "http://127.0.0.1:{}/lodash/-/lodash-4.17.21.tgz",
        upstream.port()
    );
    let proxy_spec = format!("http://{proxy}");
    let status = tokio::task::spawn_blocking(move || -> std::result::Result<u16, String> {
        let agent = ureq::AgentBuilder::new()
            .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
            .timeout(Duration::from_secs(5))
            .build();
        agent
            .get(&url)
            .call()
            .map(|r| r.status())
            .map_err(|e| format!("{e:?}"))
    })
    .await
    .unwrap()
    .expect("client GET through proxy");
    assert_eq!(status, 200);

    // OTLP dispatch runs on `spawn_blocking`; wait for it. Poll
    // up to ~3s. The `Mutex` lock is taken in a tight scope and
    // released before `await` (clippy::await_holding_lock).
    let captured = {
        let mut last = None;
        for _ in 0..60 {
            let snapshot = {
                let g = captured.lock().unwrap();
                if g.is_empty() { None } else { Some(g.clone()) }
            };
            if let Some(snapshot) = snapshot {
                last = Some(snapshot);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        last.expect("OTLP exporter must POST within 3s of the install")
    };
    assert_eq!(captured.len(), 1, "exactly one OTLP record expected");

    let (headers, body) = split_request(&captured[0]);
    assert!(
        headers.starts_with("POST /v1/logs HTTP/1.1\r\n"),
        "OTLP must POST to the configured /v1/logs path; got:\n{headers}"
    );
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("content-type: application/json"),
        "OTLP payload must be JSON; got:\n{headers}"
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&body).expect("OTLP body must parse as JSON");

    // Drill into the OTLP/JSON shape: resourceLogs[].scopeLogs[].logRecords[]
    let log_record = &payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
    let attrs = &log_record["attributes"];

    assert_eq!(
        find_attr(attrs, "package.ecosystem").and_then(|v| v["stringValue"].as_str()),
        Some("npm"),
        "package.ecosystem must be `npm`"
    );
    assert_eq!(
        find_attr(attrs, "package.name").and_then(|v| v["stringValue"].as_str()),
        Some("lodash"),
        "package.name must be `lodash`"
    );
    assert_eq!(
        find_attr(attrs, "package.version").and_then(|v| v["stringValue"].as_str()),
        Some("4.17.21"),
        "package.version must be `4.17.21`"
    );
    // execution_mode is best-effort from User-Agent. ureq's UA
    // doesn't match any known package manager, so we expect
    // `unknown` (not "persistent" or "ephemeral"). Pinning this
    // catches a future regression that mis-classifies arbitrary
    // clients as a known PM.
    assert_eq!(
        find_attr(attrs, "package.execution_mode").and_then(|v| v["stringValue"].as_str()),
        Some("unknown"),
        "ureq's UA must classify as `unknown` execution mode"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn otlp_exporter_silent_when_decision_is_deny() {
    // When the decision is Deny (here forced by setting
    // `fail_on_missing = true` so the missing age lookup denies),
    // OTLP must NOT fire — the exporter is bound to `Allow`. Pins
    // the contract documented at proxy.rs:1029-1036.
    let (otlp_addr, captured) = spawn_capturing_http_server().await;
    let upstream = spawn_mock_tarball_upstream(b"upstream body never reached".to_vec()).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let config_dir = tmp_dir("proxy-deny");
    std::fs::create_dir_all(&config_dir).unwrap();
    let mut cfg = ProxyConfig::default_dev().unwrap();
    cfg.listen = proxy_addr;
    cfg.ca_files = CaFiles::at(config_dir);
    cfg.install_log_enabled = false;
    cfg.registries = RegistryHosts {
        npm: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    // Oracle returns Ok(None) → unknown publish date. With
    // `fail_on_missing = true` the Decider denies.
    cfg.oracle = Some(Box::new(FixedOracle(None)));
    cfg.fail_on_missing = true;
    cfg.otlp_endpoint = Some(format!("http://{otlp_addr}/v1/logs"));
    tokio::spawn(async move {
        let _ = sakimori_proxy::run(cfg).await;
    });
    // Wait for ready.
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(proxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let url = format!(
        "http://127.0.0.1:{}/lodash/-/lodash-4.17.21.tgz",
        upstream.port()
    );
    let proxy_spec = format!("http://{proxy_addr}");
    let status = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
            .timeout(Duration::from_secs(5))
            .build();
        match agent.get(&url).call() {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(code, _)) => code,
            Err(e) => panic!("transport: {e:?}"),
        }
    })
    .await
    .unwrap();
    assert_eq!(status, 403, "missing-age + fail_on_missing must deny");

    // Wait a bit to make sure no OTLP request lands.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let g = captured.lock().unwrap();
    assert!(
        g.is_empty(),
        "OTLP exporter must NOT fire on Decision::Deny — captured: {} request(s)",
        g.len()
    );
}
