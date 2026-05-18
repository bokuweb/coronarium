//! Real-network end-to-end: spin up `sakimori_proxy::run` on a TCP
//! socket, point a hand-rolled HTTP/1.1 mock upstream at another
//! TCP socket, and drive traffic through the proxy with a real
//! HTTP client. Exercises the **whole chain**:
//!
//!   client ── HTTP_PROXY ── sakimori_proxy ── upstream
//!
//! The unit + cross-module tests already cover parsers / rewriters
//! in isolation. This file is the only place we prove the full
//! wire pipeline works: hudsucker's handler invocation,
//! `handle_request` → `should_intercept` → `parse_for_host`,
//! upstream forwarding, response buffering, npm packument
//! rewriter, and the response body being delivered to the client
//! with the young version actually stripped.
//!
//! ## How TLS is avoided
//!
//! We use the **plain HTTP** proxy path (not HTTPS CONNECT
//! tunnelling). When a client sets `HTTP_PROXY=http://127.0.0.1:M`
//! and fetches `http://127.0.0.1:N/lodash`, the client sends the
//! request directly to the proxy with an absolute URI in the
//! request line and `Host: 127.0.0.1:N`. Hudsucker's HTTP path
//! calls `handle_request`, our handler parses the Host header
//! (port stripped → `127.0.0.1`), routes it through the npm
//! parser (because we configured `--npm-registry 127.0.0.1`),
//! forwards to the upstream URI, and rewrites the response
//! before sending it back.
//!
//! This avoids all the rustls / webpki-roots complexity that
//! would come with a self-signed HTTPS upstream while still
//! exercising the load-bearing parts of the proxy's request/
//! response lifecycle.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sakimori_proxy::{ProxyConfig, RegistryHosts, ca::CaFiles};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

fn tmp_config_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "sakimori-http-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// A minimal HTTP/1.1 server: accepts connections, reads the
/// request line + headers (terminated by `\r\n\r\n`), responds
/// with a canned body. Connection-per-request — the proxy opens
/// a fresh upstream connection each time, which is fine for
/// our tests.
async fn spawn_mock_upstream(
    response_body: Vec<u8>,
    content_type: &'static str,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(response_body);
    let ct = content_type.to_string();
    tokio::spawn(async move {
        loop {
            let (mut sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let body = body.clone();
            let ct = ct.clone();
            tokio::spawn(async move {
                // Drain request bytes until we see end-of-headers.
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
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

/// Start `sakimori_proxy::run` on a random local port with the
/// given `RegistryHosts`. Returns the bound `SocketAddr` and a
/// `Notify` callers can `drop` to leave the proxy task running
/// for the lifetime of the test process — the runtime takes care
/// of shutdown when the test exits.
async fn spawn_proxy(registries: RegistryHosts) -> std::net::SocketAddr {
    // Reserve a port (bind+drop) so we know what to tell the
    // caller. There's a TOCTOU window before `run` re-binds but
    // it's tolerable for tests; the OS rarely reuses a just-freed
    // ephemeral port within milliseconds on the same process.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config_dir = tmp_config_dir("proxy");
    std::fs::create_dir_all(&config_dir).unwrap();
    let ca_files = CaFiles::at(config_dir);

    let mut cfg = ProxyConfig::default_dev().unwrap();
    cfg.listen = addr;
    cfg.min_age = Duration::from_secs(30 * 86_400);
    cfg.ca_files = ca_files;
    cfg.registries = registries;
    // Don't write to the user's real install log during tests.
    cfg.install_log_enabled = false;

    tokio::spawn(async move {
        if let Err(e) = sakimori_proxy::run(cfg).await {
            eprintln!("proxy exited: {e:#}");
        }
    });

    // Wait for the proxy to actually accept connections — without
    // this, the first client request can race and hit a closed
    // socket. Poll up to ~3s.
    let ready = Arc::new(Notify::new());
    let ready2 = ready.clone();
    tokio::spawn(async move {
        for _ in 0..150 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready2.notify_one();
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    tokio::time::timeout(Duration::from_secs(5), ready.notified())
        .await
        .expect("proxy never came up");

    addr
}

/// Synchronous HTTP GET through the proxy, returning the response
/// body. Uses ureq's proxy support — keeps the test single-
/// threaded and obvious. Run inside `tokio::task::spawn_blocking`
/// because ureq blocks the calling thread.
fn http_get_through_proxy(proxy: std::net::SocketAddr, target_url: &str) -> (u16, Vec<u8>) {
    let proxy_spec = format!("http://{proxy}");
    let agent = ureq::AgentBuilder::new()
        .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
        .timeout(Duration::from_secs(10))
        .build();
    let resp = agent
        .get(target_url)
        .call()
        .expect("client GET through proxy");
    let status = resp.status();
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(4 * 1024 * 1024)
        .read_to_end(&mut buf)
        .unwrap();
    (status, buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Synthetic packument: one version 4 months old, one 5 days old.
/// `min_age = 30d` should drop only the young one. The `dist-tags`
/// retarget proves the rewriter is firing on a real HTTP response
/// (not just on a synthetic Vec<u8>).
fn synthetic_packument() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": "demo",
        "dist-tags": { "latest": "1.0.1" },
        "versions": {
            "1.0.0": { "name": "demo", "version": "1.0.0", "dist": {} },
            "1.0.1": { "name": "demo", "version": "1.0.1", "dist": {} },
        },
        "time": {
            // ~5 months old → kept under 30d threshold
            "1.0.0": "2025-12-15T00:00:00Z",
            // <30d old as of test runtime → dropped
            "1.0.1": (chrono::Utc::now() - chrono::Duration::days(5))
                .to_rfc3339(),
        }
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_npm_host_packument_rewritten_over_real_http() {
    let upstream = spawn_mock_upstream(synthetic_packument(), "application/json").await;

    // Configure the proxy to treat 127.0.0.1 as an npm registry.
    let registries = RegistryHosts {
        npm: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    let proxy = spawn_proxy(registries).await;

    let url = format!("http://{upstream}/demo");
    let (status, body) = tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
        .await
        .unwrap();

    assert_eq!(status, 200);
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("rewritten body is valid JSON");
    let versions = parsed["versions"]
        .as_object()
        .expect("versions object survives rewriting");
    assert!(
        versions.contains_key("1.0.0"),
        "old version 1.0.0 should remain: {parsed}"
    );
    assert!(
        !versions.contains_key("1.0.1"),
        "young version 1.0.1 should be dropped: {parsed}"
    );
    // dist-tags.latest retargeted onto the surviving newest.
    assert_eq!(parsed["dist-tags"]["latest"], "1.0.0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfigured_host_passes_through_unrewritten() {
    // Same upstream + proxy, but DON'T tell the proxy 127.0.0.1
    // is an npm registry. The packument should reach the client
    // byte-for-byte: the young version stays in.
    let upstream = spawn_mock_upstream(synthetic_packument(), "application/json").await;
    let proxy = spawn_proxy(RegistryHosts::default()).await;

    let url = format!("http://{upstream}/demo");
    let (status, body) = tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
        .await
        .unwrap();

    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let versions = parsed["versions"].as_object().unwrap();
    assert!(versions.contains_key("1.0.0"));
    assert!(
        versions.contains_key("1.0.1"),
        "young version must survive when host is not configured",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_packument_path_under_npm_host_is_unmodified() {
    // The npm rewriter only fires on packument paths (`/<pkg>` or
    // `/@scope/<pkg>`). A request to a tarball path is Pinned and
    // routes through the age-check decider, but a request to a
    // per-version metadata URL is Metadata and the body must pass
    // through unmodified.
    let canned = br#"{"hello":"world","not":"a packument"}"#.to_vec();
    let upstream = spawn_mock_upstream(canned.clone(), "application/json").await;
    let registries = RegistryHosts {
        npm: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    let proxy = spawn_proxy(registries).await;

    // `/demo/1.0.0` is a per-version manifest, not a packument.
    // The rewriter must not touch it; the client receives the
    // upstream body byte-for-byte.
    let url = format!("http://{upstream}/demo/1.0.0");
    let (status, body) = tokio::task::spawn_blocking(move || http_get_through_proxy(proxy, &url))
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, canned, "non-packument body must pass through");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_allow_blocks_unlisted_host_with_403() {
    // `--network-allow` is the egress firewall. When set, a
    // CONNECT or plain-HTTP request to a host not on the list
    // must come back as 403 before the upstream is even
    // contacted. Verify by listing a different IP and trying to
    // reach 127.0.0.1.
    let upstream = spawn_mock_upstream(b"should never be reached".to_vec(), "text/plain").await;

    let mut cfg = ProxyConfig::default_dev().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let config_dir = tmp_config_dir("allow");
    std::fs::create_dir_all(&config_dir).unwrap();
    cfg.listen = proxy_addr;
    cfg.ca_files = CaFiles::at(config_dir);
    cfg.install_log_enabled = false;
    cfg.network_allow = Some(
        sakimori_proxy::host_allow::HostMatcher::from_patterns(["only.allowed.example"]).unwrap(),
    );

    tokio::spawn(async move {
        let _ = sakimori_proxy::run(cfg).await;
    });
    // Wait for ready.
    for _ in 0..150 {
        if tokio::net::TcpStream::connect(proxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let url = format!("http://{upstream}/x");
    let proxy_spec = format!("http://{proxy_addr}");
    // Reduce the call result to a tiny owned shape inside the
    // blocking closure — `ureq::Error` is large enough to trip
    // `clippy::result-large-err` if returned across the await.
    let outcome: std::result::Result<u16, String> =
        tokio::task::spawn_blocking(move || -> std::result::Result<u16, String> {
            let agent = ureq::AgentBuilder::new()
                .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
                .timeout(Duration::from_secs(5))
                .build();
            match agent.get(&url).call() {
                Ok(r) => Ok(r.status()),
                Err(ureq::Error::Status(code, _)) => Err(format!("status:{code}")),
                Err(other) => Err(format!("transport:{other:?}")),
            }
        })
        .await
        .unwrap();

    match outcome {
        Err(s) if s == "status:403" => {} // expected
        Err(other) => panic!("expected status:403, got `{other}`"),
        Ok(code) => panic!("expected 403, got HTTP {code}"),
    }
}
