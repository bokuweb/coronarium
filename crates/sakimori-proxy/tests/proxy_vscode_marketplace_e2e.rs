//! End-to-end: VS Code Marketplace `extensionquery` rewriter
//! exercised over real HTTP through the proxy.
//!
//!   client ── HTTP_PROXY ── sakimori_proxy ── upstream
//!
//! Mirrors the architecture of [`proxy_http_e2e.rs`] (plain-HTTP
//! path, no TLS) but POSTs to the two `extensionquery` endpoint
//! shapes the proxy recognises (Microsoft's `/_apis/public/
//! gallery/extensionquery` and OpenVSX's `/vscode/gallery/
//! extensionquery` compatibility shim), and asserts the response
//! the client sees has too-young `versions[]` entries stripped
//! while old ones survive.
//!
//! Unit tests in `rewrite_vscode.rs` already cover every
//! algorithmic branch of the rewriter; this file is the only
//! place we prove the full hyper / hudsucker / `classify_response`
//! → `RewriteTarget::VscodeExtensionQuery` → body-rewrite pipeline
//! works on the wire.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sakimori_proxy::{ProxyConfig, RegistryHosts, ca::CaFiles};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

fn tmp_config_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "sakimori-vscode-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// HTTP/1.1 mock that consumes the request (including a
/// `Content-Length`-bounded body so the client can flush a POST
/// cleanly) and returns the canned response body. Connection-per-
/// request — the proxy opens a fresh upstream connection for each
/// rewrite candidate, which matches production behaviour.
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
                let mut buf = Vec::with_capacity(2048);
                let mut tmp = [0u8; 1024];
                // Drain headers.
                let header_end;
                loop {
                    match sock.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(i) = (0..=buf.len().saturating_sub(4))
                                .find(|&i| &buf[i..i + 4] == b"\r\n\r\n")
                            {
                                header_end = i + 4;
                                break;
                            }
                            if buf.len() > 64 * 1024 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                // Parse Content-Length from the request headers so we
                // can drain the POST body before responding. Without
                // this the proxy may see EPIPE on the upstream socket
                // while still trying to forward the request.
                let header_bytes = &buf[..header_end];
                let header_str = std::str::from_utf8(header_bytes).unwrap_or("");
                let content_length: usize = header_str
                    .lines()
                    .find_map(|l| {
                        let mut parts = l.splitn(2, ':');
                        let k = parts.next()?.trim();
                        let v = parts.next()?.trim();
                        if k.eq_ignore_ascii_case("content-length") {
                            v.parse().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let already_have = buf.len() - header_end;
                if content_length > already_have {
                    let mut remaining = content_length - already_have;
                    while remaining > 0 {
                        match sock.read(&mut tmp).await {
                            Ok(0) => break,
                            Ok(n) => remaining = remaining.saturating_sub(n),
                            Err(_) => break,
                        }
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

async fn spawn_proxy(registries: RegistryHosts) -> std::net::SocketAddr {
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
    cfg.install_log_enabled = false;

    tokio::spawn(async move {
        if let Err(e) = sakimori_proxy::run(cfg).await {
            eprintln!("proxy exited: {e:#}");
        }
    });

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

fn http_post_through_proxy(
    proxy: std::net::SocketAddr,
    target_url: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let proxy_spec = format!("http://{proxy}");
    let agent = ureq::AgentBuilder::new()
        .proxy(ureq::Proxy::new(&proxy_spec).unwrap())
        .timeout(Duration::from_secs(10))
        .build();
    let resp = agent
        .post(target_url)
        .set("Content-Type", "application/json")
        .send_bytes(body)
        .expect("client POST through proxy");
    let status = resp.status();
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(4 * 1024 * 1024)
        .read_to_end(&mut buf)
        .unwrap();
    (status, buf)
}

/// Build an `extensionquery` response with one old version and one
/// young version. The proxy's rewriter, configured with
/// `--min-age 30d`, should drop the young one and keep the old.
fn synthetic_extensionquery_json() -> Vec<u8> {
    let young = (chrono::Utc::now() - chrono::Duration::days(5)).to_rfc3339();
    let old = "2024-06-01T12:00:00Z";
    serde_json::to_vec(&serde_json::json!({
        "results": [{
            "extensions": [{
                "publisher": {"publisherName": "ms-vscode"},
                "extensionName": "vscode-eslint",
                "versions": [
                    {"version": "3.0.10", "lastUpdated": young},
                    {"version": "3.0.9",  "lastUpdated": old},
                ]
            }]
        }]
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vscode_marketplace_extensionquery_rewritten_over_real_http() {
    let upstream = spawn_mock_upstream(synthetic_extensionquery_json(), "application/json").await;

    let registries = RegistryHosts {
        vscode_marketplace: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    let proxy = spawn_proxy(registries).await;

    // Microsoft's canonical path.
    let url = format!("http://{upstream}/_apis/public/gallery/extensionquery");
    let (status, body) = tokio::task::spawn_blocking(move || {
        http_post_through_proxy(proxy, &url, br#"{"filters":[]}"#)
    })
    .await
    .unwrap();

    assert_eq!(status, 200);
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("rewritten body is valid JSON");
    let versions = parsed["results"][0]["extensions"][0]["versions"]
        .as_array()
        .expect("versions[] survives rewriting");
    let kept: Vec<&str> = versions
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(kept, vec!["3.0.9"], "young 3.0.10 should be stripped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openvsx_vscode_gallery_path_also_rewritten() {
    // OpenVSX exposes a VS Code-compatibility shim at
    // `/vscode/gallery/extensionquery`. The proxy must route this
    // through the same rewriter even though the URL path differs
    // from Microsoft's `/_apis/...`.
    let upstream = spawn_mock_upstream(synthetic_extensionquery_json(), "application/json").await;
    let registries = RegistryHosts {
        vscode_marketplace: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    let proxy = spawn_proxy(registries).await;

    let url = format!("http://{upstream}/vscode/gallery/extensionquery");
    let (status, body) = tokio::task::spawn_blocking(move || {
        http_post_through_proxy(proxy, &url, br#"{"filters":[]}"#)
    })
    .await
    .unwrap();

    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let versions = parsed["results"][0]["extensions"][0]["versions"]
        .as_array()
        .unwrap();
    let kept: Vec<&str> = versions
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(kept, vec!["3.0.9"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfigured_host_passes_extensionquery_through_unrewritten() {
    // Default registries (no 127.0.0.1 in vscode_marketplace) → the
    // proxy doesn't recognise this host as a marketplace and the
    // body reaches the client unchanged. Young version survives.
    let upstream = spawn_mock_upstream(synthetic_extensionquery_json(), "application/json").await;
    let proxy = spawn_proxy(RegistryHosts::default()).await;

    let url = format!("http://{upstream}/_apis/public/gallery/extensionquery");
    let (status, body) = tokio::task::spawn_blocking(move || {
        http_post_through_proxy(proxy, &url, br#"{"filters":[]}"#)
    })
    .await
    .unwrap();
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let versions = parsed["results"][0]["extensions"][0]["versions"]
        .as_array()
        .unwrap();
    assert_eq!(
        versions.len(),
        2,
        "untouched body should keep both versions"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrecognised_path_under_marketplace_host_is_passed_through() {
    // A request to a non-extensionquery path on a configured
    // marketplace host falls through `classify_response` and the
    // upstream body reaches the client byte-for-byte. Important
    // because the marketplace also serves asset URIs, telemetry
    // endpoints, etc. that the rewriter must not touch.
    let canned = br#"{"hello":"world","not":"an extensionquery"}"#.to_vec();
    let upstream = spawn_mock_upstream(canned.clone(), "application/json").await;
    let registries = RegistryHosts {
        vscode_marketplace: vec!["127.0.0.1".into()],
        ..RegistryHosts::default()
    };
    let proxy = spawn_proxy(registries).await;

    let url = format!("http://{upstream}/some/other/path");
    let (status, body) =
        tokio::task::spawn_blocking(move || http_post_through_proxy(proxy, &url, br#"{}"#))
            .await
            .unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, canned, "non-extensionquery body must pass through");
}
