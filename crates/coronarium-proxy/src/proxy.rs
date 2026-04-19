//! hudsucker-based MITM proxy. Wires the URL parser + age decider
//! into an HTTP request hook.
//!
//! The hook only MITM's traffic for hosts we have a parser for;
//! everything else is CONNECT-tunnelled through unchanged (see
//! [`should_intercept`]).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
    certificate_authority::RcgenAuthority,
    hyper::{Request, Response, StatusCode},
    rcgen::KeyPair,
};

use crate::ca::{CaFiles, ensure_ca, trust_instructions};
use crate::decision::{AgeOracle, Decider, Decision};
use crate::parser::{ParseResult, RegistryParser, default_parsers, parse_for_host};
use crate::rewrite::rewrite_crates_index_jsonl;

pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub min_age: Duration,
    pub fail_on_missing: bool,
    pub ca_files: CaFiles,
    pub user_agent: String,
    /// Override to inject a fake oracle in tests.
    pub oracle: Option<Box<dyn AgeOracle>>,
}

impl ProxyConfig {
    pub fn default_dev() -> Result<Self> {
        Ok(Self {
            listen: "127.0.0.1:0".parse().unwrap(),
            min_age: Duration::from_secs(7 * 24 * 3600),
            fail_on_missing: false,
            ca_files: CaFiles::at_default_location()?,
            user_agent: format!("coronarium-proxy/{}", env!("CARGO_PKG_VERSION")),
            oracle: None,
        })
    }
}

/// Start the proxy and run until it errors.
pub async fn run(cfg: ProxyConfig) -> Result<()> {
    // Ensure root CA exists, warn on first-run + print trust
    // instructions. Parsing them at startup is cheaper than failing
    // mid-request.
    let (cert_pem, key_pem, generated) = ensure_ca(&cfg.ca_files)?;
    if generated {
        eprintln!(
            "coronarium-proxy: generated root CA at {}\n\n\
             Trust this CA before running package managers through the proxy:\n\n{}",
            cfg.ca_files.cert_pem.display(),
            trust_instructions(&cfg.ca_files)
        );
    }

    let key = KeyPair::from_pem(&String::from_utf8_lossy(&key_pem))
        .context("loading CA key into rcgen")?;
    let ca_cert = rcgen_cert_from_pem(&cert_pem)?;
    let authority = RcgenAuthority::new(key, ca_cert, 1_000);

    let oracle: Box<dyn AgeOracle> = cfg
        .oracle
        .unwrap_or_else(|| Box::new(crate::decision::RegistryOracle::new(cfg.user_agent.clone())));
    let decider = Arc::new(Decider {
        oracle,
        min_age: cfg.min_age,
        fail_on_missing: cfg.fail_on_missing,
    });

    let handler = CoronariumHandler {
        parsers: Arc::new(default_parsers()),
        decider,
        last_host: None,
    };

    // `.build()` in hudsucker 0.22 returns Proxy<…> directly; no Result.
    let proxy = Proxy::builder()
        .with_addr(cfg.listen)
        .with_rustls_client()
        .with_ca(authority)
        .with_http_handler(handler)
        .build();

    log::info!("coronarium-proxy listening on {}", cfg.listen);
    proxy.start().await.context("proxy.start()")
}

fn rcgen_cert_from_pem(pem: &[u8]) -> Result<rcgen::Certificate> {
    let text = String::from_utf8_lossy(pem).to_string();
    let params =
        rcgen::CertificateParams::from_ca_cert_pem(&text).context("parsing CA cert PEM")?;
    let key = rcgen::KeyPair::generate().context("regen keypair for rcgen cert")?;
    let cert = params.self_signed(&key).context("re-sign CA cert")?;
    Ok(cert)
}

/// Only MITM traffic bound for hosts we care about. Everything else
/// gets passed through as an opaque TCP tunnel.
fn should_intercept(host: &str, parsers: &[Box<dyn RegistryParser>]) -> bool {
    parsers.iter().any(|p| host.eq_ignore_ascii_case(p.host()))
}

#[derive(Clone)]
struct CoronariumHandler {
    parsers: Arc<Vec<Box<dyn RegistryParser>>>,
    decider: Arc<Decider<dyn AgeOracle>>,
    /// Host of the in-flight request, captured in `handle_request` so
    /// `handle_response` knows whether to rewrite the body. hudsucker
    /// guarantees the same handler instance sees the matching pair.
    last_host: Option<String>,
}

impl HttpHandler for CoronariumHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // Host header is required; without it we can't route.
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();
        if !should_intercept(&host, &self.parsers) {
            self.last_host = None;
            return RequestOrResponse::Request(req);
        }
        self.last_host = Some(host.clone());
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        match parse_for_host(&self.parsers, &host, path) {
            ParseResult::Pinned {
                ecosystem,
                name,
                version,
            } => {
                let now = Utc::now();
                match self.decider.decide(ecosystem, &name, &version, now) {
                    Decision::Allow => RequestOrResponse::Request(req),
                    Decision::Deny { reason } => {
                        log::warn!("deny {host}{path}: {reason}");
                        RequestOrResponse::Response(deny_response(&reason))
                    }
                }
            }
            ParseResult::Metadata | ParseResult::Unknown => RequestOrResponse::Request(req),
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // Only rewrite the crates.io sparse index. Other hosts flow
        // through untouched so we don't risk corrupting binary tarballs
        // or metadata we haven't specifically handled.
        let is_sparse_index = matches!(self.last_host.as_deref(), Some("index.crates.io"));
        if !is_sparse_index {
            return res;
        }
        // 2xx only — preserve 404 / 304 / etc. as-is.
        if !res.status().is_success() {
            return res;
        }

        use http_body_util::BodyExt;
        let (parts, body) = res.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                log::warn!("sparse-rewrite: failed to buffer response body: {e}");
                // Best effort: return an empty body — safer than
                // forwarding a half-read stream.
                return Response::from_parts(parts, Body::empty());
            }
        };

        let now = Utc::now();
        let (rewritten, stats) = rewrite_crates_index_jsonl(&collected, &self.decider, now);
        if stats.dropped > 0 {
            log::info!(
                "sparse-rewrite: dropped {} version(s), kept {} (crates.io)",
                stats.dropped,
                stats.kept
            );
        }

        // Rebuild response with the new body. Strip Content-Length —
        // hyper will set it from the new Full body, and leaving a stale
        // length would confuse the client.
        let mut parts = parts;
        parts.headers.remove(http::header::CONTENT_LENGTH);
        // If the upstream used gzip/br etc. the filter already saw
        // plaintext (hudsucker doesn't auto-decode), so refuse to rewrite
        // encoded bodies — punt and return original.
        if let Some(enc) = parts.headers.get(http::header::CONTENT_ENCODING)
            && !enc.as_bytes().eq_ignore_ascii_case(b"identity")
        {
            log::debug!("sparse-rewrite: skipping non-identity Content-Encoding");
            return Response::from_parts(parts, Body::from(http_body_util::Full::new(collected)));
        }
        Response::from_parts(
            parts,
            Body::from(http_body_util::Full::new(bytes::Bytes::from(rewritten))),
        )
    }
}

fn deny_response(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-coronarium-deny", "minimum-release-age")
        .body(Body::from(format!("{reason}\n")))
        .expect("static response builder")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_intercept_matches_known_hosts_case_insensitively() {
        let ps = default_parsers();
        for host in [
            "crates.io",
            "CRATES.IO",
            "index.crates.io",
            "registry.npmjs.org",
            "files.pythonhosted.org",
            "api.nuget.org",
        ] {
            assert!(should_intercept(host, &ps), "should intercept {host}");
        }
        for host in ["evil.example.com", "pypi.org", "www.nuget.org"] {
            assert!(!should_intercept(host, &ps), "should NOT intercept {host}");
        }
    }

    #[test]
    fn deny_response_has_expected_shape() {
        let r = deny_response("nope");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            r.headers()
                .get("x-coronarium-deny")
                .and_then(|v| v.to_str().ok()),
            Some("minimum-release-age")
        );
    }
}
