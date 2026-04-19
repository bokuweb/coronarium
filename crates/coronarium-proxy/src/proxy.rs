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
            return RequestOrResponse::Request(req);
        }
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
