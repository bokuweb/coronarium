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
use crate::rewrite_npm::{NpmRewriteOptions, rewrite_npm_packument_with};
use crate::rewrite_nuget::rewrite_nuget_registration;
use crate::rewrite_pypi::{rewrite_pypi_json_api, rewrite_pypi_simple_json};

pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub min_age: Duration,
    pub fail_on_missing: bool,
    /// Strict mode: when `true`, npm packument rewriting drops every
    /// version without a Sigstore provenance claim (see
    /// [`crate::rewrite_npm::NpmRewriteOptions`]). This is the
    /// strongest single knob against "stolen publish token" attacks
    /// that `minimumReleaseAge` alone can't catch.
    pub require_provenance: bool,
    /// When `true`, consult OSV.dev before every age check. Versions
    /// flagged as malicious packages (MAL-* IDs or advisories whose
    /// summary/details contain "malicious") are hard-denied
    /// regardless of `--min-age`.
    pub osv: bool,
    /// When `true`, additionally consume the coronarium-hosted OSV
    /// mirror (pre-filtered to malicious-package advisories) for
    /// O(1) local lookups. Layered in front of live OSV: mirror
    /// hit short-circuits, miss cascades to live when `osv` is
    /// also on.
    pub osv_mirror: bool,
    /// Override URL for `osv_mirror`. Defaults to
    /// [`crate::osv_mirror::DEFAULT_MIRROR_URL`].
    pub osv_mirror_url: Option<String>,
    /// Typosquat detection mode: `None` disables, `Some(Warn)` logs
    /// close-match warnings, `Some(Block)` hard-denies typosquat
    /// candidates.
    pub typosquat: Option<crate::decision::TyposquatMode>,
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
            require_provenance: false,
            osv: false,
            osv_mirror: false,
            osv_mirror_url: None,
            typosquat: None,
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
    // Compose the known-bad oracle chain. Up to three layers:
    //   mirror (local HashMap) → live OSV API → None
    // Only the `osv_mirror` layer runs a background task; the live
    // client is a lazy-per-request HTTP lookup.
    let known_bad: Option<Box<dyn crate::osv::KnownBadOracle>> = match (cfg.osv_mirror, cfg.osv) {
        (false, false) => None,
        (true, false) => {
            let url = cfg
                .osv_mirror_url
                .clone()
                .unwrap_or_else(|| crate::osv_mirror::DEFAULT_MIRROR_URL.to_string());
            log::info!("OSV known-malicious check: mirror only ({url})");
            let mirror = crate::osv_mirror::OsvMirrorOracle::with_url(cfg.user_agent.clone(), url);
            mirror.spawn_refresh_loop();
            Some(Box::new(mirror))
        }
        (false, true) => {
            log::info!("OSV known-malicious check: live API only (api.osv.dev)");
            Some(Box::new(crate::osv::OsvClient::new(cfg.user_agent.clone())))
        }
        (true, true) => {
            let url = cfg
                .osv_mirror_url
                .clone()
                .unwrap_or_else(|| crate::osv_mirror::DEFAULT_MIRROR_URL.to_string());
            log::info!("OSV known-malicious check: mirror ({url}) + live API fallback");
            let mirror = crate::osv_mirror::OsvMirrorOracle::with_url(cfg.user_agent.clone(), url);
            mirror.spawn_refresh_loop();
            Some(Box::new(crate::osv_mirror::LayeredKnownBad {
                primary: Box::new(mirror),
                fallback: Box::new(crate::osv::OsvClient::new(cfg.user_agent.clone())),
            }))
        }
    };
    let typosquat = cfg.typosquat.map(|mode| {
        log::info!("typosquat detection: {:?}", mode);
        crate::decision::TyposquatHook {
            detector: crate::typosquat::Detector::new(),
            mode,
        }
    });
    let decider = Arc::new(Decider {
        oracle,
        min_age: cfg.min_age,
        fail_on_missing: cfg.fail_on_missing,
        known_bad,
        typosquat,
    });

    let handler = CoronariumHandler {
        parsers: Arc::new(default_parsers()),
        decider,
        last_host: None,
        last_path: None,
        require_provenance: cfg.require_provenance,
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
    /// Path of the in-flight request. Used to decide whether an
    /// `registry.npmjs.org` response is a packument (bare `/<pkg>`) —
    /// per-version endpoints and tarballs must be left untouched.
    last_path: Option<String>,
    /// Forwarded from [`ProxyConfig::require_provenance`]. Consulted
    /// by the npm rewrite path.
    require_provenance: bool,
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
            self.last_path = None;
            return RequestOrResponse::Request(req);
        }
        self.last_host = Some(host.clone());
        let path: String = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        self.last_path = Some(path.clone());
        // Force upstream to send us plain-body responses so our
        // rewriters see JSON / JSONL directly. Without this, npm
        // and pypi will gzip-encode and we'd have to decode+reencode
        // to filter — hudsucker doesn't decode response bodies for
        // us. Tarballs are content-encoded, not transfer-encoded,
        // so this flag doesn't inflate their wire size.
        let mut req = req;
        req.headers_mut().insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("identity"),
        );
        match parse_for_host(&self.parsers, &host, &path) {
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
        // Decide whether and how to rewrite based on host + path. Only
        // endpoints we specifically understand get touched; everything
        // else flows through byte-for-byte.
        let Some(target) = classify_response(self.last_host.as_deref(), self.last_path.as_deref())
        else {
            return res;
        };
        // 2xx only — preserve 404 / 304 / etc. as-is.
        if !res.status().is_success() {
            return res;
        }

        use http_body_util::BodyExt;
        let (mut parts, body) = res.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                log::warn!("rewrite: failed to buffer response body: {e}");
                return Response::from_parts(parts, Body::empty());
            }
        };

        // If the upstream used gzip/br etc. the filter would see
        // opaque bytes (hudsucker doesn't auto-decode), so refuse to
        // rewrite encoded bodies — pass them through instead.
        if let Some(enc) = parts.headers.get(http::header::CONTENT_ENCODING)
            && !enc.as_bytes().eq_ignore_ascii_case(b"identity")
        {
            log::debug!("rewrite: skipping non-identity Content-Encoding");
            return Response::from_parts(parts, Body::from(http_body_util::Full::new(collected)));
        }

        let now = Utc::now();
        let rewritten = match target {
            RewriteTarget::CratesSparse => {
                let (out, stats) = rewrite_crates_index_jsonl(&collected, &self.decider, now);
                if stats.dropped > 0 {
                    log::info!(
                        "sparse-rewrite: dropped {} version(s), kept {} (crates.io)",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
            RewriteTarget::NpmPackument => {
                let (out, stats) = rewrite_npm_packument_with(
                    &collected,
                    self.decider.min_age,
                    now,
                    NpmRewriteOptions {
                        require_provenance: self.require_provenance,
                    },
                );
                if stats.dropped > 0 {
                    log::info!(
                        "npm-rewrite: dropped {} version(s) ({} for missing provenance), kept {}, retargeted {} tag(s)",
                        stats.dropped,
                        stats.dropped_no_provenance,
                        stats.kept,
                        stats.retargeted_tags
                    );
                }
                out
            }
            RewriteTarget::PypiJsonApi => {
                let (out, stats) = rewrite_pypi_json_api(&collected, self.decider.min_age, now);
                if stats.dropped > 0 {
                    log::info!(
                        "pypi-rewrite(json): dropped {} version(s), kept {}",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
            RewriteTarget::PypiSimpleJson => {
                // PEP 691 Simple JSON and PEP 503 HTML share the
                // `/simple/<pkg>/` path — distinguish by Content-Type.
                // Anything other than `application/vnd.pypi.simple.v1+json`
                // (the only JSON shape we currently handle) passes through.
                let is_simple_json = parts
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|h| h.to_str().ok())
                    .map(|ct| {
                        let ct = ct.to_ascii_lowercase();
                        ct.contains("application/vnd.pypi.simple.v1+json")
                            || ct.contains("application/vnd.pypi.simple.latest+json")
                    })
                    .unwrap_or(false);
                if !is_simple_json {
                    log::debug!("pypi-rewrite(simple): pass-through (non-JSON Content-Type)");
                    return Response::from_parts(
                        parts,
                        Body::from(http_body_util::Full::new(collected)),
                    );
                }
                let (out, stats) = rewrite_pypi_simple_json(&collected, self.decider.min_age, now);
                if stats.dropped > 0 {
                    log::info!(
                        "pypi-rewrite(simple): dropped {} file(s), kept {}",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
            RewriteTarget::NugetRegistration => {
                let (out, stats) =
                    rewrite_nuget_registration(&collected, self.decider.min_age, now);
                if stats.dropped > 0 {
                    log::info!(
                        "nuget-rewrite: dropped {} version(s), kept {}",
                        stats.dropped,
                        stats.kept
                    );
                }
                out
            }
        };

        // Strip Content-Length so hyper recomputes it from the new body.
        parts.headers.remove(http::header::CONTENT_LENGTH);
        Response::from_parts(
            parts,
            Body::from(http_body_util::Full::new(bytes::Bytes::from(rewritten))),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RewriteTarget {
    CratesSparse,
    NpmPackument,
    PypiJsonApi,
    PypiSimpleJson,
    NugetRegistration,
}

/// Match the in-flight `(host, path)` to a rewriter. Returning `None`
/// means "pass the response through unchanged".
///
/// For npm we only rewrite the bare packument endpoint `/<pkg>` or
/// `/@scope/<pkg>`. Per-version manifests (`/<pkg>/<version>`) and
/// tarballs (`/<pkg>/-/<tgz>`) are not packuments and would be
/// corrupted by packument-shaped filtering.
fn classify_response(host: Option<&str>, path: Option<&str>) -> Option<RewriteTarget> {
    let host = host?;
    let path = path?;
    if host.eq_ignore_ascii_case("index.crates.io") {
        return Some(RewriteTarget::CratesSparse);
    }
    if host.eq_ignore_ascii_case("registry.npmjs.org") && is_npm_packument_path(path) {
        return Some(RewriteTarget::NpmPackument);
    }
    if host.eq_ignore_ascii_case("pypi.org") {
        if is_pypi_json_api_path(path) {
            return Some(RewriteTarget::PypiJsonApi);
        }
        if is_pypi_simple_path(path) {
            // We can't distinguish HTML vs JSON by path alone — the
            // client's Accept header decides, and the upstream
            // response's Content-Type confirms. The handler inspects
            // Content-Type at rewrite time and skips HTML bodies.
            return Some(RewriteTarget::PypiSimpleJson);
        }
    }
    if host.eq_ignore_ascii_case("api.nuget.org") && is_nuget_registration_path(path) {
        return Some(RewriteTarget::NugetRegistration);
    }
    None
}

/// NuGet registration endpoints:
/// - `/v3/registration<X>*/<id>/index.json` (top-level index)
/// - `/v3/registration<X>*/<id>/page/<lower>/<upper>.json` (paged)
///
/// `<X>*` is one of the many versioned URL bases NuGet publishes
/// (`registration5-semver1`, `registration5-gz-semver2`, …). We match
/// any prefix starting with `registration` so new endpoints added by
/// NuGet don't require a code change.
fn is_nuget_registration_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let rest = match path.strip_prefix("/v3/") {
        Some(r) => r,
        None => return false,
    };
    let mut parts = rest.splitn(2, '/');
    let base = parts.next().unwrap_or("");
    let tail = parts.next().unwrap_or("");
    if !base.starts_with("registration") {
        return false;
    }
    // index.json or page/<lower>/<upper>.json anywhere in the tail.
    tail.ends_with("/index.json") || (tail.contains("/page/") && tail.ends_with(".json"))
}

/// `GET /pypi/<pkg>/json` — the Warehouse legacy JSON API.
fn is_pypi_json_api_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    // Accept both `/pypi/<pkg>/json` and `/pypi/<pkg>/<version>/json`.
    path.starts_with("/pypi/") && path.trim_end_matches('/').ends_with("/json")
}

/// `GET /simple/<pkg>/` — PEP 503 simple index (HTML) or PEP 691 JSON.
fn is_pypi_simple_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    if let Some(rest) = path.strip_prefix("/simple/") {
        let rest = rest.trim_end_matches('/');
        !rest.is_empty() && !rest.contains('/')
    } else {
        false
    }
}

fn is_npm_packument_path(path: &str) -> bool {
    // Strip query string and trim trailing slash.
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches('/');
    let trimmed = match path.strip_prefix('/') {
        Some(p) => p,
        None => return false,
    };
    if trimmed.is_empty() {
        return false;
    }
    // Scoped packages: "/@scope/name" — exactly one slash after the
    // leading "@". Unscoped packages: "/name" — zero slashes.
    if let Some(rest) = trimmed.strip_prefix('@') {
        // "scope/name" — exactly one remaining '/', no further path parts
        let mut parts = rest.splitn(3, '/');
        let scope = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");
        let extra = parts.next();
        !scope.is_empty() && !name.is_empty() && extra.is_none()
    } else {
        // Unscoped: must not contain any '/'
        !trimmed.contains('/')
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
            "pypi.org",
            "api.nuget.org",
        ] {
            assert!(should_intercept(host, &ps), "should intercept {host}");
        }
        for host in ["evil.example.com", "www.nuget.org"] {
            assert!(!should_intercept(host, &ps), "should NOT intercept {host}");
        }
    }

    #[test]
    fn npm_packument_path_matches_unscoped_and_scoped_names_only() {
        // Packument endpoints.
        assert!(is_npm_packument_path("/lodash"));
        assert!(is_npm_packument_path("/lodash/"));
        assert!(is_npm_packument_path("/@types/node"));
        assert!(is_npm_packument_path("/@types/node/"));

        // Per-version manifests — NOT packuments.
        assert!(!is_npm_packument_path("/lodash/4.17.21"));
        assert!(!is_npm_packument_path("/@types/node/20.0.0"));

        // Tarballs — NOT packuments.
        assert!(!is_npm_packument_path("/lodash/-/lodash-4.17.21.tgz"));
        assert!(!is_npm_packument_path("/@types/node/-/node-20.0.0.tgz"));

        // Malformed.
        assert!(!is_npm_packument_path(""));
        assert!(!is_npm_packument_path("/"));
        assert!(!is_npm_packument_path("/@scope"));
    }

    #[test]
    fn pypi_json_api_path_matches_warehouse_shape() {
        assert!(is_pypi_json_api_path("/pypi/requests/json"));
        assert!(is_pypi_json_api_path("/pypi/requests/json/"));
        assert!(is_pypi_json_api_path("/pypi/requests/2.32.4/json"));
        assert!(!is_pypi_json_api_path("/simple/requests/"));
        assert!(!is_pypi_json_api_path("/pypi/requests/"));
        assert!(!is_pypi_json_api_path("/"));
    }

    #[test]
    fn pypi_simple_path_matches_index_shape() {
        assert!(is_pypi_simple_path("/simple/requests/"));
        assert!(is_pypi_simple_path("/simple/requests"));
        assert!(!is_pypi_simple_path("/simple/requests/2.32.4/"));
        assert!(!is_pypi_simple_path("/simple/"));
        assert!(!is_pypi_simple_path("/pypi/requests/json"));
    }

    #[test]
    fn nuget_registration_path_matches_index_and_page_shapes() {
        assert!(is_nuget_registration_path(
            "/v3/registration5-semver1/newtonsoft.json/index.json"
        ));
        assert!(is_nuget_registration_path(
            "/v3/registration5-gz-semver2/serilog/index.json"
        ));
        assert!(is_nuget_registration_path(
            "/v3/registration5-semver1/pkg/page/1.0.0/9.9.9.json"
        ));
        // Not registration.
        assert!(!is_nuget_registration_path(
            "/v3-flatcontainer/pkg/index.json"
        ));
        assert!(!is_nuget_registration_path("/v3/search-query"));
        assert!(!is_nuget_registration_path("/"));
    }

    #[test]
    fn classify_response_routes_to_correct_rewriter() {
        assert_eq!(
            classify_response(Some("index.crates.io"), Some("/anything")),
            Some(RewriteTarget::CratesSparse)
        );
        assert_eq!(
            classify_response(Some("registry.npmjs.org"), Some("/lodash")),
            Some(RewriteTarget::NpmPackument)
        );
        // tarball path — npm but not a packument
        assert_eq!(
            classify_response(
                Some("registry.npmjs.org"),
                Some("/lodash/-/lodash-4.17.21.tgz")
            ),
            None
        );
        // PyPI endpoints
        assert_eq!(
            classify_response(Some("pypi.org"), Some("/pypi/requests/json")),
            Some(RewriteTarget::PypiJsonApi)
        );
        assert_eq!(
            classify_response(Some("pypi.org"), Some("/simple/requests/")),
            Some(RewriteTarget::PypiSimpleJson)
        );
        assert_eq!(classify_response(Some("pypi.org"), Some("/")), None);
        // NuGet registration.
        assert_eq!(
            classify_response(
                Some("api.nuget.org"),
                Some("/v3/registration5-semver1/newtonsoft.json/index.json")
            ),
            Some(RewriteTarget::NugetRegistration)
        );
        // NuGet flat-container is NOT rewritten yet.
        assert_eq!(
            classify_response(
                Some("api.nuget.org"),
                Some("/v3-flatcontainer/newtonsoft.json/index.json")
            ),
            None
        );
        // unrecognised host
        assert_eq!(
            classify_response(Some("evil.example.com"), Some("/foo")),
            None
        );
        assert_eq!(classify_response(None, Some("/foo")), None);
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
