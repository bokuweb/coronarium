//! Live end-to-end check: the real `HubIngestExporter` POSTing
//! into a **real running `sakimori-hub`**.
//!
//! `hub_ingest_e2e.rs` already pins the wire surface against a
//! mock HTTP server. This file goes one layer further: it points
//! the exporter at an *arbitrary* hub URL — the self-hosting
//! contract — and proves the event survives the whole hub
//! pipeline (ingest endpoint → Cloudflare Queue → consumer → D1)
//! by reading it back through the hub's inventory API.
//!
//! The failure it catches that the mock test cannot: a wire-shape
//! drift between this repo's `build_wire_event` and the hub's
//! `InstallEvent` serde mirror / valibot schema. A drift makes
//! the hub `400` the POST; the event never lands; this test's
//! poll times out. That cross-repo schema break is the
//! "memorable incident" class — exactly what an e2e is for.
//!
//! ## Running
//!
//! Skipped (early `return`, reported as a pass) unless
//! `SAKIMORI_HUB_E2E_URL` is set, so this is a no-op in the
//! normal `cargo test` run. The `bokuweb/sakimori-hub` repo's
//! `hub-ingest-e2e.yml` workflow starts a local hub and sets:
//!
//!   - `SAKIMORI_HUB_E2E_URL`   — hub origin, e.g.
//!     `http://127.0.0.1:8787` (any http/https URL works — that
//!     is the self-host contract this test exercises).
//!   - `SAKIMORI_HUB_E2E_TOKEN` — a team-scoped ingest token.
//!   - `SAKIMORI_HUB_E2E_TEAM`  — team slug (default `acme`).
//!
//! Read-back uses the hub's `/api/v1/teams/{slug}/events`
//! inventory API. That route is session-cookie-authed; the
//! workflow runs the hub with its loopback dev-auth bypass on, so
//! the GET resolves without a cookie. If the bypass is off the
//! read-back 401s and the test fails loudly — which is correct:
//! the harness is then misconfigured.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use sakimori_core::deps::Ecosystem;
use sakimori_core::installs::{ExecutionMode, InstallEvent};
use sakimori_proxy::hub_ingest::{HubIngestExporter, SakimoriToken};

/// How long to wait for the event to traverse ingest → Queue →
/// consumer → D1 and become visible on the inventory API.
const POLL_BUDGET: Duration = Duration::from_secs(40);
/// Gap between inventory polls.
const POLL_INTERVAL: Duration = Duration::from_millis(750);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_exporter_lands_one_event_in_a_real_hub() {
    let Ok(base) = std::env::var("SAKIMORI_HUB_E2E_URL") else {
        eprintln!(
            "hub_ingest_live: SAKIMORI_HUB_E2E_URL unset — skipping \
             (this is expected outside the hub-ingest-e2e workflow)"
        );
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let token = std::env::var("SAKIMORI_HUB_E2E_TOKEN")
        .expect("SAKIMORI_HUB_E2E_TOKEN must be set when SAKIMORI_HUB_E2E_URL is");
    let team = std::env::var("SAKIMORI_HUB_E2E_TEAM").unwrap_or_else(|_| "acme".to_string());

    // A unique (name, version) so the inventory poll cannot match
    // a row left by an earlier run or the dev seed.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let pkg_name = "sakimori-hub-ingest-e2e";
    let pkg_version = format!("0.0.0-e2e-{nonce}");

    // Point the REAL exporter at the (arbitrary) hub URL — the
    // self-host path. Team-scoped route + token.
    let exporter = Arc::new(HubIngestExporter::new(
        format!("{base}/v1/{team}/_team/events"),
        SakimoriToken::new(token),
        "sakimori-proxy/hub-ingest-live-e2e".to_string(),
    ));

    let mut event = InstallEvent::new(Ecosystem::Npm, pkg_name, pkg_version.clone())
        .with_mode(ExecutionMode::Persistent)
        .with_user_agent("sakimori-proxy/hub-ingest-live-e2e");
    event.resolved_at = Utc::now();

    // Fire-and-forget; the POST runs on a spawn_blocking worker.
    exporter.dispatch(&event);

    // Poll the inventory API until the event lands (or the budget
    // runs out). The hub pipeline is async: ingest 202s
    // immediately, the Queue consumer does the D1 insert a beat
    // later.
    let inventory_url = format!("{base}/api/v1/teams/{team}/events?limit=100");
    let deadline = Instant::now() + POLL_BUDGET;
    let mut last_diag = String::from("no inventory response observed");

    loop {
        if Instant::now() >= deadline {
            panic!(
                "event {pkg_name}@{pkg_version} did not appear on \
                 {inventory_url} within {}s — last: {last_diag}",
                POLL_BUDGET.as_secs(),
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;

        let url = inventory_url.clone();
        let fetch = tokio::task::spawn_blocking(move || http_get(&url))
            .await
            .expect("spawn_blocking join");

        match fetch {
            Ok(body) => {
                if inventory_contains(&body, pkg_name, &pkg_version) {
                    // Found it — the full ingest pipeline works.
                    return;
                }
                last_diag = format!("{} bytes, event not present yet", body.len());
            }
            Err(e) => {
                last_diag = e;
            }
        }
    }
}

/// Blocking HTTP GET. Returns the body on a 2xx, else a
/// diagnostic string (status / transport error) for the poll
/// loop to surface if the budget runs out.
fn http_get(url: &str) -> Result<String, String> {
    match ureq::get(url).timeout(Duration::from_millis(3000)).call() {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| format!("read body failed: {e}")),
        Err(ureq::Error::Status(code, _)) => {
            // 401 here means the hub's dev-auth bypass is off and
            // the inventory route still demands a cookie — a
            // harness misconfiguration worth a clear message.
            Err(format!("inventory GET returned HTTP {code}"))
        }
        Err(e) => Err(format!("inventory GET transport error: {e}")),
    }
}

/// True if the inventory JSON body carries an event whose `name`
/// and `version` both match. Parsed structurally rather than via
/// substring so a coincidental match elsewhere in the payload
/// can't produce a false pass.
fn inventory_contains(body: &str, name: &str, version: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(events) = value.get("events").and_then(|e| e.as_array()) else {
        return false;
    };
    events.iter().any(|ev| {
        ev.get("name").and_then(|n| n.as_str()) == Some(name)
            && ev.get("version").and_then(|v| v.as_str()) == Some(version)
    })
}
