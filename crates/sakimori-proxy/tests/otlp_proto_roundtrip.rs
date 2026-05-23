//! Strict OTLP/HTTP JSON shape validation.
//!
//! `proxy_otlp_e2e.rs` proves the exporter is wired into the install
//! decision path, but its assertions are field-by-field on a
//! `serde_json::Value` — they can't catch a payload that is *shaped*
//! correctly but uses a field name or value type a real
//! otel-collector would reject (e.g. emitting `timeUnixNano` as a
//! JSON number instead of a string, which violates the proto3→JSON
//! mapping for 64-bit ints).
//!
//! This file feeds the payload our exporter produces through
//! `opentelemetry-proto`'s generated message types. The proto-derived
//! `serde::Deserialize` impls enforce:
//!
//!  - canonical OTLP field names (camelCase on the wire),
//!  - int64 / fixed64 fields encoded as decimal strings,
//!  - `AnyValue` carrying exactly one of the documented variant keys
//!    (`stringValue`, `intValue`, `boolValue`, …),
//!  - `severityNumber` falling inside the OTLP enum range.
//!
//! If a future change starts emitting a non-OTLP shape, this test
//! breaks before the change can ship — without spending a CI minute
//! on a Docker-hosted collector.
//!
//! NOTE: the `package.*` attribute namespace itself is **not**
//! OpenTelemetry semantic-convention compliant — those keys are
//! sakimori-specific (see README "Semantic conventions" subsection).
//! This test validates the *envelope*, which is the bit a collector
//! parses; the attribute keys ride through as opaque strings.

use chrono::{DateTime, Utc};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueVariant;
use sakimori_core::deps::Ecosystem;
use sakimori_core::installs::{ExecutionMode, InstallEvent};
use sakimori_proxy::otlp::OtlpExporter;

fn fixed_event() -> InstallEvent {
    let mut ev = InstallEvent::new(Ecosystem::Npm, "left-pad", "1.3.0")
        .with_mode(ExecutionMode::Persistent)
        .with_user_agent("npm/10.0.0 node/20.0.0")
        .with_project_path("/work/repo");
    ev.resolved_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&Utc);
    ev
}

fn exporter() -> OtlpExporter {
    OtlpExporter::new(
        "https://otel.example.invalid/v1/logs".into(),
        vec![],
        "sakimori-test/0".into(),
    )
}

#[test]
fn payload_round_trips_through_opentelemetry_proto() {
    let payload = exporter().build_payload(&fixed_event());

    // The strict gate: the proto-derived `Deserialize` impl will
    // reject unknown variant tags inside AnyValue, the wrong JSON
    // type for int64 fields, missing oneof discriminators, etc.
    let parsed: ExportLogsServiceRequest =
        serde_json::from_value(payload).expect("OTLP payload must deserialize via proto types");

    // Envelope: 1 resource → 1 scope → 1 record.
    assert_eq!(parsed.resource_logs.len(), 1);
    let rl = &parsed.resource_logs[0];
    let resource = rl.resource.as_ref().expect("resource present");
    let service_name = resource
        .attributes
        .iter()
        .find(|kv| kv.key == "service.name")
        .and_then(|kv| kv.value.as_ref())
        .and_then(|v| v.value.as_ref())
        .expect("service.name attribute present");
    match service_name {
        AnyValueVariant::StringValue(s) => assert_eq!(s, "sakimori-proxy"),
        other => panic!("service.name must be stringValue, got {other:?}"),
    }

    assert_eq!(rl.scope_logs.len(), 1);
    let sl = &rl.scope_logs[0];
    let scope = sl.scope.as_ref().expect("instrumentation scope present");
    assert_eq!(scope.name, "sakimori-proxy");

    assert_eq!(sl.log_records.len(), 1);
    let lr = &sl.log_records[0];

    // 64-bit timestamp must have decoded — if the exporter ever
    // regresses to emitting a JSON number, the proto's Deserialize
    // bails before reaching this assertion.
    let expected_nanos = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .timestamp_nanos_opt()
        .unwrap() as u64;
    assert_eq!(lr.time_unix_nano, expected_nanos);
    assert_eq!(lr.observed_time_unix_nano, expected_nanos);

    // severityNumber must fall inside the OTLP enum (1..=24). The
    // proto-derived parser accepts any int32, so we re-check here.
    assert!(
        (1..=24).contains(&lr.severity_number),
        "severityNumber {} outside OTLP range",
        lr.severity_number
    );
    assert_eq!(lr.severity_text, "INFO");

    let body = lr
        .body
        .as_ref()
        .and_then(|v| v.value.as_ref())
        .expect("log body present");
    match body {
        AnyValueVariant::StringValue(s) => assert_eq!(s, "package install"),
        other => panic!("log body must be stringValue, got {other:?}"),
    }

    // Attribute namespace check — these keys are sakimori-specific
    // (not OTel semconv) but must at least all be present + carry
    // stringValue. Pinning the shape here means a future variant
    // change (e.g. switching `package.version` to intValue) trips
    // this test, which is the user-facing contract.
    let attr_keys: Vec<&str> = lr.attributes.iter().map(|kv| kv.key.as_str()).collect();
    for required in [
        "package.ecosystem",
        "package.name",
        "package.version",
        "package.resolved_at",
        "package.execution_mode",
        "package.project_path",
        "package.user_agent",
    ] {
        assert!(
            attr_keys.contains(&required),
            "required attribute `{required}` missing; got {attr_keys:?}"
        );
    }
    for kv in &lr.attributes {
        let v = kv
            .value
            .as_ref()
            .and_then(|v| v.value.as_ref())
            .unwrap_or_else(|| panic!("attribute {} has no value", kv.key));
        assert!(
            matches!(v, AnyValueVariant::StringValue(_)),
            "attribute {} must be stringValue (current contract), got {:?}",
            kv.key,
            v
        );
    }
}

#[test]
fn unknown_execution_mode_still_passes_proto_validation() {
    // Regression guard: the `unknown` enum-as-string mustn't
    // accidentally collide with anything the proto deserializer
    // treats specially.
    let mut ev = fixed_event();
    ev.execution_mode = ExecutionMode::Unknown;
    let payload = exporter().build_payload(&ev);
    let _: ExportLogsServiceRequest =
        serde_json::from_value(payload).expect("unknown-mode payload must still deserialize");
}
