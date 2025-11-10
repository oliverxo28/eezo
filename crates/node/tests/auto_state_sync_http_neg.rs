// Negative tests for state-sync HTTP validation and JSON errors.
// Run with features:
// cargo test -p eezo-node --features "pq44-runtime,metrics,checkpoints,state-sync,state-sync-http" --test auto_state_sync_http_neg -j1 -- --nocapture

mod common;

use reqwest::blocking::Client;
use reqwest::StatusCode;
use std::time::Duration;

/// Small helper to GET and return (status, body)
fn http_get(port: u16, path_and_query: &str) -> (StatusCode, String) {
    let url = format!("http://127.0.0.1:{}{}", port, path_and_query);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(url).send().unwrap();
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    (status, body)
}

/// Snapshot: limit=0 should be rejected (limit must be 1..=1024)
#[test]
fn snapshot_rejects_zero_limit() {
    let port = 39101;
    let _guard = common::spawn_node_on_port(port);

    let (status, body) = http_get(port, "/state/snapshot?limit=0");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "status/body: {status:?} {body}"
    );
    assert!(body.contains("invalid_argument"), "body: {body}");
    assert!(body.to_lowercase().contains("limit"), "body: {body}");
}

/// Snapshot: limit too large should be rejected
#[test]
fn snapshot_rejects_too_large_limit() {
    let port = 39102;
    let _guard = common::spawn_node_on_port(port);

    let (status, body) = http_get(port, "/state/snapshot?limit=999999");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "status/body: {status:?} {body}"
    );
    assert!(body.contains("invalid_argument"), "body: {body}");
    assert!(body.to_lowercase().contains("limit"), "body: {body}");
}

/// Snapshot: invalid base64 prefix should be rejected
#[test]
fn snapshot_rejects_invalid_base64_prefix() {
    let port = 39103;
    let _guard = common::spawn_node_on_port(port);

    // invalid base64 (contains '@' and not padded properly)
    let (status, body) = http_get(port, "/state/snapshot?prefix=@@not_base64@@&limit=10");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "status/body: {status:?} {body}"
    );
    assert!(body.contains("invalid_argument"), "body: {body}");
    assert!(body.to_lowercase().contains("prefix"), "body: {body}");
}

/// Delta: inverted range (from > to) should be rejected
#[test]
fn delta_rejects_inverted_range() {
    let port = 39104;
    let _guard = common::spawn_node_on_port(port);

    let (status, body) = http_get(port, "/state/delta?from=50&to=10&limit=50");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "status/body: {status:?} {body}"
    );
    assert!(body.contains("invalid_argument"), "body: {body}");
    assert!(body.to_lowercase().contains("from_height"), "body: {body}");
}

/// Delta: span too large should be rejected (uses RANGE_SPAN_MAX=10000)
#[test]
fn delta_rejects_span_too_large() {
    let port = 39105;
    let _guard = common::spawn_node_on_port(port);

    // from=0, to=10001 -> span of 10001 > 10000
    let (status, body) = http_get(port, "/state/delta?from=0&to=10001&limit=50");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "status/body: {status:?} {body}"
    );
    assert!(body.contains("invalid_argument"), "body: {body}");
    assert!(body.to_lowercase().contains("range"), "body: {body}");
}

/// Delta: limit=0 should be rejected
#[test]
fn delta_rejects_zero_limit() {
    let port = 39106;
    let _guard = common::spawn_node_on_port(port);

    let (status, body) = http_get(port, "/state/delta?from=0&to=1&limit=0");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "status/body: {status:?} {body}"
    );
    assert!(body.contains("invalid_argument"), "body: {body}");
    assert!(body.to_lowercase().contains("limit"), "body: {body}");
}
