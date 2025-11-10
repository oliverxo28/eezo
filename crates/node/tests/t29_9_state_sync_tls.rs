use reqwest::blocking::Client;
use reqwest::StatusCode;
use std::time::{Duration, Instant};

mod common;
use common::{spawn_node, spawn_node_env};

/// Minimal local readiness poller (since `common::poll_ready` doesn’t exist)
fn poll_ready(url: &str, timeout_ms: u64) -> bool {
    let client = Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    println!("Polling readiness at: {}", url);
    while Instant::now() < deadline {
        match client.get(url).send() {
            Ok(resp) => {
                if resp.status() == StatusCode::OK {
                    println!("Received status: 200 OK");
                    return true;
                } else {
                    println!("Received status: {}", resp.status());
                }
            }
            Err(e) => {
                println!("Request to /ready failed: {}", e);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn t29_9_tls_client_against_http_server_is_unready() {
    // server: plain HTTP
    let server_port: u16 = 19261;
    // No special env needed for server; it always mounts state-sync endpoints with features.
    let mut server = spawn_node(
        "t29_9-tls-srv",
        &format!("127.0.0.1:{server_port}"),
        &[],
    );

    // Wait for server readiness (HTTP)
    assert!(
        poll_ready(&format!("http://127.0.0.1:{}/ready", server_port), 10000),
        "server did not become ready"
    );

    // client: turn TLS on; point at the HTTP server (mismatch should keep client unready)
    let client_port: u16 = 19262;
    // Dynamic value must be set via process env so the child inherits it.
    std::env::set_var(
        "EEZO_BOOTSTRAP_BASE_URL",
        format!("https://127.0.0.1:{server_port}"),
    );
    // Static values can be passed through spawn_node_env as &str pairs.
    let client_env: &[(&str, &str)] = &[
        ("EEZO_SYNC_TLS", "on"),
        ("EEZO_ENABLE_STATE_SYNC", "true"),
        ("EEZO_SYNC_MAX_RETRIES", "3"),
        ("EEZO_SYNC_BACKOFF_MS", "50"),
        ("EEZO_SYNC_BACKOFF_CAP_MS", "200"),
    ];
    let mut client = spawn_node_env(
        "t29_9-tls-cli",
        &format!("127.0.0.1:{client_port}"),
        client_env,
        &[],
    );

    // Client should remain unready due to TLS/HTTP mismatch
    let client_ready = poll_ready(
        &format!("http://127.0.0.1:{}/ready", client_port),
        5000,
    );
    assert!(
        !client_ready,
        "client unexpectedly ready with TLS against HTTP server"
    );

    // Clean up
    let _ = client.kill();
    let _ = server.kill();
    
    // Clean up dynamic env to avoid leaking into other tests
    std::env::remove_var("EEZO_BOOTSTRAP_BASE_URL");
}