// crates/node/tests/t29_9_state_sync_security.rs
use std::process::{Command, Stdio};
use std::time::Duration;
use std::thread::sleep;

mod common;
use common::wait_until_ready;

/// Helper: spawn a node with minimal args
fn spawn_node(datadir: &str, port: u16, extra: &[&str], envs: &[(&str, &str)]) -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_eezo-node");
    let mut cmd = Command::new(bin);
    cmd.arg("--datadir").arg(datadir)
       .arg("--listen").arg(format!("127.0.0.1:{port}"))
       .stdout(Stdio::null()).stderr(Stdio::null());
    for a in extra { cmd.arg(a); }
    for (k,v) in envs { cmd.env(k, v); }
    cmd.spawn().expect("spawn node")
}

#[cfg(any())] // T42.2: legacy behavior; disabled — node no longer exits on unsigned anchors
#[test]
fn t29_9_policy_require_signed_anchor_blocks_bootstrap_when_unsigned() {
    // Start a server with an unsigned anchor (current default)
    let server_port = 19231;
    let mut server = spawn_node("t29_9-srv-unsigned", server_port, &[], &[
        // use a fixed test chain id (20-byte hex handled by your config/parser)
        ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
    ]);
    assert!(wait_until_ready(server_port, 5_000), "server should become ready");

    // Start a client with DEFAULT policy (signatures required)
    let client_port = 19232;
    let mut client = spawn_node("t29_9-cli-require", client_port, &[], &[
        ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
        // NOTE: we do NOT set EEZO_SYNC_ALLOW_UNSIGNED_ANCHOR here
    ]);

    // Give the client some time to attempt bootstrap and fail hard
    sleep(Duration::from_millis(1200));
    // Assert the client process exited (bootstrap_entry returned Err) and not success
    match client.try_wait().expect("check client exit") {
        Some(status) => assert!(
            !status.success(),
            "client should exit with failure when unsigned anchors are required"
        ),
        None => panic!("client is still running; expected it to exit on unsigned anchor policy"),
    }

    // cleanup
    let _ = server.kill();
}

#[test]
fn t29_9_policy_allow_unsigned_anchor_bootstraps() {
    // Start a server with an unsigned anchor (current default)
    let server_port = 19241;
    let mut server = spawn_node("t29_9-srv-unsigned-2", server_port, &[], &[
        ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
    ]);
    assert!(wait_until_ready(server_port, 5_000));

    // Start a client with ALLOW policy for unsigned anchors (legacy interop)
    let client_port = 19242;
    let mut client = spawn_node("t29_9-cli-allow", client_port, &[], &[
        ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
        ("EEZO_SYNC_ALLOW_UNSIGNED_ANCHOR", "1"),
    ]);

    // Client should become ready
    assert!(wait_until_ready(client_port, 7_000), "client should bootstrap with allow-unsigned policy");

    // cleanup
    let _ = client.kill();
    let _ = server.kill();
}