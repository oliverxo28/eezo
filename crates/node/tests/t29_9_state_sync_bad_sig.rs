// crates/node/tests/t29_9_state_sync_bad_sig.rs
#![cfg(any())]
#![cfg(any())]
// NOTE (T42.2):
// This test was written for an older state-sync design where any bad anchor
// signature was treated as a fatal condition and the client process was
// expected to exit. After T42.x hardening we allow nodes to remain up and
// "ready" even if state-sync/bootstrap fails, so this behavior is no longer
// desired. We disable this legacy test until a new state-sync v2 contract is
// defined.

use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

mod common;
use common::wait_until_ready;

fn spawn_node(datadir: &str, port: u16, extra: &[&str], envs: &[(&str, &str)]) -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_eezo-node");
    let mut cmd = Command::new(bin);
    cmd.arg("--datadir").arg(datadir)
        .arg("--listen").arg(format!("127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for a in extra { cmd.arg(a); }
    for (k,v) in envs { cmd.env(k, v); }
    cmd.spawn().expect("spawn node")
}

#[test]
fn t29_9_bad_signature_rejected_and_client_exits() {
    // Server (unsigned anchor), but inject BAD signature via test hook:
    let server_port = 19251;
    let mut server = spawn_node("t29_9-srv-badsig", server_port, &[], &[
        ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
        ("EEZO_SYNC_TEST_BAD_SIG", "1"),
    ]);
    assert!(wait_until_ready(server_port, 5_000), "server should be up");

    // Client: require signature (default policy)
    let client_port = 19252;
    let mut client = spawn_node("t29_9-cli-badsig", client_port, &[], &[
        ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
    ]);

    // Give bootstrap a moment to fail on signature verification
    sleep(Duration::from_millis(1500));

    // Client should exit non-success
    match client.try_wait().expect("client status") {
        Some(status) => assert!(!status.success(), "client must exit on bad signature"),
        None => panic!("client still running; expected exit on bad signature"),
    }

    let _ = server.kill();
}
