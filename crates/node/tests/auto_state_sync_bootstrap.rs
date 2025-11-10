#![cfg(feature = "state-sync")]

use std::{
    path::PathBuf,
    process::{Command, Stdio},
    thread::sleep,
    time::Duration,
};

/// Minimal helper: wait until /ready says ok
fn wait_ready(port: u16, max_tries: u32) -> bool {
    for try_count in 0..max_tries {
        let ok = Command::new("curl")
            .args(["-sf", &format!("http://127.0.0.1:{}/ready", port)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if ok {
            println!("✅ Node is ready on port {}", port);
            return true;
        }
        if try_count % 10 == 0 {
            println!(
                "⏳ Waiting for node to be ready on port {} (try {}/{})",
                port,
                try_count + 1,
                max_tries
            );
        }
        sleep(Duration::from_millis(200));
    }
    false
}

#[test]
fn loopback_bootstrap_runs() {
    // Resolve workspace root from this crate (crates/node) -> up two dirs
    let node_crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = node_crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();

    // Paths
    let node_bin = ws_root.join("target").join("debug").join("eezo-node");
    let genesis_path = ws_root.join("crates").join("genesis.min.json");

    // Test params
    let port: u16 = 18280;
    let datadir = ws_root
        .join("target")
        .join("testdata")
        .join(format!("state_sync_loopback_{}", port));

    // Clean datadir
    let _ = std::fs::remove_dir_all(&datadir);

    println!("🚀 Starting node with state-sync enabled...");
    let node_bin_str = node_bin.display().to_string();
    let datadir_str = datadir.display().to_string();
    let genesis_str = genesis_path.display().to_string();
    println!("   - bin: {}", node_bin_str);
    println!("   - datadir: {}", datadir_str);
    println!("   - port: {}", port);
    println!("   - genesis: {}", genesis_str);

    // Spawn eezo-node directly (binary should exist after cargo builds for tests)
    let mut child = Command::new(&node_bin)
        .args([
            "--datadir",
            &datadir_str,
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--genesis",
            &genesis_str,
            "--enable-state-sync",
        ])
        .env("EEZO_ENABLE_STATE_SYNC", "true")
        .env("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001")
        .env("RUST_LOG", "info")
        .current_dir(&ws_root)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn eezo-node");

    // Give node a moment to boot
    sleep(Duration::from_secs(1));

    // Node should come up and run bootstrap
    assert!(
        wait_ready(port, 60),
        "node never became ready on port {}",
        port
    );

    // Probe anchor endpoint; allow 404 (no anchor yet) or 200
    let output = Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("http://127.0.0.1:{}/state/anchor", port),
        ])
        .output()
        .expect("curl failed");

    let status_code = String::from_utf8_lossy(&output.stdout);
    println!("📊 Anchor endpoint returned HTTP status: {}", status_code);
    assert!(
        status_code == "200" || status_code == "404",
        "server returned unexpected status: {}",
        status_code
    );

    println!("✅ Test passed - node bootstrap completed successfully");

    // Cleanup process
    let _ = child.kill();
    let _ = child.wait();
}
