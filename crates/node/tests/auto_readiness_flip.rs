mod common;

use std::path::PathBuf;

#[test]
fn auto_readiness_flip_to_503_on_bg_error() {
    let port: u16 = 18134;
    // Add process ID and timestamp to make datadir unique
    let datadir = format!(
        "crates/node/target/testdata/auto_flip_{}_{}_{}",
        port,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Clean up any existing directory first
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // matches your genesis chain id (20 bytes ending with 0x01)
    let chain_id_hex = "0000000000000000000000000000000000000001";
    let admin_token = "t22auto";

    let _guard = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            &datadir,
            "--genesis",
            genesis,
        ],
        &[
            ("EEZO_CHAIN_ID", chain_id_hex),
            ("EEZO_ADMIN_TOKEN", admin_token),
            ("EEZO_SIMULATE_BG_IO_ERROR", "on"),
            // metrics optional here; include if you want to assert the counter
            ("EEZO_METRICS", "on"),
        ],
    );

    // Wait for initial readiness with more debugging
    println!("Waiting for initial readiness (200)...");
    assert!(
        common::wait_until_ready(port, 15_000),
        "Node never became initially ready"
    );

    let url_ready = format!("http://127.0.0.1:{}/ready", port);
    let resp = reqwest::blocking::get(&url_ready).unwrap();
    println!("Initial readiness check: {}", resp.status());
    assert!(
        resp.status().is_success(),
        "Initial readiness should be 200"
    );

    // After the background task triggers, /ready should flip to 503 within ~3s
    println!("Waiting for readiness to flip to 503...");
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);
    let mut saw_503 = false;

    loop {
        match reqwest::blocking::get(&url_ready) {
            Ok(resp) => {
                let status = resp.status();
                println!("Readiness check: {}", status);
                if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                    saw_503 = true;
                    break;
                }
            }
            Err(e) => {
                println!("Request to /ready failed: {}", e);
            }
        }

        if start.elapsed() > timeout {
            println!("Timeout reached without seeing 503");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    assert!(saw_503, "Readiness never flipped to 503 within timeout");

    // (Optional) Assert metric was incremented
    let metrics_url = format!("http://127.0.0.1:{}/metrics", port);
    match reqwest::blocking::get(&metrics_url) {
        Ok(resp) => {
            let body = resp.text().unwrap();
            println!("Metrics response: {}", body);
            assert!(
                body.contains("eezo_node_bg_error_total"),
                "Metric not found in metrics output"
            );
        }
        Err(e) => {
            println!("Failed to get metrics: {}", e);
            // Don't fail the test if metrics endpoint is not available
        }
    }

    // ChildGuard will handle cleanup automatically when it goes out of scope
}
