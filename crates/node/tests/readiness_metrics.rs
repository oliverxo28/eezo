mod common;

use std::path::PathBuf;

#[test]
fn readiness_metrics_gauge_and_counters() {
    let port: u16 = 18132;
    let datadir = format!("crates/node/target/testdata/metrics_ready_{}", port);

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let chain_id_hex = "0000000000000000000000000000000000000001";
    let admin_token = "t22metrics";

    let mut child = common::spawn_node_with_env(
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
            ("EEZO_METRICS", "on"),
        ],
    );

    assert!(common::wait_until_ready(port, 10_000));

    let metrics_url = format!("http://127.0.0.1:{}/metrics", port);
    let body = reqwest::blocking::get(&metrics_url)
        .unwrap()
        .text()
        .unwrap();
    assert!(body.contains("eezo_node_ready 1"));

    // Degrade
    let _ = reqwest::blocking::get(&format!(
        "http://127.0.0.1:{}/_admin/degrade?token={}",
        port, admin_token
    ))
    .unwrap();

    let body = reqwest::blocking::get(&metrics_url)
        .unwrap()
        .text()
        .unwrap();
    assert!(body.contains("eezo_node_ready 0"));
    assert!(body.contains("eezo_node_ready_degrade_total"));

    // Restore
    let _ = reqwest::blocking::get(&format!(
        "http://127.0.0.1:{}/_admin/restore?token={}",
        port, admin_token
    ))
    .unwrap();

    let body = reqwest::blocking::get(&metrics_url)
        .unwrap()
        .text()
        .unwrap();
    assert!(body.contains("eezo_node_ready 1"));
    assert!(body.contains("eezo_node_ready_restore_total"));

    child.kill();
}
