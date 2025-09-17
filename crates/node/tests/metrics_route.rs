#![cfg(feature = "metrics")]

mod common;

use std::path::PathBuf;

#[test]
fn metrics_endpoint_serves_when_feature_enabled() {
    let listen_port: u16 = 18102;
    let metrics_port: u16 = 18103;
    let datadir = format!("crates/node/target/testdata/metrics_cli_disable_{}", metrics_port);
    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &format!("127.0.0.1:{}", listen_port),
            "--datadir", &datadir,
            "--genesis", genesis,
        ],
        &[
            ("EEZO_METRICS", "on"),
            ("EEZO_METRICS_PORT", &metrics_port.to_string()),
        ],
    );

    assert!(common::wait_until_ready(listen_port, 15_000));

    // /config reflects metrics
    let cfg: serde_json::Value = reqwest::blocking::get(
        &format!("http://127.0.0.1:{}/config", listen_port)
    ).unwrap().json().unwrap();
    assert_eq!(cfg["metrics_on"], true);
    assert_eq!(cfg["metrics_port"].as_u64().unwrap() as u16, metrics_port);

    // /metrics is actually served (feature = "metrics")
    let resp = reqwest::blocking::get(&format!("http://127.0.0.1:{}/metrics", listen_port)).unwrap();
    assert!(resp.status().is_success());

    common::kill_child(&mut child);
}
