#![cfg(not(feature = "metrics"))]

mod common;

use std::path::PathBuf;

#[test]
fn metrics_endpoint_absent_when_feature_disabled() {
    // Build WITHOUT the "metrics" feature.
    let listen_port: u16 = 18105;
    let datadir = "crates/node/target/testdata/metrics_route_disabled";
    std::fs::create_dir_all(datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", listen_port),
            "--datadir",
            datadir,
            "--genesis",
            genesis,
        ],
        &[
            ("EEZO_METRICS", "on"),         // even if requested…
            ("EEZO_METRICS_PORT", "18106"), // …route should not exist when feature is off
        ],
    );

    assert!(common::wait_until_ready(listen_port, 15_000));

    // /config still exists, and should show metrics_on per env flag
    let cfg: serde_json::Value =
        reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", listen_port))
            .unwrap()
            .json()
            .unwrap();
    assert_eq!(cfg["metrics_on"], true);

    // But /metrics route is not compiled → 404
    let resp =
        reqwest::blocking::get(&format!("http://127.0.0.1:{}/metrics", listen_port)).unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    common::kill_child_guard(&mut child);
}
