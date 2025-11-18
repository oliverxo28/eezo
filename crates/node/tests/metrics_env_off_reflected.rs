mod common;

use std::path::PathBuf;

#[test]
fn metrics_env_off_reflected_in_config() {
    // Build with `features="pq44-runtime,metrics"`.
    let listen_port: u16 = 18104;
    let datadir = "crates/node/target/testdata/metrics_env_off_reflected";
    std::fs::create_dir_all(datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // EEZO_METRICS=off (or 0/false) should set metrics_on=false in /config
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
            ("EEZO_METRICS", "off"),
            ("EEZO_METRICS_PORT", "9999"), // arbitrary; shouldn't matter when off
        ],
    );

    assert!(common::wait_until_ready(listen_port, 15_000));

    // Verify /config reflects metrics_off
    let cfg: serde_json::Value =
        reqwest::blocking::get(format!("http://127.0.0.1:{}/config", listen_port))
            .unwrap()
            .json()
            .unwrap();

    assert!(!cfg["metrics_on"].as_bool().unwrap());
    // Port still present as an integer; we don't depend on it when off
    assert!(cfg["metrics_port"].is_u64());

    child.kill();
}
