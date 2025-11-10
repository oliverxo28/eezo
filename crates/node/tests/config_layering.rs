mod common;

#[test]
fn config_exposes_effective_cli() {
    let port: u16 = 18082;
    let datadir = "target/testdata/config_layering";
    let mut child = common::spawn_node_with(&[
        "--listen",
        "127.0.0.1:18082",
        "--datadir",
        datadir,
        "--genesis",
        &format!("{}/../genesis.min.json", env!("CARGO_MANIFEST_DIR")),
    ]);
    assert!(common::wait_until_ready(port, 10_000));

    let v: serde_json::Value = reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", port))
        .unwrap()
        .json()
        .unwrap();

    // Presence checks (additive, won't break old test):
    let node = v.get("node").expect("node section missing");
    assert_eq!(
        node.get("listen").and_then(|s| s.as_str()),
        Some("127.0.0.1:18082")
    );
    assert_eq!(node.get("datadir").and_then(|s| s.as_str()), Some(datadir));
    assert!(node.get("genesis").is_some());
    assert!(node.get("log_level").is_some()); // Should be present now

    let _ = child.kill();
}

#[test]
fn config_reflects_log_level_cli() {
    let port: u16 = 18083;
    let datadir = "target/testdata/config_log_level";

    let genesis_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with(&[
        "--listen",
        "127.0.0.1:18083",
        "--datadir",
        datadir,
        "--genesis",
        genesis,
        "--log-level",
        "debug",
    ]);
    assert!(common::wait_until_ready(port, 10_000));

    let v: serde_json::Value = reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", port))
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(v["node"]["log_level"], "debug");
    let _ = child.kill();
}

#[test]
fn cli_log_level_precedence_over_env() {
    let port: u16 = 18084;
    let datadir = "target/testdata/config_log_precedence";

    let genesis_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // Set RUST_LOG to warn but CLI should override to debug
    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            "127.0.0.1:18084",
            "--datadir",
            datadir,
            "--genesis",
            genesis,
            "--log-level",
            "debug",
        ],
        &[("RUST_LOG", "warn")],
    );

    assert!(common::wait_until_ready(port, 10_000));

    let v: serde_json::Value = reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", port))
        .unwrap()
        .json()
        .unwrap();

    // CLI should take precedence over ENV
    assert_eq!(v["node"]["log_level"], "debug");
    let _ = child.kill();
}
