mod common;

use std::path::PathBuf;

#[test]
fn config_endpoint_returns_runtime_config() {
    // pick a dedicated port + datadir
    let port: u16 = 18111;
    let datadir = "crates/node/target/testdata/config_ep_runtime";

    // clean & prep datadir
    let _ = std::fs::remove_dir_all(datadir);
    std::fs::create_dir_all(datadir).ok();

    // we’ll point to the provided minimal genesis in the repo
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // start node
    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--datadir",
            datadir,
            "--log-level",
            "debug",
            "--genesis",
            genesis,
        ],
        &[], // no special env overrides needed
    );

    // wait until it’s ready
    let ok = common::wait_until_ready(port, 15_000);
    if !ok {
        // use ChildGuard’s own readers
        let stdout = child.read_stdout();
        let stderr = child.read_stderr();
        eprintln!("Node stdout:\n{stdout}");
        eprintln!("Node stderr:\n{stderr}");
        child.kill();
        let _ = child.try_wait();
        panic!("Node did not become ready within timeout");
    }

    // fetch /config
    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{port}/config"))
        .expect("GET /config failed")
        .json()
        .expect("parse /config JSON failed");

    // basic shape assertions
    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{port}"));
    assert_eq!(v["node"]["log_level"], "debug");
    assert!(v["node"]["datadir"]
        .as_str()
        .unwrap()
        .contains("config_ep_runtime"));

    // chain id should be a 40-hex string
    let chain_id_hex = v["chain_id_hex"].as_str().unwrap();
    assert_eq!(chain_id_hex.len(), 40);

    // peers should be an array (may be empty)
    assert!(v["peers"].is_array());

    // node identity should be present
    assert!(v["node_id"].is_string());
    assert!(v["first_seen"].as_u64().unwrap() > 0);

    // clean shutdown
    child.kill();
    let _ = child.try_wait();
}
