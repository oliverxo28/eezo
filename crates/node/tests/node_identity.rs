mod common;

use std::path::PathBuf;

#[test]
fn identity_persists_across_restarts() {
    let port: u16 = 18138;
    let datadir = format!("crates/node/target/testdata/identity_{}", port);
    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();
    let chain_id_hex = "0000000000000000000000000000000000000001";

    // First start
    let mut child1 = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            &datadir,
            "--genesis",
            genesis,
        ],
        &[("EEZO_CHAIN_ID", chain_id_hex)],
    );
    assert!(common::wait_until_ready(port, 10_000));
    let status_url = format!("http://127.0.0.1:{}/status", port);
    let first: serde_json::Value = reqwest::blocking::get(&status_url).unwrap().json().unwrap();
    let id1 = first["node_id"].as_str().unwrap().to_string();
    assert!(!id1.is_empty());
    child1.kill();

    // Second start on same datadir -> must reuse same ID
    let _child2 = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            &datadir,
            "--genesis",
            genesis,
        ],
        &[("EEZO_CHAIN_ID", chain_id_hex)],
    );
    assert!(common::wait_until_ready(port, 10_000));
    let second: serde_json::Value = reqwest::blocking::get(&status_url).unwrap().json().unwrap();
    let id2 = second["node_id"].as_str().unwrap().to_string();

    assert_eq!(id1, id2, "node_id must persist across restarts");

    // IDENTITY file should exist and be valid JSON
    let ident_path = format!("{}/IDENTITY", datadir);
    let contents = std::fs::read_to_string(&ident_path).unwrap();
    let _parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();

    let _ = child1.kill();
}
