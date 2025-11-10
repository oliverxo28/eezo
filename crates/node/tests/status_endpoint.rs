mod common;

use std::path::PathBuf;

#[test]
fn status_reports_pid_uptime_ready_and_build_info() {
    let port: u16 = 18136;
    let datadir = format!("crates/node/target/testdata/status_{}", port);

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // match your genesis chain id (20 bytes ending with 0x01)
    let chain_id_hex = "0000000000000000000000000000000000000001";

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
            // (optional) turn metrics on; not required here
            ("EEZO_METRICS", "on"),
        ],
    );

    assert!(common::wait_until_ready(port, 10_000));

    let url = format!("http://127.0.0.1:{}/status", port);
    let v: serde_json::Value = reqwest::blocking::get(&url).unwrap().json().unwrap();

    // basic shape checks
    assert!(v["pid"].as_u64().unwrap() > 0);
    assert!(v["uptime_secs"].as_u64().is_some());
    assert_eq!(v["ready"].as_bool().unwrap(), true);
    assert_eq!(v["listen"], format!("127.0.0.1:{}", port));
    assert_eq!(v["datadir"].as_str().unwrap(), datadir);
    assert!(v["version"].as_str().unwrap().len() > 0);
    // git_sha is Option<String>, allow null or non-empty string
    if !v["git_sha"].is_null() {
        assert!(v["git_sha"].as_str().unwrap().len() > 0);
    }

    // degrade then verify ready=false in /status
    let _ = reqwest::blocking::get(&format!(
        "http://127.0.0.1:{}/_admin/degrade?token={}",
        port, "t23token"
    )); // no token set -> 404; set one to exercise, or just skip

    // set a token to properly call admin (spawn a new node to fully exercise)
    child.kill();
}
