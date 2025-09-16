mod common;

#[test]
fn config_endpoint_reflects_env() {
    // Pick a random-ish port to avoid clashes in CI
    let listen_port: u16 = 18087;
    let metrics_port = "9199";
    let datadir = "target/testdata/config_endpoint_env";
    let envs = [
        ("EEZO_CHAIN_ID", "000102030405060708090a0b0c0d0e0f10111213"),
        ("EEZO_MAX_BLOCK_BYTES", "65536"),
        ("EEZO_VERIFY_CACHE_CAP", "1234"),
        ("EEZO_PARALLEL_VERIFY", "off"),
        ("EEZO_METRICS", "on"),
        ("EEZO_METRICS_PORT", metrics_port),
    ];

    let genesis_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // Use the common helper with explicit listen port
    let mut child = common::spawn_node_with_env(&[
        "--listen", &format!("127.0.0.1:{}", listen_port),
        "--datadir", datadir,
        "--genesis", genesis,
    ], &envs);

    // Give the server a moment to bind using the common helper
    let ok = common::wait_until_ready(listen_port, 10_000);
    assert!(ok, "node did not become ready");

    // Fetch /config and check the fields (preserving your original assertions)
    let cfg: serde_json::Value =
        reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", listen_port)).unwrap().json().unwrap();

    assert_eq!(cfg["chain_id_hex"], "000102030405060708090a0b0c0d0e0f10111213");
    assert_eq!(cfg["verify_cache_cap"], 1234);
    assert_eq!(cfg["parallel_verify"], false);
    assert_eq!(cfg["max_block_bytes"], 65536);
    assert_eq!(cfg["metrics_on"], true);
    assert_eq!(cfg["metrics_port"], metrics_port.parse::<u64>().unwrap());

    // Kill node
    let _ = child.kill();
}