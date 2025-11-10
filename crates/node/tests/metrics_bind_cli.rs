mod common;

use std::path::PathBuf;

#[test]
fn metrics_bind_cli_reflected_in_config() {
    // We'll drive the node primarily by CLI (listen/datadir/genesis)
    // and set metrics via ENV (since metrics_* are ENV-driven in main.rs).
    let listen_port: u16 = 18098;
    let metrics_port: u16 = 18100;
    let datadir = format!(
        "crates/node/target/testdata/metrics_bind_cli_{}",
        metrics_port
    );

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", listen_port),
            "--datadir",
            &datadir,
            "--genesis",
            genesis,
        ],
        &[
            ("EEZO_METRICS", "on"),
            ("EEZO_METRICS_PORT", &metrics_port.to_string()),
        ],
    );

    // wait until the HTTP server is up
    assert!(common::wait_until_ready(listen_port, 15_000));

    // Read back the effective config from /config
    let v: serde_json::Value =
        reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", listen_port))
            .unwrap()
            .json()
            .unwrap();

    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{}", listen_port));
    assert_eq!(v["node"]["datadir"].as_str().unwrap(), datadir);
    // metrics are carried in the top-level runtime section
    assert_eq!(v["metrics_on"].as_bool().unwrap(), true);
    assert_eq!(v["metrics_port"].as_u64().unwrap() as u16, metrics_port);

    child.kill();
    let stdout = child.read_stdout();
    if !stdout.is_empty() {
        println!("Node stdout:\n{}", stdout);
    }
}
