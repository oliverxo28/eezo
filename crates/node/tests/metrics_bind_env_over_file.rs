mod common;

use std::path::PathBuf;

#[test]
fn metrics_env_over_file_reflected_in_config() {
    let listen_port: u16 = 18099;
    let metrics_port: u16 = 18101;

    // Datadir named to match the metrics_port (just like your prior layout)
    let datadir = format!(
        "crates/node/target/testdata/metrics_env_over_file_{}",
        metrics_port
    );
    std::fs::create_dir_all(&datadir).ok();

    // Create a TOML config file that sets unrelated fields (listen/log_level/datadir).
    // Note: NodeCfg ignores unknown fields; we keep it simple.
    let toml = format!(
        r#"
listen = "127.0.0.1:19999"
datadir = "{}"
log_level = "warn"
"#,
        datadir
    );
    let toml_path = "crates/node/target/testdata/metrics_file.toml";
    std::fs::write(toml_path, toml).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            // Use the file for base fields…
            "--config-file",
            toml_path,
            "--genesis",
            genesis,
            // …but override listen via CLI to ensure precedence is still correct.
            "--listen",
            &format!("127.0.0.1:{}", listen_port),
        ],
        &[
            // Metrics are *always* driven by ENV in your main.rs
            ("EEZO_METRICS", "true"),
            ("EEZO_METRICS_PORT", &metrics_port.to_string()),
        ],
    );

    // quick early-exit check (handy for diagnosing file path issues)
    std::thread::sleep(std::time::Duration::from_secs(2));
    if let Some(status) = child.try_wait().unwrap() {
        let stderr = child.read_stderr();
        panic!("node exited early: {:?}\nstderr:\n{}", status, stderr);
    }

    assert!(common::wait_until_ready(listen_port, 15_000));

    // Validate effective config
    let v: serde_json::Value =
        reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", listen_port))
            .unwrap()
            .json()
            .unwrap();

    // CLI listen wins over file
    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{}", listen_port));
    // File datadir is reflected (we didn't override it here)
    assert_eq!(v["node"]["datadir"].as_str().unwrap(), datadir);

    // ENV metrics reflected
    assert_eq!(v["metrics_on"].as_bool().unwrap(), true);
    assert_eq!(v["metrics_port"].as_u64().unwrap() as u16, metrics_port);

    child.kill();
    let stdout = child.read_stdout();
    if !stdout.is_empty() {
        println!("Node stdout:\n{}", stdout);
    }
}
