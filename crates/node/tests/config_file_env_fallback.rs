mod common;

use std::fs;
use std::path::PathBuf;

#[test]
fn config_file_env_fallback() {
    // Clean and prepare datadir
    let datadir = "target/testdata/env_fallback";
    let _ = fs::remove_dir_all(datadir);
    fs::create_dir_all(datadir).ok();

    // Write config file
    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_env_file"
log_level = "warn"
"#;
    fs::write("target/testdata/env_fallback.toml", toml).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // Spawn node with EEZO_CONFIG_FILE env var
    let mut child = common::spawn_node_with_env(
        &["--datadir", datadir, "--genesis", genesis],
        &[
            ("EEZO_CONFIG_FILE", "target/testdata/env_fallback.toml"),
            ("EEZO_LOG_LEVEL", "info"),
        ],
    );

    // Wait for readiness
    let ok = common::wait_until_ready(19999, 15_000);
    if !ok {
        let stdout = child.read_stdout();
        let stderr = child.read_stderr();
        println!("Node stdout:\n{}", stdout);
        println!("Node stderr:\n{}", stderr);
        child.kill();
        panic!("Node did not become ready");
    }

    // Fetch /config
    let v: serde_json::Value = reqwest::blocking::get("http://127.0.0.1:19999/config")
        .expect("Failed GET /config")
        .json()
        .expect("Invalid JSON");

    // Assertions
    assert_eq!(v["node"]["listen"], "127.0.0.1:19999");
    let expected_datadir = fs::canonicalize(datadir).unwrap();
    let actual_datadir = fs::canonicalize(v["node"]["datadir"].as_str().unwrap()).unwrap();
    assert_eq!(actual_datadir, expected_datadir);
    assert_eq!(v["node"]["log_level"], "info");

    // Clean shutdown
    child.kill();
    let _ = child.wait();
}

#[test]
fn config_file_env_fallback_with_cli_override() {
    // Clean and prepare datadir
    let port: u16 = 18096;
    let datadir = "target/testdata/env_fallback_cli";
    let _ = fs::remove_dir_all(datadir);
    fs::create_dir_all(datadir).ok();

    // Write config file
    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_env_file_cli"
log_level = "warn"
"#;
    fs::write("target/testdata/env_fallback_cli.toml", toml).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let cli_listen = format!("127.0.0.1:{}", port);

    // Spawn node with CLI override
    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &cli_listen,
            "--datadir",
            datadir,
            "--genesis",
            genesis,
            "--config-file",
            "target/testdata/env_fallback_cli.toml",
        ],
        &[
            ("EEZO_CONFIG_FILE", "target/testdata/nonexistent.toml"),
            ("EEZO_LOG_LEVEL", "debug"),
        ],
    );

    // Wait for readiness
    let ok = common::wait_until_ready(port, 15_000);
    if !ok {
        let stdout = child.read_stdout();
        let stderr = child.read_stderr();
        println!("Node stdout:\n{}", stdout);
        println!("Node stderr:\n{}", stderr);
        child.kill();
        panic!("Node did not become ready");
    }

    // Fetch /config
    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{}/config", port))
        .expect("Failed GET /config")
        .json()
        .expect("Invalid JSON");

    // Assertions
    assert_eq!(v["node"]["listen"], cli_listen);
    let expected_datadir = fs::canonicalize(datadir).unwrap();
    let actual_datadir = fs::canonicalize(v["node"]["datadir"].as_str().unwrap()).unwrap();
    assert_eq!(actual_datadir, expected_datadir);
    assert_eq!(v["node"]["log_level"], "debug");

    // Clean shutdown
    child.kill();
    let _ = child.wait();
}

#[test]
fn config_file_env_fallback_no_file() {
    // EEZO_CONFIG_FILE points to a non-existent file and we also pass it on CLI
    let port: u16 = 18097;
    let datadir = "target/testdata/env_fallback_no_file";

    // Clean first to avoid stale state
    let _ = std::fs::remove_dir_all(datadir);

    // Use the *fail-fast* spawner so an early non-zero exit is OK
    let mut child = common::spawn_node_for_failfast(
        &[
            "--config-file",
            "target/testdata/nonexistent_config.toml",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--genesis",
            common::GENESIS_PATH,
            "--datadir",
            datadir,
        ],
        &[(
            "EEZO_CONFIG_FILE",
            "target/testdata/nonexistent_config.toml",
        )],
    );

    // The process should exit quickly with non-zero status
    let status = child.wait().expect("failed to wait on child");
    assert!(
        !status.success(),
        "process should fail fast when config file is missing"
    );

    // Optional: dump output to make debugging easier if this ever regresses
    eprintln!("(expected fail-fast) stdout:\n{}", child.read_stdout());
    eprintln!("(expected fail-fast) stderr:\n{}", child.read_stderr());

    // Tidy up
    let _ = std::fs::remove_dir_all(datadir);
}
