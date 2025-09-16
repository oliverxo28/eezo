mod common;

use std::fs;
use std::path::PathBuf;

#[test]
fn config_file_env_fallback() {
    // The port from config file which should be respected in absence of --listen CLI arg
    let expected_listen = "127.0.0.1:19999";
    let datadir = "target/testdata/env_fallback";

    fs::create_dir_all(datadir).ok();

    // Write a config file with the listen address to be used if no CLI arg overrides
    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_env_file"
log_level = "warn"
"#;
    fs::write("target/testdata/env_fallback.toml", toml).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // Spawn node with EEZO_CONFIG_FILE env var but no --config-file CLI arg or --listen CLI arg
    // So listen should come from config file
    let mut child = common::spawn_node_with_env(
        &[
            "--datadir", datadir,
            "--genesis", genesis,
        ],
        &[
            ("EEZO_CONFIG_FILE", "target/testdata/env_fallback.toml"),
            ("EEZO_LOG_LEVEL", "info"), // overrides the file's log_level
        ],
    );

    assert!(common::wait_until_ready(19999, 15_000));

    let v: serde_json::Value = reqwest::blocking::get("http://127.0.0.1:19999/config").unwrap().json().unwrap();

    // Verify the listen address from the config file is used
    assert_eq!(v["node"]["listen"], expected_listen);

    // Verify datadir overridden by CLI arg
    let expected_datadir = std::fs::canonicalize(datadir).unwrap();
    let actual_datadir = std::fs::canonicalize(v["node"]["datadir"].as_str().unwrap()).unwrap();
    assert_eq!(actual_datadir, expected_datadir);

    // Verify log_level overridden by ENV var
    assert_eq!(v["node"]["log_level"], "info");

    let _ = child.kill();
}

#[test]
fn config_file_env_fallback_with_cli_override() {
    // In this test, CLI --listen overrides the config file listen port
    let port: u16 = 18096;
    let cli_listen = format!("127.0.0.1:{}", port);
    let _toml_listen = "127.0.0.1:19999";
    let datadir = "target/testdata/env_fallback_cli";

    fs::create_dir_all(datadir).ok();

    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_env_file_cli"
log_level = "warn"
"#;
    fs::write("target/testdata/env_fallback_cli.toml", toml).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // Spawn node with both EEZO_CONFIG_FILE env var and --config-file CLI arg
    // CLI --listen arg overrides the listen port in the config file
    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &cli_listen,
            "--datadir", datadir,
            "--genesis", genesis,
            "--config-file", "target/testdata/env_fallback_cli.toml",
        ],
        &[
            ("EEZO_CONFIG_FILE", "target/testdata/nonexistent.toml"), // ignored due to CLI argument presence
            ("EEZO_LOG_LEVEL", "debug"),
        ],
    );

    assert!(common::wait_until_ready(port, 15_000));

    let v: serde_json::Value = reqwest::blocking::get(&format!("http://127.0.0.1:{}/config", port))
        .unwrap().json().unwrap();

    // Assert CLI listen overrides config file listen
    assert_eq!(v["node"]["listen"], cli_listen);

    // Assert CLI datadir overrides config file datadir
    let expected_datadir = std::fs::canonicalize(datadir).unwrap();
    let actual_datadir = std::fs::canonicalize(v["node"]["datadir"].as_str().unwrap()).unwrap();
    assert_eq!(actual_datadir, expected_datadir);

    // ENV log_level overrides config file log_level
    assert_eq!(v["node"]["log_level"], "debug");

    let _ = child.kill();
}

#[test]
fn config_file_env_fallback_no_file() {
    let port: u16 = 18097;
    let datadir = "target/testdata/env_fallback_no_file";

    fs::create_dir_all(datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // Spawn node with EEZO_CONFIG_FILE pointing to a non-existent file should fail fast
    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &format!("127.0.0.1:{}", port),
            "--datadir", datadir,
            "--genesis", genesis,
        ],
        &[
            ("EEZO_CONFIG_FILE", "target/testdata/nonexistent_config.toml"),
        ],
    );

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);

    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "Process should fail with missing config file from ENV");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let _ = child.kill();
    panic!("Process did not exit within 5 seconds for missing config file from ENV");
}
