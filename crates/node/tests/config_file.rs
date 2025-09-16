mod common;

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn node_crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn testdata_dir() -> PathBuf {
    node_crate_dir().join("target/testdata")
}

#[test]
fn config_file_is_loaded_and_overridden_by_cli() {
    let port: u16 = 18095;
    let td = testdata_dir();
    let datadir = td.join("conf_file_18095");
    fs::create_dir_all(&datadir).ok();

    // Write a small TOML file (file values should be overridden by CLI below)
    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_file"
log_level = "warn"
"#;
    let cfg_path = td.join("node.toml");
    fs::write(&cfg_path, toml).unwrap();

    let genesis_path = node_crate_dir().join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();
    let cfg_str = cfg_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &format!("127.0.0.1:{}", port),
            "--datadir", datadir.to_str().unwrap(),
            "--log-level", "debug",                    // CLI overrides file
            "--config-file", cfg_str,
            "--genesis", genesis,
        ],
        &[],
    );

    let ok = common::wait_until_ready(port, 15_000);
    if !ok {
        let _ = child.kill();
        panic!("node did not become ready for config_file_is_loaded_and_overridden_by_cli");
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build().unwrap();

    let v: serde_json::Value = client
        .get(&format!("http://127.0.0.1:{}/config", port))
        .send().unwrap()
        .json().unwrap();

    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{}", port));
    assert_eq!(v["node"]["datadir"], datadir.to_str().unwrap());
    assert_eq!(v["node"]["log_level"], "debug");

    let _ = child.kill();
}

#[test]
fn config_file_with_env_override() {
    // Unique port + datadir to avoid collisions across tests
    let port: u16 = 18096;
    let td = testdata_dir();
    let datadir = td.join("conf_file_env_18096");
    fs::create_dir_all(&datadir).ok();

    // File provides "warn" but ENV should override to "error"
    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_file"
log_level = "warn"
"#;
    let cfg_path = td.join("node_env.toml");
    fs::write(&cfg_path, toml).unwrap();

    let genesis_path = node_crate_dir().join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();
    let cfg_str = cfg_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &format!("127.0.0.1:{}", port),
            "--datadir", datadir.to_str().unwrap(),
            "--config-file", cfg_str,
            "--genesis", genesis,
        ],
        &[("EEZO_LOG_LEVEL", "error")],   // ENV should override file
    );

    let ok = common::wait_until_ready(port, 15_000);
    if !ok {
        let _ = child.kill();
        panic!("node did not become ready for config_file_with_env_override");
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build().unwrap();

    let v: serde_json::Value = client
        .get(&format!("http://127.0.0.1:{}/config", port))
        .send().unwrap()
        .json().unwrap();

    // Compare datadir canonically to be robust to absolute/relative forms
    let expected = std::fs::canonicalize(&datadir).unwrap();
    let actual = std::fs::canonicalize(v["node"]["datadir"].as_str().unwrap()).unwrap();

    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{}", port));
    assert_eq!(actual, expected);
    assert_eq!(v["node"]["log_level"], "error");

    let _ = child.kill();
}

#[test]
fn config_file_missing_fails_fast() {
    let td = testdata_dir();
    let nonexistent_path = td.join("nonexistent_config.toml");
    if nonexistent_path.exists() {
        fs::remove_file(&nonexistent_path).unwrap();
    }

    let mut child = common::spawn_node_with(&[
        "--config-file", nonexistent_path.to_str().unwrap(),
        "--listen", "127.0.0.1:0", // bind ephemeral port to avoid conflicts
    ]);

    // Wait for process to exit (should happen quickly)
    let start = Instant::now();
    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "Process should fail with missing config file");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    panic!("Process did not exit within 5 seconds for missing config file");
}

#[test]
fn config_file_malformed_fails_fast() {
    let td = testdata_dir();
    let malformed_path = td.join("malformed_config.toml");

    // Write invalid TOML
    fs::write(&malformed_path, r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_file"
log_level = "warn"
[invalid section without closing bracket
"#).unwrap();

    let mut child = common::spawn_node_with(&[
        "--config-file", malformed_path.to_str().unwrap(),
        "--listen", "127.0.0.1:0", // bind ephemeral port
    ]);

    // Wait for process to exit (should happen quickly)
    let start = Instant::now();
    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "Process should fail with malformed config file");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    panic!("Process did not exit within 5 seconds for malformed config file");
}
