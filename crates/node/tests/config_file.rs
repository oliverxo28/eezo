mod common;

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn config_file_is_loaded_and_overridden_by_cli() {
    let port: u16 = 18085;
    let datadir = "target/testdata/conf_file";

    // Clean up stale data and recreate directory
    let _ = std::fs::remove_dir_all(datadir);
    fs::create_dir_all(datadir).ok();

    // write a small TOML file
    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_file"
log_level = "warn"
"#;

    fs::write("target/testdata/node.toml", toml).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            datadir,
            "--log-level",
            "debug",
            "--config-file",
            "target/testdata/node.toml",
            "--genesis",
            genesis,
        ],
        &[],
    );

    let ok = common::wait_until_ready(port, 15_000);
    if !ok {
        let stdout = child.read_stdout();
        let stderr = child.read_stderr();
        println!("Node stdout:\n{}", stdout);
        println!("Node stderr:\n{}", stderr);
        child.kill();
        panic!("Node did not become ready within timeout");
    }

    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{}/config", port))
        .expect("Failed to fetch /config")
        .json()
        .expect("Failed to parse JSON");

    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{}", port));
    assert_eq!(v["node"]["datadir"], datadir);
    assert_eq!(v["node"]["log_level"], "debug");

    // Clean shutdown
    child.kill();
    let _ = child.wait();
}

#[test]
fn config_file_with_env_override() {
    let port: u16 = 18089;
    let datadir = "crates/node/target/testdata/conf_file_env";

    // Clean up stale data and recreate directory
    let _ = std::fs::remove_dir_all(datadir);
    std::fs::create_dir_all(datadir).ok();

    let toml = r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_file"
log_level = "warn"
"#;

    std::fs::write("crates/node/target/testdata/node_env.toml", toml).unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--config-file",
            "crates/node/target/testdata/node_env.toml",
            "--genesis",
            genesis,
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            datadir,
        ],
        &[("EEZO_LOG_LEVEL", "error")],
    );

    let ok = common::wait_until_ready(port, 15_000);
    if !ok {
        let stdout = child.read_stdout();
        let stderr = child.read_stderr();
        println!("Node stdout:\n{}", stdout);
        println!("Node stderr:\n{}", stderr);
        child.kill();
        panic!("Node did not become ready within timeout");
    }

    // Query and assert (while node is alive)
    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{}/config", port))
        .expect("Failed to fetch /config")
        .json()
        .expect("Failed to parse JSON");

    let expected = std::fs::canonicalize(datadir).unwrap();
    let actual = std::fs::canonicalize(v["node"]["datadir"].as_str().unwrap()).unwrap();

    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{}", port));
    assert_eq!(actual, expected);
    assert_eq!(v["node"]["log_level"], "error");

    // Clean shutdown
    child.kill();
    let _ = child.wait();
}

#[test]
fn config_file_missing_fails_fast() {
    let nonexistent_path = "target/testdata/nonexistent_config.toml";

    // Ensure the file doesn't exist
    if std::fs::metadata(nonexistent_path).is_ok() {
        std::fs::remove_file(nonexistent_path).unwrap();
    }

    // Use the failfast helper with empty env
    let mut child = common::spawn_node_for_failfast(
        &[
            "--config-file",
            nonexistent_path,
            "--listen",
            "127.0.0.1:0", // Use port 0 to avoid conflicts
        ],
        &[],
    );

    // Wait for process to exit (should happen quickly)
    let start = Instant::now();
    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait().unwrap() {
            // Process should exit with non-zero status
            assert!(
                !status.success(),
                "Process should fail with missing config file"
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // If we reach here, process didn't exit - print output for debugging
    let stdout = child.read_stdout();
    let stderr = child.read_stderr();
    println!("Process did not exit, stdout:\n{}", stdout);
    println!("Process did not exit, stderr:\n{}", stderr);

    child.kill();
    let _ = child.wait();
    panic!("Process did not exit within 5 seconds for missing config file");
}

#[test]
fn config_file_malformed_fails_fast() {
    let malformed_path = "target/testdata/malformed_config.toml";

    // Write invalid TOML
    std::fs::write(
        malformed_path,
        r#"
listen = "127.0.0.1:19999"
datadir = "target/testdata/from_file"
log_level = "warn"
[invalid section without closing bracket
"#,
    )
    .unwrap();

    // Use the failfast helper with empty env
    let mut child = common::spawn_node_for_failfast(
        &[
            "--config-file",
            malformed_path,
            "--listen",
            "127.0.0.1:0", // Use port 0 to avoid conflicts
        ],
        &[],
    );

    // Wait for process to exit (should happen quickly)
    let start = Instant::now();
    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait().unwrap() {
            // Process should exit with non-zero status
            assert!(
                !status.success(),
                "Process should fail with malformed config file"
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // If we reach here, process didn't exit - print output for debugging
    let stdout = child.read_stdout();
    let stderr = child.read_stderr();
    println!("Process did not exit, stdout:\n{}", stdout);
    println!("Process did not exit, stderr:\n{}", stderr);

    child.kill();
    let _ = child.wait();
    panic!("Process did not exit within 5 seconds for malformed config file");
}
