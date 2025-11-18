mod common;

use std::path::PathBuf;

/// Lower clamp: EEZO_MAX_BLOCK_BYTES=512 → should fail fast
#[test]
fn clamp_max_block_bytes_lower() {
    let datadir = "crates/node/target/testdata/inv_clamp_lower";
    let _ = std::fs::remove_dir_all(datadir);

    // Below lower bound (1 KiB) => should fail fast
    let mut child = common::spawn_node_for_failfast(
        &[
            "--listen",
            "127.0.0.1:18110",
            "--genesis",
            common::GENESIS_PATH,
            "--datadir",
            datadir,
        ],
        &[("EEZO_MAX_BLOCK_BYTES", "512")],
    );

    let status = child.wait().expect("wait failed");
    assert!(
        !status.success(),
        "node should fail fast when EEZO_MAX_BLOCK_BYTES < 1 KiB"
    );

    // Optional visibility
    eprintln!("{}", child.read_stdout());
    eprintln!("{}", child.read_stderr());
}

/// Upper clamp: EEZO_MAX_BLOCK_BYTES=100000000 → should fail fast
#[test]
fn clamp_max_block_bytes_upper() {
    let datadir = "crates/node/target/testdata/inv_clamp_upper";
    let _ = std::fs::remove_dir_all(datadir);

    // Above upper bound (64 MiB) => should fail fast
    let mut child = common::spawn_node_for_failfast(
        &[
            "--listen",
            "127.0.0.1:18111",
            "--genesis",
            common::GENESIS_PATH,
            "--datadir",
            datadir,
        ],
        &[("EEZO_MAX_BLOCK_BYTES", "100000000")], // > 64 MiB
    );

    let status = child.wait().expect("wait failed");
    assert!(
        !status.success(),
        "node should fail fast when EEZO_MAX_BLOCK_BYTES > 64 MiB"
    );

    // Optional visibility
    eprintln!("{}", child.read_stdout());
    eprintln!("{}", child.read_stderr());
}

/// Boolean parsing: OFF/false/No → false (case-insensitive)
#[test]
fn boolean_parsing_is_case_insensitive() {
    let port: u16 = 18112;
    let datadir = "crates/node/target/testdata/inv_bool_parse";
    std::fs::create_dir_all(datadir).ok();

    let genesis = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            datadir,
            "--genesis",
            genesis,
        ],
        &[("EEZO_PARALLEL_VERIFY", "OFF"), ("EEZO_METRICS", "false")],
    );

    assert!(common::wait_until_ready(port, 15_000));

    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{}/config", port))
        .unwrap()
        .json()
        .unwrap();

    assert!(!v["parallel_verify"].as_bool().unwrap());
    assert!(!v["metrics_on"].as_bool().unwrap());

    child.kill();
}

/// Numeric parsing fallbacks: invalid → defaults
#[test]
fn numeric_parsing_fallbacks() {
    let port: u16 = 18113;
    let datadir = "crates/node/target/testdata/inv_num_fallbacks";
    std::fs::create_dir_all(datadir).ok();

    let genesis = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            datadir,
            "--genesis",
            genesis,
        ],
        &[
            ("EEZO_VERIFY_CACHE_CAP", "notanumber"),
            ("EEZO_METRICS_PORT", "also_not_a_number"),
        ],
    );

    assert!(common::wait_until_ready(port, 15_000));

    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{}/config", port))
        .unwrap()
        .json()
        .unwrap();

    // defaults from main.rs: verify_cache_cap=10_000, metrics_port=9090
    assert_eq!(v["verify_cache_cap"].as_u64().unwrap(), 10_000);
    assert_eq!(v["metrics_port"].as_u64().unwrap(), 9090);

    child.kill();
}

/// Precedence spot-check: file<warn> < ENV<info> < CLI<debug> → final "debug"
#[test]
fn precedence_file_env_cli_for_log_level() {
    use std::fs::write;

    let port: u16 = 18114;
    let datadir = "crates/node/target/testdata/inv_prec_loglvl";
    std::fs::create_dir_all(datadir).ok();

    // file: warn
    let toml = format!(
        r#"
listen = "127.0.0.1:{port}"
datadir = "{datadir}"
log_level = "warn"
"#,
        port = 19998,
        datadir = datadir
    );
    let toml_path = "crates/node/target/testdata/inv_prec_loglvl.toml";
    write(toml_path, toml).unwrap();

    let genesis = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--config-file",
            toml_path,
            "--genesis",
            genesis,
            "--listen",
            &format!("127.0.0.1:{}", port), // CLI listen
            "--log-level",
            "debug", // CLI wins
        ],
        &[
            ("EEZO_LOG_LEVEL", "info"), // ENV middle
        ],
    );

    assert!(common::wait_until_ready(port, 15_000));

    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{}/config", port))
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(v["node"]["log_level"], "debug");

    child.kill();
}
