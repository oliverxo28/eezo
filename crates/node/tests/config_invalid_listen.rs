mod common;

#[test]
fn invalid_listen_fails_fast() {
    use std::path::PathBuf;

    let malformed_toml_path = "crates/node/target/testdata/inv_bad_listen.toml";
    std::fs::create_dir_all("crates/node/target/testdata").ok();

    // Bad socket address
    std::fs::write(
        malformed_toml_path,
        r#"
listen = "not_a_socket_addr"
datadir = "crates/node/target/testdata/inv_bad_listen_data"
log_level = "info"
"#,
    )
    .unwrap();

    let genesis = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis.to_str().unwrap();

    // Use the new helper that captures output without panicking on non-zero exit
    let (status, _stdout, stderr) =
        common::run_node_and_capture(&["--config-file", malformed_toml_path, "--genesis", genesis]);

    // Verify the node failed as expected
    assert!(
        !status.success(),
        "expected non-zero exit when listen is invalid"
    );
    assert!(
        stderr.contains("invalid listen address"),
        "stderr did not mention invalid listen address.\nstderr:\n{}",
        stderr
    );
}
