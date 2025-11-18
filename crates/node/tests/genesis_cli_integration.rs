#![cfg(feature = "persistence")]
mod common;

use std::path::PathBuf;

#[test]
fn node_starts_with_valid_genesis() {
    let port: u16 = 18081;
    let datadir = "target/testdata/genesis_ok_18081";

    // Resolve relative to the node crate dir (CARGO_MANIFEST_DIR = crates/node)
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis_str = genesis_path.to_str().expect("utf8 path");

    let mut child = common::spawn_node_with(&[
        "--listen",
        "127.0.0.1:18081",
        "--datadir",
        datadir,
        "--genesis",
        genesis_str,
    ]);

    let ok = common::wait_until_ready(port, 15_000);
    assert!(ok, "node did not become ready with valid --genesis");
    child.kill();
}

#[test]
fn node_fails_fast_with_invalid_genesis_path() {
    let port: u16 = 18081; // any free port; the node won’t reach bind anyway
    let datadir = "target/testdata/genesis_bad_path";

    // clean
    let _ = std::fs::remove_dir_all(datadir);

    let mut child = common::spawn_node_for_failfast(
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--datadir",
            datadir,
            "--genesis",
            "target/testdata/this_file_does_not_exist.json",
        ],
        &[], // no extra env
    );

    // should exit quickly and NON-zero
    let status = child.wait().expect("wait failed");
    assert!(
        !status.success(),
        "process did not exit quickly on bad --genesis"
    );

    // (optional) log for visibility
    eprintln!("stdout:\n{}", child.read_stdout());
    eprintln!("stderr:\n{}", child.read_stderr());
}
