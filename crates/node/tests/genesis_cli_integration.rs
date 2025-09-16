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
        "--listen", "127.0.0.1:18081",
        "--datadir", datadir,
        "--genesis", genesis_str,
    ]);

    let ok = common::wait_until_ready(port, 15_000);
    assert!(ok, "node did not become ready with valid --genesis");
    let _ = child.kill();
}

#[test]
fn node_fails_fast_with_invalid_genesis_path() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    use std::thread::sleep;

    // unique dir to avoid RocksDB lock from other tests
    let datadir = "target/testdata/genesis_bad_0";

    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["run", "-p", "eezo-node", "--features", "pq44-runtime", "--"]);
    cmd.args(&["--datadir", datadir, "--genesis", "crates/NOPE_DOES_NOT_EXIST.json"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn node");

    // wait for cargo+binary to start and exit (give it up to ~10s)
    let start = Instant::now();
    let status_nonzero = loop {
        if start.elapsed() > Duration::from_secs(10) { break None; }
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break Some(!status.success());
        }
        sleep(Duration::from_millis(100));
    };

    assert!(status_nonzero.is_some(), "process did not exit quickly on bad --genesis");
    assert_eq!(status_nonzero, Some(true), "expected non-zero exit on bad --genesis");
}
