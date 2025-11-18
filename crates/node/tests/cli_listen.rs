// crates/node/tests/cli_listen.rs
mod common;

use std::fs;
use std::path::PathBuf;

#[test]
fn cli_listen_binds_custom_port() {
    // grab an unused port from the helper
    let port: u16 = common::free_port();
    let datadir = format!("crates/node/target/testdata/cli_listen_{}", port);
    let _ = fs::remove_dir_all(&datadir);
    fs::create_dir_all(&datadir).ok();

    // keep genesis to match other tests; remove if not needed in your setup
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--datadir",
            &datadir,
            "--log-level",
            "warn",
            "--genesis",
            genesis,
        ],
        &[],
    );

    let ok = common::wait_until_ready(port, 15_000);
    if !ok {
        eprintln!("stdout:\n{}", child.read_stdout());
        eprintln!("stderr:\n{}", child.read_stderr());
        child.kill();
        panic!("node did not become ready on 127.0.0.1:{port}");
    }

    // sanity check: /config should report the chosen listen address
    let v: serde_json::Value = reqwest::blocking::get(format!("http://127.0.0.1:{}/config", port))
        .expect("fetch /config")
        .json()
        .expect("parse json");
    assert_eq!(v["node"]["listen"], format!("127.0.0.1:{port}"));

    child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&datadir);
}
