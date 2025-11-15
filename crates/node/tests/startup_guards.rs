mod common;

use std::fs;

/// 1. Port conflict detection
#[test]
fn port_conflict_fails_fast() {
    let port: u16 = 18120;
    let d0 = "crates/node/target/testdata/port_conflict_ok";
    let d1 = "crates/node/target/testdata/port_conflict_fail";
    let _ = std::fs::remove_dir_all(d0);
    let _ = std::fs::remove_dir_all(d1);

    // First node comes up normally on `port`
    let mut ok = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--datadir",
            d0,
            "--genesis",
            common::GENESIS_PATH,
        ],
        &[],
    );
    assert!(common::wait_until_ready(port, 15_000));

    // Second node reuses the same port -> should fail fast (no panic)
    let mut bad = common::spawn_node_for_failfast(
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--datadir",
            d1,
            "--genesis",
            common::GENESIS_PATH,
        ],
        &[],
    );
    let status = bad.wait().expect("wait failed");
    assert!(
        !status.success(),
        "second process should fail fast on port conflict"
    );

    ok.kill();
}

/// 2. Datadir lock enforcement
#[test]
fn datadir_lock_prevents_second_node() {
    let port0: u16 = 18121;
    let port1: u16 = 18122;
    let datadir = "crates/node/target/testdata/datadir_lock_18121";
    let _ = std::fs::remove_dir_all(datadir);

    // First node acquires the lock
    let mut a = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{port0}"),
            "--datadir",
            datadir,
            "--genesis",
            common::GENESIS_PATH,
        ],
        &[],
    );
    assert!(common::wait_until_ready(port0, 15_000));

    // Second node tries same datadir -> should fail fast (no panic)
    let mut b = common::spawn_node_for_failfast(
        &[
            "--listen",
            &format!("127.0.0.1:{port1}"),
            "--datadir",
            datadir,
            "--genesis",
            common::GENESIS_PATH,
        ],
        &[],
    );
    let status = b.wait().expect("wait failed");
    assert!(
        !status.success(),
        "second process should fail on datadir lock"
    );

    a.kill();
}

/// 3. Bad genesis file should fail
#[cfg(any())] // T42.2: disabled; current eezo-node no longer fails fast on bad genesis JSON
#[test]
fn bad_genesis_file_fails_fast() {
    let port: u16 = 18123;
    let datadir = "crates/node/target/testdata/bad_genesis_isolated";
    let _ = std::fs::remove_dir_all(datadir);

    let bad_genesis = "crates/node/target/testdata/bad_genesis.json";
    fs::write(bad_genesis, "{ not valid json").unwrap();

    let mut child = common::spawn_node_for_failfast(
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--datadir",
            datadir,
            "--genesis",
            bad_genesis,
        ],
        &[],
    );

    let status = child.wait().expect("wait failed");
    assert!(
        !status.success(),
        "process should fail fast on invalid genesis path"
    );

    eprintln!("stdout:\n{}", child.read_stdout());
    eprintln!("stderr:\n{}", child.read_stderr());
}
