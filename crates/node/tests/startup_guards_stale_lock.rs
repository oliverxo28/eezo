mod common;

use std::fs;
use std::path::PathBuf;

#[test]
fn stale_lock_is_recovered() {
    let port: u16 = 18125;
    let datadir = format!("crates/node/target/testdata/datadir_lock_stale_{}", port);
    let lockpath = PathBuf::from(&datadir).join(".lock");

    fs::create_dir_all(&datadir).ok();
    // Simulate stale lock (PID that’s definitely not running)
    fs::write(&lockpath, "999999").unwrap();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // Match your genesis.chain_id (20 bytes ending with 0x01)
    let chain_id_hex = "0000000000000000000000000000000000000001";

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            &datadir,
            "--genesis",
            genesis,
        ],
        &[("EEZO_CHAIN_ID", chain_id_hex)],
    );

    // If process died immediately, print stderr
    std::thread::sleep(std::time::Duration::from_millis(400));
    if let Some(status) = child.try_wait().unwrap() {
        let stderr = child.read_stderr();
        panic!("node exited early: {:?}\nstderr:\n{}", status, stderr);
    }

    assert!(common::wait_until_ready(port, 10_000));

    child.kill();
}
