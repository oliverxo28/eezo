// crates/node/tests/debug_test.rs
mod common;

#[test]
fn debug_env_vars() {
    let port: u16 = 18088;
    let datadir = "crates/node/target/testdata/debug_env_vars";
    let envs = [
        ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
        ("TEST_VAR", "test_value"),
    ];

    // Give this test its own datadir and pass genesis so it doesn't touch the shared default.
    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--datadir",
            datadir,
            "--genesis",
            common::GENESIS_PATH,
        ],
        &envs,
    );

    // Short grace period
    std::thread::sleep(std::time::Duration::from_millis(800));

    // If it died early, surface logs so the failure is informative
    if let Ok(Some(status)) = child.try_wait() {
        let stdout = child.read_stdout();
        let stderr = child.read_stderr();
        panic!("node exited early: {status:?}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    } else {
        println!("Process is running (as expected for this smoke test)");
    }

    let _ = child.kill(); // ChildGuard will also clean up the datadir
}
