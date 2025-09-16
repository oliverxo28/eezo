// crates/node/tests/debug_test.rs
mod common;

#[test]
fn debug_env_vars() {
    let port: u16 = 18088;
    let envs = [
        ("EEZO_CHAIN_ID", "000102030405060708090a0b0c0d0e0f10111213"),
        ("TEST_VAR", "test_value"),
    ];

    let mut child = common::spawn_node_with_env(&[
        "--listen", &format!("127.0.0.1:{}", port),
    ], &envs);

    // Give it a moment to start
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Check if the process is still running
    if let Ok(Some(status)) = child.try_wait() {
        println!("Process exited with status: {:?}", status);
    } else {
        println!("Process is still running");
    }
    
    let _ = child.kill();
}

