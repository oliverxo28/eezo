// crates/node/tests/cli_listen.rs
mod common;

#[test]
fn cli_listen_binds_custom_port() {
    let port: u16 = 9090; // Keep your original port
    let mut child = common::spawn_node_with(&["--listen", &format!("127.0.0.1:{}", port)]);

    let ok = common::wait_until_ready(port, 5000); // 5 second timeout like original
    assert!(ok, "node did not become ready on custom port");

    let _ = child.kill();
}