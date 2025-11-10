mod common;

use reqwest::blocking::Client;
use std::time::Duration;

/// Simple ping to ensure a node is alive (metrics route)
fn wait_ready(port: u16, timeout_ms: u64) -> bool {
    let client = Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/metrics", port);
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_millis() as u64 > timeout_ms {
            return false;
        }
        if let Ok(resp) = client.get(&url).send() {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(80));
    }
}

#[test]
fn client_bootstraps_from_server_url() {
    // 1) start server node
    let srv_port = 39210;
    let _srv = common::spawn_with_opts(
        &[
            "--datadir",
            &format!("test-bootstrap-srv-{srv_port}"),
            "--listen",
            &format!("127.0.0.1:{srv_port}"),
        ],
        &[], /* envs */
        true,
    );
    assert!(wait_ready(srv_port, 6_000), "server not ready on /metrics");

    // 2) start client node with EEZO_BOOTSTRAP_URL=http://127.0.0.1:<srv_port>
    let cli_port = 39211;
    let url = format!("http://127.0.0.1:{srv_port}");
    let _cli = common::spawn_with_opts(
        &[
            "--datadir",
            &format!("test-bootstrap-cli-{cli_port}"),
            "--listen",
            &format!("127.0.0.1:{cli_port}"),
        ],
        &[("EEZO_BOOTSTRAP_URL", &url)],
        true,
    );
    assert!(wait_ready(cli_port, 6_000), "client did not stay up");
}
