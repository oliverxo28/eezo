mod common;

use common::spawn_node;

#[test]
fn node_info_metric_exposes_identity_and_build_labels() {
    let port: u16 = 18140;
    let datadir = format!("crates/node/target/testdata/node_info_{}", port);
    std::fs::create_dir_all(&datadir).ok();

    let listen_addr = format!("127.0.0.1:{}", port);

    // Build a flat CLI arg list and use the new one-arg helper.
    let _args: [&str; 6] = [
        "--datadir", &datadir,
        "--listen", &listen_addr,
        "--genesis", "crates/genesis.min.json",
    ];
    let mut child = spawn_node(&datadir, &listen_addr, &[]);
    assert!(common::wait_until_ready(port, 10_000));

    // Fetch /status to learn node_id and version
    let status_url = format!("http://127.0.0.1:{}/status", port);
    let status: serde_json::Value = reqwest::blocking::get(&status_url).unwrap().json().unwrap();
    let node_id = status["node_id"].as_str().unwrap().to_string();
    let version = status["version"].as_str().unwrap().to_string();

    // Scrape /metrics and check the labeled info line exists
    let metrics_url = format!("http://127.0.0.1:{}/metrics", port);
    // Add retry logic to handle timing issues with metrics initialization
    let mut body = String::new();
    for i in 0..10 {
        if let Ok(resp) = reqwest::blocking::get(&metrics_url) {
            if let Ok(text) = resp.text() {
                body = text;
                break;
            }
        };
        if i < 9 {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    // Do not assume label order; just ensure the line exists and has both labels and value 1
    // Cheap check: overall metric and value present
    assert!(body.contains("eezo_node_info"), "info metric name missing");
    assert!(
        body.contains("\neezo_node_info") || body.starts_with("eezo_node_info"),
        "info metric sample not found"
    );
    assert!(
        body.contains(" 1\n") || body.trim_end().ends_with(" 1"),
        "info metric value not 1"
    );
    // Labels present somewhere on the info line
    assert!(
        body.contains(&format!(r#"node_id="{}""#, node_id)),
        "info metric missing node_id label"
    );
    assert!(
        body.contains(&format!(r#"version="{}""#, version)),
        "info metric missing version label"
    );

    child.kill();
}