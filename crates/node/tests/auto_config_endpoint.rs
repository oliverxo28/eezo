use reqwest::blocking::Client;
use serde_json::Value as J;
use std::time::Duration;
mod common;

#[test]
fn config_endpoint_exposes_runtime_peers_and_fields() {
    let client = Client::builder()
        .timeout(Duration::from_millis(1000))
        .build()
        .unwrap();

    // three ports
    let p1 = common::free_port();
    let p2 = common::free_port();
    let p3 = common::free_port();

    // datadirs + CLI
    let d1 = common::unique_test_datadir("config_ep", p1);
    let d2 = common::unique_test_datadir("config_ep", p2);
    let d3 = common::unique_test_datadir("config_ep", p3);

    let a1 = ["--listen", &format!("127.0.0.1:{p1}"), "--datadir", &d1];
    let a2 = ["--listen", &format!("127.0.0.1:{p2}"), "--datadir", &d2];
    let a3 = ["--listen", &format!("127.0.0.1:{p3}"), "--datadir", &d3];

    // Start node1 with peers=[p2]; node2 peers=[p1]; node3 not started yet.
    let peers1 = common::peers_env_from_ports(&[p2]);
    let peers2 = common::peers_env_from_ports(&[p1]);

    let _g1 = common::spawn_node_with_env(&a1, &[(&peers1.0, &peers1.1)]);
    let _g2 = common::spawn_node_with_env(&a2, &[(&peers2.0, &peers2.1)]);

    // Allow startup + first peer sweep
    std::thread::sleep(Duration::from_millis(1200));

    // Fetch /config from node1 and assert fields + peers list
    let cfg1: J = client
        .get(format!("http://127.0.0.1:{p1}/config"))
        .send()
        .unwrap()
        .json()
        .unwrap();

    // Basic shape checks
    assert_eq!(cfg1["node"]["listen"], format!("127.0.0.1:{p1}"));
    assert_eq!(cfg1["node"]["datadir"], d1);
    assert!(cfg1["node_id"]
        .as_str()
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    assert!(cfg1["chain_id_hex"].as_str().is_some());
    assert!(cfg1["peers"].is_array());

    // peers must contain p2
    let peers_vec = cfg1["peers"].as_array().unwrap();
    let want_p2 = format!("http://127.0.0.1:{p2}");
    assert!(
        peers_vec.iter().any(|v| v == &J::String(want_p2.clone())),
        "expected peers to contain {want_p2}, got {peers_vec:?}"
    );

    // Now hot-reload peers to include p3 via POST body, start node3, and confirm /config peers reflect it
    let _ = client
        .post(format!("http://127.0.0.1:{p1}/reload"))
        .json(&vec![
            format!("http://127.0.0.1:{p2}"),
            format!("http://127.0.0.1:{p3}"),
        ])
        .send()
        .unwrap();

    // bring node3 up (it will point back to node1 so it's /ready=200)
    let peers3 = common::peers_env_from_ports(&[p1]);
    let _g3 = common::spawn_node_with_env(&a3, &[(&peers3.0, &peers3.1)]);

    // give the peer loop a moment to sweep and /config to reflect runtime peers
    std::thread::sleep(Duration::from_millis(1500));

    let cfg1b: J = client
        .get(format!("http://127.0.0.1:{p1}/config"))
        .send()
        .unwrap()
        .json()
        .unwrap();

    let peers_vec_b = cfg1b["peers"].as_array().unwrap();
    let want_p3 = format!("http://127.0.0.1:{p3}");
    assert!(
        peers_vec_b.iter().any(|v| v == &J::String(want_p3.clone())),
        "expected peers after reload to contain {want_p3}, got {peers_vec_b:?}"
    );

    // Optional: peers should be deduped and sorted (best-effort check: no duplicates)
    let unique_count = peers_vec_b
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(
        unique_count,
        peers_vec_b.len(),
        "peers list contains duplicates"
    );
}
