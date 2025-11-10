use reqwest::blocking::Client;
use std::time::Duration;

mod common;

#[test]
fn cluster_quorum_loss_flips_readiness() {
    let client = Client::builder()
        .timeout(Duration::from_millis(600))
        .build()
        .unwrap();

    // Three nodes
    let p1 = common::free_port();
    let p2 = common::free_port();
    let p3 = common::free_port();

    // Each node peers with the other two; also set low quorum window for fast tests
    let peers1 = common::peers_env_from_ports(&[p2, p3]);
    let peers2 = common::peers_env_from_ports(&[p1, p3]);
    let peers3 = common::peers_env_from_ports(&[p1, p2]);

    let loss = ("EEZO_QUORUM_LOSS_MS", "1200"); // ~1.2s

    // Unique datadirs per node
    let d1 = common::unique_test_datadir("cluster_quorum", p1);
    let d2 = common::unique_test_datadir("cluster_quorum", p2);
    let d3 = common::unique_test_datadir("cluster_quorum", p3);

    // Pass CLI args expected by common.rs: --listen and --datadir
    let a1 = ["--listen", &format!("127.0.0.1:{p1}"), "--datadir", &d1];
    let a2 = ["--listen", &format!("127.0.0.1:{p2}"), "--datadir", &d2];
    let a3 = ["--listen", &format!("127.0.0.1:{p3}"), "--datadir", &d3];

    // Spawn all three nodes
    let _g1 = common::spawn_node_with_env(&a1, &[(&peers1.0, &peers1.1), loss]);
    let mut g2 = common::spawn_node_with_env(&a2, &[(&peers2.0, &peers2.1), loss]);
    let mut g3 = common::spawn_node_with_env(&a3, &[(&peers3.0, &peers3.1), loss]);

    // Wait until node1 is ready 200
    common::wait_for_status_blocking(
        &client,
        &format!("http://127.0.0.1:{p1}/ready"),
        200,
        40,
        100,
    );

    // Kill two peers to drop below quorum (explicitly kill both)
    g2.kill();
    g3.kill();

    // Debug loop: Print /ready and /metrics for several seconds after peers die
    for i in 0..15 {
        let status = client
            .get(format!("http://127.0.0.1:{p1}/ready"))
            .send()
            .map(|r| r.status().as_u16());
        let metrics = client
            .get(format!("http://127.0.0.1:{p1}/metrics"))
            .send()
            .ok()
            .and_then(|r| r.text().ok());
        println!(
            "Check {i}: /ready = {:?}, metrics = {:?}",
            status,
            metrics.as_deref().map(|s| &s[0..s.len().min(300)])
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // expect node1 to flip to 503 after ~1.2s (+poll)
    let flipped = common::wait_until_blocking(
        || {
            client
                .get(format!("http://127.0.0.1:{p1}/ready"))
                .send()
                .map(|r| r.status().as_u16())
                .ok()
                == Some(503)
        },
        40,
        Duration::from_millis(100),
    );
    assert!(
        flipped,
        "node1 did not flip to 503 after quorum loss window"
    );

    // metrics should reflect quorum loss
    let m1 = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(m1.contains("eezo_node_cluster_quorum_ok 0"));
    assert!(m1.contains("eezo_node_quorum_degrade_total "));
}
