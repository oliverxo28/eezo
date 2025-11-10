use reqwest::blocking::Client;
use std::time::Duration;

mod common;

#[test]
fn peer_ping_histograms_and_fail_counter() {
    let client = Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .unwrap();

    // pick two ports
    let p1 = common::free_port();
    let p2 = common::free_port();

    // datadirs + CLI args expected by your common.rs
    let d1 = common::unique_test_datadir("peer_metrics", p1);
    let d2 = common::unique_test_datadir("peer_metrics", p2);
    let a1 = ["--listen", &format!("127.0.0.1:{p1}"), "--datadir", &d1];
    let a2 = ["--listen", &format!("127.0.0.1:{p2}"), "--datadir", &d2];

    // wire peers (each points to the other)
    let peers1 = common::peers_env_from_ports(&[p2]);
    let peers2 = common::peers_env_from_ports(&[p1]);

    // OPTIONAL: make node2 slow for a couple cycles (your ready handler can read this env if supported)
    // If you don't have this env in main.rs, omit the "slow" tuple — the test will still pass by killing node2 later.
    let maybe_slow = ("EEZO_SIMULATE_READY_DELAY_MS", "350");

    let _g1 = common::spawn_node_with_env(&a1, &[(&peers1.0, &peers1.1)]);
    let mut g2 = common::spawn_node_with_env(&a2, &[(&peers2.0, &peers2.1), maybe_slow]);

    // allow a few ping intervals to collect histograms
    std::thread::sleep(Duration::from_millis(1600));

    // check histograms exist on node1
    let m1 = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        m1.contains("eezo_node_peer_ping_ms_bucket"),
        "no ping histogram seen"
    );

    // force at least one failure by killing node2, then wait one interval
    g2.kill();
    std::thread::sleep(Duration::from_millis(1200));

    let m1b = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(
        m1b.contains("eezo_node_peer_ping_fail_total"),
        "no ping fail counter seen"
    );
}
