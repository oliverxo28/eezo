use reqwest::blocking::Client;
use std::time::Duration;
mod common;

#[test]
fn hot_reload_updates_peers_and_metrics() {
    let client = Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .unwrap();

    // three ports
    let p1 = common::free_port();
    let p2 = common::free_port();
    let p3 = common::free_port();

    // datadirs + CLI
    let d1 = common::unique_test_datadir("peer_reload", p1);
    let d2 = common::unique_test_datadir("peer_reload", p2);
    let d3 = common::unique_test_datadir("peer_reload", p3);
    let a1 = ["--listen", &format!("127.0.0.1:{p1}"), "--datadir", &d1];
    let a2 = ["--listen", &format!("127.0.0.1:{p2}"), "--datadir", &d2];
    let a3 = ["--listen", &format!("127.0.0.1:{p3}"), "--datadir", &d3];

    // start node1 with peers=[p2]
    let peers1 = common::peers_env_from_ports(&[p2]);
    let _g1 = common::spawn_node_with_env(&a1, &[(&peers1.0, &peers1.1)]);
    let _g2 = common::spawn_node_with_env(
        &a2,
        &[(
            &common::peers_env_from_ports(&[p1]).0,
            &common::peers_env_from_ports(&[p1]).1,
        )],
    );
    // node3 stays down for now

    // wait a bit to collect
    std::thread::sleep(Duration::from_millis(1200));
    let m1 = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(m1.contains("eezo_node_peers_total 1"));

    // send peers list in POST body (instead of using env var)
    let new_peers = vec![
        format!("http://127.0.0.1:{p2}"),
        format!("http://127.0.0.1:{p3}"),
    ];
    let r = client
        .post(format!("http://127.0.0.1:{p1}/reload"))
        .json(&new_peers)
        .send()
        .unwrap();
    assert!(r.status().is_success());

    // bring node3 up
    let _g3 = common::spawn_node_with_env(
        &a3,
        &[(
            &common::peers_env_from_ports(&[p1]).0,
            &common::peers_env_from_ports(&[p1]).1,
        )],
    );

    // wait for refresh and check peers_total==2
    std::thread::sleep(Duration::from_millis(1500));
    let m1b = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    println!("Metrics after reload: {}", m1b);
    assert!(m1b.contains("eezo_node_peers_total 2"));
}
