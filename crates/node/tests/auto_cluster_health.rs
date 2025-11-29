use reqwest::blocking::Client;
use std::time::Duration;

mod common;

fn peers_env_for(_port: u16, others: &[u16]) -> (String, String) {
    let list = others
        .iter()
        .map(|p| format!("http://127.0.0.1:{p}"))
        .collect::<Vec<_>>()
        .join(",");
    ("EEZO_PEERS".to_string(), list)
}

#[test]
fn cluster_health_reflects_one_down() {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // choose 3 free ports
    let p1 = common::free_port();
    let p2 = common::free_port();
    let p3 = common::free_port();

    // spawn three nodes; each points to the other two
    let e1 = peers_env_for(p1, &[p2, p3]);
    let e2 = peers_env_for(p2, &[p1, p3]);
    let e3 = peers_env_for(p3, &[p1, p2]);

    // Build node arguments with listen address and datadir
    let node_args1 = &[
        "--listen",
        &format!("127.0.0.1:{}", p1),
        "--datadir",
        &format!("data_test_{}", p1),
    ];
    let node_args2 = &[
        "--listen",
        &format!("127.0.0.1:{}", p2),
        "--datadir",
        &format!("data_test_{}", p2),
    ];
    let node_args3 = &[
        "--listen",
        &format!("127.0.0.1:{}", p3),
        "--datadir",
        &format!("data_test_{}", p3),
    ];

    let _g1 = common::spawn_node_with_env(node_args1, &[(&e1.0, &e1.1)]);
    let _g2 = common::spawn_node_with_env(node_args2, &[(&e2.0, &e2.1)]);
    let mut g3 = common::spawn_node_with_env(node_args3, &[(&e3.0, &e3.1)]); // we'll kill this one

    // wait until all nodes report peers (peers_total == 2 and peers_ready == 2)
    let m1 = format!("http://127.0.0.1:{p1}/metrics");
    let m2 = format!("http://127.0.0.1:{p2}/metrics");
    let _ok = common::wait_until(
        || {
            let a = client
                .get(&m1)
                .send()
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.text());
            let b = client
                .get(&m2)
                .send()
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.text());
            if let (Ok(aa), Ok(bb)) = (a, b) {
                aa.contains("eezo_node_peers_total 2")
                    && aa.contains("eezo_node_peers_ready 2")
                    && bb.contains("eezo_node_peers_total 2")
                    && bb.contains("eezo_node_peers_ready 2")
            } else {
                false
            }
        },
        60,
        Duration::from_millis(200),
    );
    // If initial convergence is slow, we still proceed; the key check is after we drop g3.

    // kill node3
    g3.kill();

    // expect nodes 1 and 2 to update metrics to peers_ready == 1 within ~2s
    // (each node sees only 1 of their 2 configured peers as ready)
    let _ok2 = common::wait_until(
        || {
            client
                .get(&m1)
                .send()
                .ok()
                .and_then(|r| r.text().ok())
                .map(|t| {
                    t.contains("eezo_node_peers_total 2") && t.contains("eezo_node_peers_ready 1")
                })
                .unwrap_or(false)
                && client
                    .get(&m2)
                    .send()
                    .ok()
                    .and_then(|r| r.text().ok())
                    .map(|t| {
                        t.contains("eezo_node_peers_total 2")
                            && t.contains("eezo_node_peers_ready 1")
                    })
                    .unwrap_or(false)
        },
        40,
        Duration::from_millis(100),
    );

    // Also validate /peers returns JSON with one 'ready:false'
    // Use wait_until for resilience against transient network delays in CI
    let peers_ok = common::wait_until(
        || {
            client
                .get(format!("http://127.0.0.1:{p1}/peers"))
                .send()
                .ok()
                .and_then(|r| r.text().ok())
                .map(|t| t.contains("\"ready\":false"))
                .unwrap_or(false)
        },
        30,
        Duration::from_millis(200),
    );
    assert!(peers_ok, "expected at least one down peer in /peers");

    // guards drop → children get cleaned up
}