use reqwest::blocking::Client;
use serde_json::Value;
use std::time::Duration;
mod common;

#[test]
fn admin_can_get_and_set_peers() {
    let client = Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .unwrap();
    let admin_token = "sekret";

    // three ports
    let p1 = common::free_port();
    let p2 = common::free_port();
    let p3 = common::free_port();

    // datadirs + CLI
    let d1 = common::unique_test_datadir("admin_peers", p1);
    let d2 = common::unique_test_datadir("admin_peers", p2);
    let d3 = common::unique_test_datadir("admin_peers", p3);
    let a1 = ["--listen", &format!("127.0.0.1:{p1}"), "--datadir", &d1];
    let a2 = ["--listen", &format!("127.0.0.1:{p2}"), "--datadir", &d2];
    let a3 = ["--listen", &format!("127.0.0.1:{p3}"), "--datadir", &d3];

    // node1 starts with peers=[p2] and admin token
    let peers1 = common::peers_env_from_ports(&[p2]);
    let _g1 = common::spawn_node_with_env(
        &a1,
        &[(&peers1.0, &peers1.1), ("EEZO_ADMIN_TOKEN", admin_token)],
    );

    // node2 talks back to node1
    let peers2 = common::peers_env_from_ports(&[p1]);
    let _g2 = common::spawn_node_with_env(&a2, &[(&peers2.0, &peers2.1)]);

    // let it settle
    std::thread::sleep(Duration::from_millis(1200));

    // GET /_admin/peers should show exactly p2 initially
    let url_peers = format!("http://127.0.0.1:{p1}/_admin/peers?token={}", admin_token);
    let v: Value = client.get(&url_peers).send().unwrap().json().unwrap();
    let peers_arr = v.get("peers").and_then(|x| x.as_array()).unwrap();
    assert!(peers_arr
        .iter()
        .any(|e| e["url"].as_str().unwrap().contains(&format!(":{p2}"))));
    assert_eq!(peers_arr.len(), 1);

    // POST /_admin/peers to add p3
    let new_peers = vec![
        format!("http://127.0.0.1:{p2}"),
        format!("http://127.0.0.1:{p3}"),
    ];
    let url_set = format!("http://127.0.0.1:{p1}/_admin/peers?token={}", admin_token);
    let r = client.post(&url_set).json(&new_peers).send().unwrap();
    assert!(r.status().is_success());

    // bring node3 up now
    let peers3 = common::peers_env_from_ports(&[p1]);
    let _g3 = common::spawn_node_with_env(&a3, &[(&peers3.0, &peers3.1)]);

    // wait for refresh and check peers_total==2
    std::thread::sleep(Duration::from_millis(1500));
    let m1 = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(m1.contains("eezo_node_peers_total 2"), "metrics:\n{}", m1);

    // GET /_admin/peers should now show p2 and p3
    let v2: Value = client.get(&url_peers).send().unwrap().json().unwrap();
    let peers_arr2 = v2.get("peers").and_then(|x| x.as_array()).unwrap();
    let urls: Vec<String> = peers_arr2
        .iter()
        .map(|e| e["url"].as_str().unwrap().to_string())
        .collect();
    assert!(
        urls.iter().any(|u| u.contains(&format!(":{p2}"))),
        "urls={urls:?}"
    );
    assert!(
        urls.iter().any(|u| u.contains(&format!(":{p3}"))),
        "urls={urls:?}"
    );
    assert_eq!(peers_arr2.len(), 2);
}
