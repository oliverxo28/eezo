use reqwest::blocking::Client;
use serde_json::Value;
use std::time::Duration;
mod common;

#[test]
fn admin_runtime_snapshot_and_ready_flip() {
    let client = Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .unwrap();
    let admin_token = "sekret2";

    // single node
    let p1 = common::free_port();
    let d1 = common::unique_test_datadir("admin_runtime", p1);
    let a1 = ["--listen", &format!("127.0.0.1:{p1}"), "--datadir", &d1];

    let _g1 = common::spawn_node_with_env(&a1, &[("EEZO_ADMIN_TOKEN", admin_token)]);

    std::thread::sleep(Duration::from_millis(800));

    // GET /_admin/runtime should succeed with token
    let url_rt = format!("http://127.0.0.1:{p1}/_admin/runtime?token={}", admin_token);
    let v: Value = client.get(&url_rt).send().unwrap().json().unwrap();
    assert!(v.get("pid").and_then(|x| x.as_u64()).unwrap() > 0);
    assert!(v.get("uptime_secs").is_some());
    assert!(v.get("ready").and_then(|x| x.as_bool()).unwrap());
    assert!(v.get("peers_total").is_some());
    assert!(v.get("version").and_then(|x| x.as_str()).is_some());
    assert!(v.get("node_id").and_then(|x| x.as_str()).is_some());

    // Degrade via admin and verify ready flips + /ready=503
    let url_deg = format!("http://127.0.0.1:{p1}/_admin/degrade?token={}", admin_token);
    let r = client.get(&url_deg).send().unwrap();
    assert!(r.status().is_success());

    std::thread::sleep(Duration::from_millis(300));

    // /ready should be 503 now
    let rdy = client
        .get(format!("http://127.0.0.1:{p1}/ready"))
        .send()
        .unwrap();
    assert_eq!(rdy.status().as_u16(), 503);

    // runtime says ready=false
    let v2: Value = client.get(&url_rt).send().unwrap().json().unwrap();
    assert!(!v2.get("ready").and_then(|x| x.as_bool()).unwrap());

    // Restore and verify /ready=200 and runtime ready=true
    let url_res = format!("http://127.0.0.1:{p1}/_admin/restore?token={}", admin_token);
    let r2 = client.get(&url_res).send().unwrap();
    assert!(r2.status().is_success());

    std::thread::sleep(Duration::from_millis(300));

    let rdy2 = client
        .get(format!("http://127.0.0.1:{p1}/ready"))
        .send()
        .unwrap();
    assert_eq!(rdy2.status().as_u16(), 200);

    let v3: Value = client.get(&url_rt).send().unwrap().json().unwrap();
    assert!(v3.get("ready").and_then(|x| x.as_bool()).unwrap());
}
