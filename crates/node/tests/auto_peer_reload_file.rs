use std::time::Duration;
use reqwest::blocking::Client;
mod common;

/// Write a node config TOML to `cfg_path`, making sure the parent dir exists.
fn write_cfg(cfg_path: &str, listen_port: u16, datadir: &str, peers: &[u16]) {
    use std::io::Write;
    if let Some(dir) = std::path::Path::new(cfg_path).parent() {
        std::fs::create_dir_all(dir).expect("mkdir -p for config parent dir");
    }
    let peers_str = peers
        .iter()
        .map(|p| format!("\"http://127.0.0.1:{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
listen = "127.0.0.1:{listen}"
datadir = "{datadir}"
log_level = "info"
peers = [{peers}]
"#,
        listen = listen_port,
        datadir = datadir,
        peers = peers_str
    );
    let mut f = std::fs::File::create(cfg_path).expect("open config for write");
    f.write_all(toml.as_bytes()).expect("write config toml");
}

#[test]
fn hot_reload_from_config_file_updates_peers_and_metrics() {
    let client = Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .unwrap();

    // three ports
    let p1 = common::free_port();
    let p2 = common::free_port();
    let p3 = common::free_port();

    // datadirs + CLI
    let d1 = common::unique_test_datadir("peer_reload_file", p1);
    let d2 = common::unique_test_datadir("peer_reload_file", p2);
    let d3 = common::unique_test_datadir("peer_reload_file", p3);
    let a1 = ["--listen", &format!("127.0.0.1:{p1}"), "--datadir", &d1];
    let a2 = ["--listen", &format!("127.0.0.1:{p2}"), "--datadir", &d2];
    let a3 = ["--listen", &format!("127.0.0.1:{p3}"), "--datadir", &d3];

    // node1 config file path (we’ll pass this via EEZO_CONFIG_FILE)
    let cfg1_path = format!("{}/node1.toml", d1);

    // initial node1 config: peers = [p2]
    write_cfg(&cfg1_path, p1, &d1, &[p2]);

    // start nodes
    let _g1 = common::spawn_node_with_env(&a1, &[("EEZO_CONFIG_FILE", &cfg1_path)]);
    let _g2 = common::spawn_node_with_env(
        &a2,
        &[(&common::peers_env_from_ports(&[p1]).0, &common::peers_env_from_ports(&[p1]).1)],
    );
    // node3 stays down for now

    // let node1 collect initial metrics
    std::thread::sleep(Duration::from_millis(1200));
    let m1 = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(m1.contains("eezo_node_peers_total 1"));

    // update node1 config to peers = [p2, p3]
    write_cfg(&cfg1_path, p1, &d1, &[p2, p3]);

    // trigger reload FROM FILE via GET /reload (T24.12 behavior)
    let r = client
        .get(format!("http://127.0.0.1:{p1}/reload"))
        .send()
        .unwrap();
    assert!(r.status().is_success());

    // now start node3 (it will ping back to node1)
    let _g3 = common::spawn_node_with_env(
        &a3,
        &[(&common::peers_env_from_ports(&[p1]).0, &common::peers_env_from_ports(&[p1]).1)],
    );

    // wait for refresh and check peers_total==2
    std::thread::sleep(Duration::from_millis(1500));
    let m1b = client
        .get(format!("http://127.0.0.1:{p1}/metrics"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    println!("Metrics after reload-from-file:\n{}", m1b);
    assert!(m1b.contains("eezo_node_peers_total 2"));
}
