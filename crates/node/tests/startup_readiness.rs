mod common;

use std::path::PathBuf;

#[test]
fn readiness_flips_to_503_then_back_to_200() {
    let port: u16 = 18130;
    let datadir = format!("crates/node/target/testdata/readiness_{}", port);

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    // match your genesis chain id (20 bytes ending with 0x01)
    let chain_id_hex = "0000000000000000000000000000000000000001";
    let admin_token = "t22admin";

    let mut child = common::spawn_node_with_env(
        &[
            "--listen",
            &format!("127.0.0.1:{}", port),
            "--datadir",
            &datadir,
            "--genesis",
            genesis,
        ],
        &[
            ("EEZO_CHAIN_ID", chain_id_hex),
            ("EEZO_ADMIN_TOKEN", admin_token),
        ],
    );

    // ensure it started
    assert!(common::wait_until_ready(port, 10_000));

    // 200 OK when ready
    let url_ready = format!("http://127.0.0.1:{}/ready", port);
    let resp = reqwest::blocking::get(&url_ready).unwrap();
    assert!(resp.status().is_success());

    // Degrade
    let url_degrade = format!(
        "http://127.0.0.1:{}/_admin/degrade?token={}",
        port, admin_token
    );
    let resp = reqwest::blocking::get(&url_degrade).unwrap();
    assert!(resp.status().is_success());

    // Now /ready should be 503
    let resp = reqwest::blocking::get(&url_ready).unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    // Restore
    let url_restore = format!(
        "http://127.0.0.1:{}/_admin/restore?token={}",
        port, admin_token
    );
    let resp = reqwest::blocking::get(&url_restore).unwrap();
    assert!(resp.status().is_success());

    // /ready back to 200
    let resp = reqwest::blocking::get(&url_ready).unwrap();
    assert!(resp.status().is_success());

    child.kill();
}
