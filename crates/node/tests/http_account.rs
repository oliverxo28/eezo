// T76.8: Tests for /account endpoint fix
mod common;

use std::path::PathBuf;

/// T76.8: Test that GET /account/:addr returns funded balance after faucet mint
#[test]
fn account_path_returns_funded_balance() {
    let port: u16 = 18200;
    let datadir = format!("crates/node/target/testdata/http_account_{}", port);

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let chain_id_hex = "0000000000000000000000000000000000000001";

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
            ("EEZO_METRICS", "on"),
        ],
    );

    assert!(common::wait_until_ready(port, 10_000), "Node did not become ready");

    // Test address (20-byte hex, lowercase, with 0x prefix)
    let test_addr = "0x0000000000000000000000000000000000000123";
    let mint_amount = 1_000_000u64;

    // 1. Mint via /faucet
    let faucet_url = format!("http://127.0.0.1:{}/faucet", port);
    let client = reqwest::blocking::Client::new();
    let faucet_resp = client
        .post(&faucet_url)
        .json(&serde_json::json!({
            "to": test_addr,
            "amount": mint_amount.to_string()
        }))
        .send()
        .expect("faucet request should succeed");
    
    assert_eq!(faucet_resp.status(), 200, "Faucet should return 200");
    let faucet_json: serde_json::Value = faucet_resp.json().expect("faucet should return JSON");
    assert!(faucet_json.get("balance").is_some(), "Faucet response should have balance");

    // 2. Verify GET /account/:addr returns the funded balance (path-based)
    let addr_without_prefix = &test_addr[2..]; // Remove "0x" prefix
    let account_url = format!("http://127.0.0.1:{}/account/{}", port, addr_without_prefix);
    let account_resp = client
        .get(&account_url)
        .send()
        .expect("account request should succeed");
    
    assert_eq!(account_resp.status(), 200, "Account endpoint should return 200");
    let account_json: serde_json::Value = account_resp.json().expect("account should return JSON");
    
    // Check balance is non-zero
    let balance_str = account_json["balance"].as_str().expect("balance should be string");
    let balance: u64 = balance_str.parse().expect("balance should be numeric");
    assert_eq!(balance, mint_amount, "Balance should match minted amount");

    // 3. Verify with 0x prefix also works
    let account_url_with_prefix = format!("http://127.0.0.1:{}/account/{}", port, test_addr);
    let account_resp_2 = client
        .get(&account_url_with_prefix)
        .send()
        .expect("account request with 0x prefix should succeed");
    
    assert_eq!(account_resp_2.status(), 200, "Account endpoint with 0x prefix should return 200");

    child.kill();
}

/// T76.8: Test that GET /account?addr=... (query param) also works
#[test]
fn account_query_param_returns_funded_balance() {
    let port: u16 = 18201;
    let datadir = format!("crates/node/target/testdata/http_account_query_{}", port);

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let chain_id_hex = "0000000000000000000000000000000000000001";

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
            ("EEZO_METRICS", "on"),
        ],
    );

    assert!(common::wait_until_ready(port, 10_000), "Node did not become ready");

    let test_addr = "0x0000000000000000000000000000000000000456";
    let mint_amount = 500_000u64;

    // 1. Mint via /faucet
    let faucet_url = format!("http://127.0.0.1:{}/faucet", port);
    let client = reqwest::blocking::Client::new();
    let faucet_resp = client
        .post(&faucet_url)
        .json(&serde_json::json!({
            "to": test_addr,
            "amount": mint_amount.to_string()
        }))
        .send()
        .expect("faucet request should succeed");
    
    assert_eq!(faucet_resp.status(), 200, "Faucet should return 200");

    // 2. Verify GET /account?addr=... works (query param shim)
    let account_query_url = format!("http://127.0.0.1:{}/account?addr={}", port, test_addr);
    let account_resp = client
        .get(&account_query_url)
        .send()
        .expect("account query request should succeed");
    
    assert_eq!(account_resp.status(), 200, "Account query endpoint should return 200");
    let account_json: serde_json::Value = account_resp.json().expect("account should return JSON");
    
    let balance_str = account_json["balance"].as_str().expect("balance should be string");
    let balance: u64 = balance_str.parse().expect("balance should be numeric");
    assert_eq!(balance, mint_amount, "Balance should match minted amount");

    child.kill();
}

/// T76.8: Test that unknown address returns 200 with zero balance (consistent with existing behavior)
#[test]
fn account_unknown_address_returns_zero_balance() {
    let port: u16 = 18202;
    let datadir = format!("crates/node/target/testdata/http_account_unknown_{}", port);

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let chain_id_hex = "0000000000000000000000000000000000000001";

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
            ("EEZO_METRICS", "on"),
        ],
    );

    assert!(common::wait_until_ready(port, 10_000), "Node did not become ready");

    // Use an address that has never been funded
    let unknown_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    let client = reqwest::blocking::Client::new();
    let account_url = format!("http://127.0.0.1:{}/account/{}", port, unknown_addr);
    let account_resp = client
        .get(&account_url)
        .send()
        .expect("account request should succeed");
    
    // Should return 200 with zero balance (not 404)
    assert_eq!(account_resp.status(), 200, "Account endpoint should return 200 for unknown address");
    let account_json: serde_json::Value = account_resp.json().expect("account should return JSON");
    
    let balance_str = account_json["balance"].as_str().expect("balance should be string");
    assert_eq!(balance_str, "0", "Unknown address should have zero balance");
    
    let nonce_str = account_json["nonce"].as_str().expect("nonce should be string");
    assert_eq!(nonce_str, "0", "Unknown address should have zero nonce");

    child.kill();
}

/// T76.8: Test that missing addr query param returns 400
#[test]
fn account_missing_query_param_returns_400() {
    let port: u16 = 18203;
    let datadir = format!("crates/node/target/testdata/http_account_missing_param_{}", port);

    std::fs::create_dir_all(&datadir).ok();

    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();

    let chain_id_hex = "0000000000000000000000000000000000000001";

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
            ("EEZO_METRICS", "on"),
        ],
    );

    assert!(common::wait_until_ready(port, 10_000), "Node did not become ready");

    let client = reqwest::blocking::Client::new();
    // GET /account without any query param should return 400
    let account_url = format!("http://127.0.0.1:{}/account", port);
    let account_resp = client
        .get(&account_url)
        .send()
        .expect("account request should succeed");
    
    assert_eq!(account_resp.status(), 400, "Account endpoint without addr param should return 400");
    let account_json: serde_json::Value = account_resp.json().expect("account should return JSON");
    assert!(account_json.get("error").is_some(), "Error response should have error field");

    child.kill();
}
