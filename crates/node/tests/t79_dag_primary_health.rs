//! T79.0 / T81.2: dag-primary health endpoint integration test (pure DAG semantics)
//!
//! This test validates the `/health/dag_primary` endpoint:
//! - Returns 200 when in dag-primary mode with blocks and txs flowing
//! - Returns 503 with "wrong_mode" reason when not in dag-primary mode
//!
//! The test uses the existing test infrastructure from common.rs.

mod common;

use std::path::PathBuf;
use std::time::Duration;
use std::thread::sleep;

/// Parse a Prometheus metric value from metrics text output.
fn parse_metric_value(metrics_text: &str, metric_name: &str) -> Option<i64> {
    for line in metrics_text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with(metric_name) {
            let after_name = &line[metric_name.len()..];
            let first_char = after_name.chars().next();
            if matches!(first_char, Some(' ') | Some('{') | None) {
                let value_str = if first_char == Some('{') {
                    after_name.find('}')
                        .and_then(|pos| after_name[pos + 1..].split_whitespace().next())
                } else {
                    after_name.split_whitespace().next()
                }?;
                return value_str.parse().ok();
            }
        }
    }
    None
}

/// Call the dag_primary health endpoint and parse the response.
fn call_health_endpoint(port: u16) -> Result<(u16, serde_json::Value), String> {
    let url = format!("http://127.0.0.1:{}/health/dag_primary", port);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create client: {}", e))?;
    
    let resp = client.get(&url)
        .send()
        .map_err(|e| format!("Request failed: {}", e))?;
    
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json()
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;
    
    Ok((status, body))
}

/// T79.0 / T81.2: Test that the health endpoint returns 503 for wrong mode.
///
/// This test:
/// 1. Boots a node with consensus mode != 3 (not dag-primary)
/// 2. Calls /health/dag_primary
/// 3. Verifies HTTP 503 and "wrong_mode" reason in JSON
///
/// NOTE: Since T81.1, HotStuff modes may not be available in all builds.
/// This test verifies that non-dag-primary modes result in degraded status.
#[test]
#[ignore = "requires metrics,pq44-runtime features"]
fn t79_health_endpoint_wrong_mode() {
    let port: u16 = 19001;
    let metrics_port: u16 = 9901;
    let datadir = format!("/tmp/t79_health_wrong_mode_{}", port);
    
    // Clean up any previous test data
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir).expect("create datadir");
    
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();
    
    let chain_id_hex = "0000000000000000000000000000000000000001";
    
    println!("Starting health endpoint wrong_mode test on port {}", port);
    
    // Spawn node in hybrid mode (NOT dag-primary)
    // This tests that any non-dag-primary mode results in degraded status
    let metrics_bind = format!("127.0.0.1:{}", metrics_port);
    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &format!("127.0.0.1:{}", port),
            "--datadir", &datadir,
            "--genesis", genesis,
        ],
        &[
            ("EEZO_CHAIN_ID", chain_id_hex),
            ("EEZO_METRICS_BIND", &metrics_bind),
            // Set to hybrid mode (mode=1, NOT dag-primary)
            ("EEZO_CONSENSUS_MODE", "hybrid"),
        ],
    );
    
    // Wait for the node to be ready
    if !common::wait_until_ready(port, 15_000) {
        println!("Node stderr:\n{}", child.read_stderr());
        panic!("Node did not become ready within timeout");
    }
    println!("Node is ready");
    
    // Wait a moment for metrics to initialize
    sleep(Duration::from_secs(2));
    
    // Call the health endpoint
    let (status, body) = match call_health_endpoint(port) {
        Ok(result) => result,
        Err(e) => {
            child.kill();
            panic!("Health endpoint call failed: {}", e);
        }
    };
    
    println!("Health response: status={}, body={}", status, body);
    
    // Verify 503 status
    assert_eq!(status, 503, "Expected 503 status for wrong mode");
    
    // Verify JSON contains "degraded" status and "wrong_mode" reason
    assert_eq!(body["status"], "degraded", "Expected degraded status");
    assert_eq!(body["reason"], "wrong_mode", "Expected wrong_mode reason");
    // Mode 1 = hybrid (not dag-primary)
    assert_ne!(body["consensus_mode"], 3, "Expected consensus_mode != 3 (not dag-primary)");
    
    // Clean up
    child.kill();
    println!("Test completed successfully!");
}

/// T79.0 / T81.2: Test that the health endpoint returns 200 for healthy dag-primary mode.
///
/// This test:
/// 1. Boots a node in dag-primary mode
/// 2. Funds an account and submits transactions
/// 3. Waits for transactions to be included and block height to increase
/// 4. Calls /health/dag_primary
/// 5. Verifies HTTP 200 and "healthy" status in JSON
///
/// Health is based on DAG-only semantics:
/// - consensus mode is dag-primary (3)
/// - block height is increasing within the health window
/// - transactions are being included within the health window
#[test]
#[ignore = "requires dag-primary build with pq44-runtime,dag-consensus,metrics features"]
fn t79_health_endpoint_healthy() {
    use pqcrypto_mldsa::mldsa44::{keypair, detached_sign};
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

    let port: u16 = 19002;
    let metrics_port: u16 = 9902;
    let datadir = format!("/tmp/t79_health_healthy_{}", port);
    
    // Clean up any previous test data
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir).expect("create datadir");
    
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();
    
    let chain_id_bytes: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let chain_id_hex = hex::encode(chain_id_bytes);
    
    println!("Starting health endpoint healthy test on port {}", port);
    
    // Generate keypair
    let (pk, sk) = keypair();
    let pk_bytes = pk.as_bytes();
    let mut sender_address = [0u8; 20];
    sender_address.copy_from_slice(&pk_bytes[..20]);
    println!("Generated keypair: sender=0x{}", hex::encode(sender_address));
    
    // Spawn node in dag-primary mode (pure DAG semantics, no shadow checker)
    let metrics_bind = format!("127.0.0.1:{}", metrics_port);
    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &format!("127.0.0.1:{}", port),
            "--datadir", &datadir,
            "--genesis", genesis,
        ],
        &[
            ("EEZO_CHAIN_ID", &chain_id_hex),
            ("EEZO_METRICS_BIND", &metrics_bind),
            ("EEZO_CONSENSUS_MODE", "dag-primary"),
            ("EEZO_DAG_ORDERING_ENABLED", "1"),
            ("EEZO_HYBRID_STRICT_PROFILE", "1"),
            ("EEZO_EXECUTOR_MODE", "stm"),
            ("EEZO_EXEC_LANES", "16"),
            // Shorter window for faster test
            ("EEZO_DAG_PRIMARY_HEALTH_WINDOW_SECS", "30"),
        ],
    );
    
    // Wait for the node to be ready
    if !common::wait_until_ready(port, 15_000) {
        println!("Node stderr:\n{}", child.read_stderr());
        panic!("Node did not become ready within timeout");
    }
    println!("Node is ready");
    
    // Verify consensus mode is dag-primary (3)
    if !common::wait_until_metric_value(metrics_port, "eezo_consensus_mode_active", 3, 5_000) {
        child.kill();
        panic!("Consensus mode is not dag-primary");
    }
    println!("Consensus mode verified: dag-primary (3)");
    
    // Fund the sender address
    let client = reqwest::blocking::Client::new();
    let faucet_url = format!("http://127.0.0.1:{}/faucet", port);
    let faucet_body = serde_json::json!({
        "to": format!("0x{}", hex::encode(sender_address)),
        "amount": "1000000"
    });
    let resp = client.post(&faucet_url).json(&faucet_body).send();
    if resp.is_err() || !resp.unwrap().status().is_success() {
        child.kill();
        panic!("Faucet funding failed");
    }
    println!("Funded sender address");
    
    // Wait a moment for faucet tx to process
    sleep(Duration::from_secs(2));
    
    // Submit a few signed transactions
    let recipient: [u8; 20] = [0xDE; 20];
    for nonce in 0..5 {
        let core = eezo_ledger::TxCore {
            to: eezo_ledger::Address::from_bytes(recipient),
            amount: 100,
            fee: 10,
            nonce,
        };
        let msg = eezo_ledger::tx_domain_bytes(chain_id_bytes, &core);
        let sig = detached_sign(&msg, &sk);
        
        let tx_json = serde_json::json!({
            "tx": {
                "from": format!("0x{}", hex::encode(sender_address)),
                "to": format!("0x{}", hex::encode(recipient)),
                "amount": "100",
                "fee": "10",
                "nonce": nonce.to_string(),
                "chain_id": format!("0x{}", hex::encode(chain_id_bytes))
            },
            "pubkey": hex::encode(pk.as_bytes()),
            "sig": hex::encode(sig.as_bytes())
        });
        
        let tx_url = format!("http://127.0.0.1:{}/tx", port);
        let _ = client.post(&tx_url).json(&tx_json).send();
    }
    println!("Submitted 5 transactions");
    
    // Wait for transactions to be included (DAG-only liveness check)
    if !common::wait_until_metric_gte(metrics_port, "eezo_txs_included_total", 5, 30_000) {
        println!("Warning: Transactions may not have been included");
    }
    
    // Wait for block height to increase (DAG-only liveness check)
    if !common::wait_until_metric_gt_zero(metrics_port, "eezo_block_height", 10_000) {
        println!("Warning: Block height may not have increased");
    }
    
    // Now call the health endpoint
    let (status, body) = match call_health_endpoint(port) {
        Ok(result) => result,
        Err(e) => {
            child.kill();
            panic!("Health endpoint call failed: {}", e);
        }
    };
    
    println!("Health response: status={}, body={}", status, body);
    
    // Verify 200 status
    assert_eq!(status, 200, "Expected 200 status for healthy mode");
    
    // Verify JSON contains "healthy" status
    assert_eq!(body["status"], "healthy", "Expected healthy status");
    assert!(body.get("reason").is_none() || body["reason"].is_null(), "Expected no reason for healthy");
    assert_eq!(body["consensus_mode"], 3, "Expected consensus_mode=3 (dag-primary)");
    // Verify block_height is in the response (DAG-only metric)
    assert!(body.get("block_height").is_some(), "Expected block_height in response");
    
    // Clean up
    child.kill();
    println!("Test completed successfully!");
}