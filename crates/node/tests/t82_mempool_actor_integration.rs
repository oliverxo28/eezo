//! T82.2c: Mempool Actor Integration Test for DAG-Primary Mode
//!
//! This test validates that when EEZO_MEMPOOL_ACTOR_ENABLED=1 is set in DAG-primary mode:
//! - The mempool actor is the source of tx batches for block building
//! - eezo_mempool_batches_served_total increments when batches are served
//! - eezo_mempool_inflight_len reflects in-flight transactions and goes to 0 after commit
//!
//! Test procedure:
//! 1. Boot a minimal DAG-primary node with EEZO_MEMPOOL_ACTOR_ENABLED=1
//! 2. Submit 20 transactions via HTTP
//! 3. Wait for them to be included
//! 4. Assert:
//!    - eezo_txs_included_total >= 20
//!    - eezo_mempool_actor_enabled == 1
//!    - eezo_mempool_batches_served_total > 0
//!    - eezo_mempool_inflight_len == 0 (or very small when idle)

mod common;

use std::path::PathBuf;
use pqcrypto_mldsa::mldsa44::{keypair, detached_sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};

/// Helper struct to hold keypair and sign transactions
struct TxSigner {
    pk: PublicKey,
    sk: SecretKey,
    address: [u8; 20],
}

impl TxSigner {
    /// Generate a new ML-DSA-44 keypair
    fn new() -> Self {
        let (pk, sk) = keypair();
        let pk_bytes = pk.as_bytes();
        
        // Address is first 20 bytes of public key
        let mut address = [0u8; 20];
        address.copy_from_slice(&pk_bytes[..20]);
        
        Self { pk, sk, address }
    }
    
    /// Sign a transaction and return JSON payload for /tx endpoint
    fn sign_tx(
        &self,
        chain_id: [u8; 20],
        to: [u8; 20],
        amount: u128,
        fee: u128,
        nonce: u64,
    ) -> serde_json::Value {
        // Create transaction core
        let core = eezo_ledger::TxCore {
            to: eezo_ledger::Address::from_bytes(to),
            amount,
            fee,
            nonce,
        };
        
        // Create domain-separated message for signing
        let msg = eezo_ledger::tx_domain_bytes(chain_id, &core);
        
        // Sign the message
        let sig = detached_sign(&msg, &self.sk);
        let sig_bytes = sig.as_bytes();
        
        // Build JSON payload for /tx endpoint (SignedTxEnvelope format)
        serde_json::json!({
            "tx": {
                "from": format!("0x{}", hex::encode(self.address)),
                "to": format!("0x{}", hex::encode(to)),
                "amount": amount.to_string(),
                "fee": fee.to_string(),
                "nonce": nonce.to_string(),
                "chain_id": format!("0x{}", hex::encode(chain_id))
            },
            "pubkey": hex::encode(self.pk.as_bytes()),
            "sig": hex::encode(sig_bytes)
        })
    }
}

/// Fund an address via the faucet
fn fund_address(port: u16, address: &[u8; 20], amount: u128) -> bool {
    let url = format!("http://127.0.0.1:{}/faucet", port);
    let body = serde_json::json!({
        "to": format!("0x{}", hex::encode(address)),
        "amount": amount.to_string()
    });
    
    let client = reqwest::blocking::Client::new();
    match client.post(&url).json(&body).send() {
        Ok(resp) => {
            let status = resp.status();
            println!("Faucet response: status={}", status);
            status.is_success()
        }
        Err(e) => {
            println!("Faucet request failed: {}", e);
            false
        }
    }
}

/// Submit a signed transaction via POST /tx
fn submit_tx(port: u16, tx_json: &serde_json::Value) -> bool {
    let url = format!("http://127.0.0.1:{}/tx", port);
    
    let client = reqwest::blocking::Client::new();
    match client.post(&url).json(tx_json).send() {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                if let Ok(text) = resp.text() {
                    println!("Submit tx failed: status={} body={}", status, text);
                }
                return false;
            }
            true
        }
        Err(e) => {
            println!("Submit tx request failed: {}", e);
            false
        }
    }
}

/// T82.2c: Integration test for mempool actor in DAG-primary mode.
///
/// This test:
/// 1. Boots a node in dag-primary mode with EEZO_MEMPOOL_ACTOR_ENABLED=1
/// 2. Funds a dev account via faucet
/// 3. Submits 20 signed transactions
/// 4. Waits for blocks and verifies:
///    - eezo_txs_included_total >= 20
///    - eezo_mempool_actor_enabled == 1
///    - eezo_mempool_batches_served_total > 0
///    - eezo_mempool_inflight_len == 0 (after idle)
///
/// Requirements:
/// - Must use devnet-safe (no unsigned tx support)
/// - EEZO_MEMPOOL_ACTOR_ENABLED=1
#[test]
#[ignore = "requires dag-primary build with pq44-runtime,dag-consensus,metrics features"]
fn t82_mempool_actor_dag_primary_integration() {
    let port: u16 = 18910;
    let metrics_port: u16 = 9910;
    let datadir = format!("/tmp/t82_mempool_actor_test_{}", port);
    
    // Clean up any previous test data
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir).expect("create datadir");
    
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();
    
    // Chain ID must match genesis (19 zero bytes followed by 0x01)
    let chain_id_bytes: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let chain_id_hex = hex::encode(chain_id_bytes);
    
    println!("Starting T82.2c mempool actor integration test on port {}", port);
    
    // Generate keypair for signing transactions
    let signer = TxSigner::new();
    println!("Generated keypair: sender=0x{}", hex::encode(signer.address));
    
    // Spawn node in dag-primary mode with mempool actor enabled
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
            ("EEZO_MEMPOOL_ACTOR_ENABLED", "1"),  // Key: enable mempool actor
            ("EEZO_HYBRID_STRICT_PROFILE", "1"),
            ("EEZO_EXECUTOR_MODE", "stm"),
            ("EEZO_EXEC_LANES", "16"),
        ],
    );
    
    // Wait for the node to be ready
    if !common::wait_until_ready(port, 15_000) {
        println!("Node stderr:\n{}", child.read_stderr());
        panic!("Node did not become ready within timeout");
    }
    println!("Node is ready");
    
    // Verify mempool actor is enabled (metric should be 1)
    if !common::wait_until_metric_value(metrics_port, "eezo_mempool_actor_enabled", 1, 5_000) {
        println!("Mempool actor is not enabled (expected eezo_mempool_actor_enabled=1)");
        child.kill();
        panic!("Mempool actor enabled check failed");
    }
    println!("Mempool actor verified: enabled (1)");
    
    // Fund the sender address via faucet
    // Need enough for 20 txs with amount=1000 and fee=100 each = 22000
    if !fund_address(port, &signer.address, 200_000) {
        println!("Faucet funding failed");
        child.kill();
        panic!("Faucet funding failed");
    }
    println!("Funded sender address with 200,000");
    
    // Wait a moment for the faucet tx to be processed
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Submit 20 signed transactions
    let recipient: [u8; 20] = [0xDE; 20]; // Some random recipient
    let mut submitted = 0;
    for nonce in 0..20 {
        let tx_json = signer.sign_tx(
            chain_id_bytes,
            recipient,
            1000,  // amount
            100,   // fee
            nonce,
        );
        
        if submit_tx(port, &tx_json) {
            submitted += 1;
            println!("Submitted tx nonce={}", nonce);
        } else {
            println!("Failed to submit tx nonce={}", nonce);
        }
    }
    
    assert_eq!(submitted, 20, "Should have submitted all 20 transactions");
    println!("All 20 transactions submitted");
    
    // Wait for transactions to be included (up to 30 seconds)
    if !common::wait_until_metric_gte(metrics_port, "eezo_txs_included_total", 20, 30_000) {
        println!("Transactions not included within timeout");
        if let Some(value) = common::get_metric_value(metrics_port, "eezo_txs_included_total") {
            println!("eezo_txs_included_total = {}", value);
        }
        child.kill();
        panic!("Transaction inclusion check failed");
    }
    println!("Transaction inclusion verified: >= 20 txs included");
    
    // Wait a moment for the system to be idle
    std::thread::sleep(std::time::Duration::from_secs(1));
    
    // Verify mempool_batches_served_total > 0
    if !common::wait_until_metric_gte(metrics_port, "eezo_mempool_batches_served_total", 1, 5_000) {
        println!("Mempool batches served total is 0 (expected > 0)");
        if let Some(value) = common::get_metric_value(metrics_port, "eezo_mempool_batches_served_total") {
            println!("eezo_mempool_batches_served_total = {}", value);
        }
        child.kill();
        panic!("Mempool batches served check failed");
    }
    println!("Mempool batches served verified: > 0");
    
    // Verify mempool_inflight_len is 0 or very small when idle
    if let Some(inflight) = common::get_metric_value(metrics_port, "eezo_mempool_inflight_len") {
        println!("eezo_mempool_inflight_len = {}", inflight);
        assert!(inflight <= 5, "In-flight count should be small when idle (got {})", inflight);
    }
    println!("Mempool in-flight len verified: small/zero when idle");
    
    // Print final metrics summary
    println!("\n=== Final Metrics Summary ===");
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_txs_included_total") {
        println!("eezo_txs_included_total = {}", v);
    }
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_mempool_actor_enabled") {
        println!("eezo_mempool_actor_enabled = {}", v);
        assert_eq!(v, 1, "Should have mempool actor enabled");
    }
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_mempool_batches_served_total") {
        println!("eezo_mempool_batches_served_total = {}", v);
        assert!(v > 0, "Should have served batches (got {})", v);
    }
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_mempool_inflight_len") {
        println!("eezo_mempool_inflight_len = {}", v);
    }
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_block_height") {
        println!("eezo_block_height = {}", v);
    }
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_consensus_mode_active") {
        println!("eezo_consensus_mode_active = {}", v);
        assert_eq!(v, 3, "Should be in dag-primary mode (3)");
    }
    
    // Clean up
    child.kill();
    println!("\nTest completed successfully!");
}
