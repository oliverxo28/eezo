//! T78.9: DAG-Primary Integration Test
//!
//! This test validates the dag-primary mode with shadow HotStuff checker:
//! - Boots a node in dag-primary mode
//! - Funds a dev account via faucet
//! - Submits 10 signed transactions
//! - Verifies:
//!   - eezo_txs_included_total >= 10
//!   - eezo_dag_primary_shadow_checks_total > 0
//!   - eezo_consensus_mode_active == 3 (dag-primary)
//!
//! This test runs with devnet-safe (no unsigned transactions allowed).

mod common;

use std::path::PathBuf;

/// Generate ML-DSA-44 keypair and return (public_key_hex, secret_key_hex, address_hex)
fn generate_ml_dsa_keypair() -> (Vec<u8>, Vec<u8>, [u8; 20]) {
    use pqcrypto_mldsa::mldsa44::keypair;
    use pqcrypto_traits::sign::PublicKey as _;
    
    let (pk, sk) = keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    
    // Address is first 20 bytes of public key
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&pk_bytes[..20]);
    
    // Get secret key bytes
    use pqcrypto_traits::sign::SecretKey as _;
    let sk_bytes = sk.as_bytes().to_vec();
    
    (pk_bytes, sk_bytes, addr)
}

/// Sign a transaction using ML-DSA-44
fn sign_tx(
    chain_id: [u8; 20],
    to: [u8; 20],
    amount: u128,
    fee: u128,
    nonce: u64,
    pk_bytes: &[u8],
    sk_bytes: &[u8],
) -> serde_json::Value {
    use pqcrypto_mldsa::mldsa44::{detached_sign, SecretKey};
    use pqcrypto_traits::sign::DetachedSignature;
    
    // Reconstruct secret key from bytes
    let sk = SecretKey::from_bytes(sk_bytes).expect("valid secret key");
    
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
    let sig = detached_sign(&msg, &sk);
    let sig_bytes = sig.as_bytes();
    
    // Build JSON payload for /submit_tx endpoint
    serde_json::json!({
        "to": format!("0x{}", hex::encode(to)),
        "amount": amount.to_string(),
        "fee": fee.to_string(),
        "nonce": nonce,
        "pubkey": hex::encode(pk_bytes),
        "sig": hex::encode(sig_bytes)
    })
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

/// Submit a signed transaction
fn submit_tx(port: u16, tx_json: &serde_json::Value) -> bool {
    let url = format!("http://127.0.0.1:{}/submit_tx", port);
    
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

/// T78.9: Integration test for dag-primary mode with signed transactions.
///
/// This test:
/// 1. Boots a node in dag-primary mode with shadow checker enabled
/// 2. Funds a dev account via faucet
/// 3. Submits 10 signed transactions
/// 4. Waits for blocks and verifies metrics
///
/// Requirements:
/// - Must use devnet-safe (no unsigned tx support)
/// - eezo_consensus_mode_active == 3 (dag-primary)
/// - eezo_dag_primary_shadow_checks_total > 0 (shadow checker running)
/// - eezo_txs_included_total >= 10 (transactions included)
#[test]
#[ignore = "requires dag-primary build with pq44-runtime,dag-consensus,hotstuff-shadow,metrics features"]
fn t78_dag_primary_shadow_checker_integration() {
    let port: u16 = 18900;
    let metrics_port: u16 = 9900;
    let datadir = format!("/tmp/t78_dag_primary_test_{}", port);
    
    // Clean up any previous test data
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir).expect("create datadir");
    
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../genesis.min.json");
    let genesis = genesis_path.to_str().unwrap();
    
    // Chain ID must match genesis
    let chain_id_hex = "0000000000000000000000000000000000000001";
    let chain_id_bytes: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    
    println!("Starting dag-primary integration test on port {}", port);
    
    // Generate keypair for signing transactions
    let (pk_bytes, sk_bytes, sender_addr) = generate_ml_dsa_keypair();
    println!("Generated keypair: sender=0x{}", hex::encode(sender_addr));
    
    // Spawn node in dag-primary mode with shadow checker enabled
    let mut child = common::spawn_node_with_env(
        &[
            "--listen", &format!("127.0.0.1:{}", port),
            "--metrics-bind", &format!("127.0.0.1:{}", metrics_port),
            "--datadir", &datadir,
            "--genesis", genesis,
        ],
        &[
            ("EEZO_CHAIN_ID", chain_id_hex),
            ("EEZO_CONSENSUS_MODE", "dag-primary"),
            ("EEZO_DAG_ORDERING_ENABLED", "1"),
            ("EEZO_DAG_PRIMARY_SHADOW_ENABLED", "1"),
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
    
    // Verify consensus mode is dag-primary (3)
    if !common::wait_until_metric_value(metrics_port, "eezo_consensus_mode_active", 3, 5_000) {
        println!("Consensus mode is not dag-primary (expected 3)");
        child.kill();
        panic!("Consensus mode check failed");
    }
    println!("Consensus mode verified: dag-primary (3)");
    
    // Fund the sender address via faucet
    // Need enough for 10 txs with amount=1000 and fee=100 each = 11000
    if !fund_address(port, &sender_addr, 100_000) {
        println!("Faucet funding failed");
        child.kill();
        panic!("Faucet funding failed");
    }
    println!("Funded sender address with 100,000");
    
    // Wait a moment for the faucet tx to be processed
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Submit 10 signed transactions
    let recipient: [u8; 20] = [0xDE; 20]; // Some random recipient
    let mut submitted = 0;
    for nonce in 0..10 {
        let tx_json = sign_tx(
            chain_id_bytes,
            recipient,
            1000,  // amount
            100,   // fee
            nonce,
            &pk_bytes,
            &sk_bytes,
        );
        
        if submit_tx(port, &tx_json) {
            submitted += 1;
            println!("Submitted tx nonce={}", nonce);
        } else {
            println!("Failed to submit tx nonce={}", nonce);
        }
    }
    
    assert_eq!(submitted, 10, "Should have submitted all 10 transactions");
    println!("All 10 transactions submitted");
    
    // Wait for transactions to be included (up to 30 seconds)
    // In dag-primary mode, transactions go through DAG ordering
    if !common::wait_until_metric_gte(metrics_port, "eezo_txs_included_total", 10, 30_000) {
        println!("Transactions not included within timeout");
        if let Some(value) = common::get_metric_value(metrics_port, "eezo_txs_included_total") {
            println!("eezo_txs_included_total = {}", value);
        }
        child.kill();
        panic!("Transaction inclusion check failed");
    }
    println!("Transaction inclusion verified: >= 10 txs included");
    
    // Verify shadow checker is running (shadow_checks_total > 0)
    if !common::wait_until_metric_gt_zero(metrics_port, "eezo_dag_primary_shadow_checks_total", 10_000) {
        println!("Shadow checker not running");
        child.kill();
        panic!("Shadow checker metric check failed");
    }
    println!("Shadow checker verified: > 0 checks performed");
    
    // Print final metrics summary
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_txs_included_total") {
        println!("Final: eezo_txs_included_total = {}", v);
    }
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_dag_primary_shadow_checks_total") {
        println!("Final: eezo_dag_primary_shadow_checks_total = {}", v);
    }
    if let Some(v) = common::get_metric_value(metrics_port, "eezo_dag_primary_shadow_mismatch_total") {
        println!("Final: eezo_dag_primary_shadow_mismatch_total = {}", v);
        // Verify no mismatches
        assert_eq!(v, 0, "Should have 0 shadow mismatches");
    }
    
    // Clean up
    child.kill();
    println!("Test completed successfully!");
}
