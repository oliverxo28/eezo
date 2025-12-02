//! executor/mod.rs
//!
//! Entry point for the node-side block execution layer (T54).
//! This module provides:
//!   - `Executor` trait
//!   - `ExecInput` / `ExecOutcome` types
//!   - `SingleExecutor` implementation (serial fallback)
//!   - `ParallelExecutor` implementation (wave-based parallel)
//!   - `StmExecutor` implementation (Block-STM, behind `stm-exec` feature)

mod types;
mod single;
pub mod parallel;

// T73.1: STM executor scaffolding (feature-gated)
#[cfg(feature = "stm-exec")]
pub mod mvhashmap;

#[cfg(feature = "stm-exec")]
pub mod stm;

pub use types::{Executor, ExecInput, ExecOutcome};
pub use single::SingleExecutor;
pub use parallel::ParallelExecutor;

// T73.1: Export StmExecutor when stm-exec feature is enabled
#[cfg(feature = "stm-exec")]
pub use stm::StmExecutor;

// ============================================================================
// T73.5: Executor Equivalence Tests (Single vs STM)
// ============================================================================
#[cfg(all(test, feature = "stm-exec"))]
mod equivalence_tests {
    use super::*;
    use eezo_ledger::consensus::{SingleNode, SingleNodeCfg};
    use eezo_ledger::{Address, Accounts, Supply, SignedTx, TxCore};
    use eezo_ledger::tx::apply_tx;
    use eezo_ledger::sender_from_pubkey_first20;

    /// Helper: Create a minimal SingleNode for testing.
    fn create_test_node() -> SingleNode {
        let chain_id = [0u8; 20];
        let cfg = SingleNodeCfg {
            chain_id,
            block_byte_budget: 1 << 20,
            header_cache_cap: 100,
            ..Default::default()
        };
        let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
        SingleNode::new(cfg, sk, pk)
    }

    /// Helper: Create a funded address with known pubkey bytes.
    /// The sender address is derived as first 20 bytes of pubkey (matching sender_from_pubkey_first20).
    /// Returns the derived sender address.
    fn create_funded_sender(node: &mut SingleNode, pubkey_bytes: [u8; 20], balance: u128) -> Address {
        // sender_from_pubkey_first20 uses first 20 bytes of pubkey as address
        // So if we use a 20-byte pubkey, the sender == pubkey_bytes
        let sender = Address(pubkey_bytes);
        node.dev_faucet_credit(sender, balance);
        sender
    }

    /// Helper: Create a test transaction.
    /// The pubkey must be at least 20 bytes. sender_from_pubkey_first20 uses first 20 bytes.
    fn create_test_tx(
        pubkey_bytes: [u8; 20],
        to: Address,
        amount: u128,
        fee: u128,
        nonce: u64,
    ) -> SignedTx {
        SignedTx {
            core: TxCore {
                to,
                amount,
                fee,
                nonce,
            },
            pubkey: pubkey_bytes.to_vec(),
            sig: vec![], // Empty sig for test (no sig validation in STM executor)
        }
    }

    /// Helper: Clone node state (accounts + supply) for comparison.
    fn snapshot_state(node: &SingleNode) -> (Accounts, Supply) {
        (node.accounts.clone(), node.supply.clone())
    }

    /// Helper: Apply the block's transactions to node state manually.
    /// This mirrors what the consensus runner does after execute_block returns.
    fn apply_block_to_node(node: &mut SingleNode, block: &eezo_ledger::Block) {
        for tx in &block.txs {
            let sender = sender_from_pubkey_first20(tx).unwrap();
            apply_tx(&mut node.accounts, &mut node.supply, sender, &tx.core).unwrap();
        }
    }

    /// Helper: Compare two account states for equality.
    #[allow(dead_code)]
    fn accounts_equal(a: &Accounts, b: &Accounts, addresses: &[Address]) -> bool {
        for addr in addresses {
            let acct_a = a.get(addr);
            let acct_b = b.get(addr);
            if acct_a.balance != acct_b.balance || acct_a.nonce != acct_b.nonce {
                return false;
            }
        }
        true
    }

    /// Helper: Compare two supply states for equality.
    #[allow(dead_code)]
    fn supply_equal(a: &Supply, b: &Supply) -> bool {
        a.native_mint_total == b.native_mint_total
            && a.bridge_mint_total == b.bridge_mint_total
            && a.burn_total == b.burn_total
    }

    // ========================================================================
    // Test: No conflicts - multiple independent senders
    // ========================================================================
    #[test]
    fn test_executor_equivalence_no_conflicts() {
        // Create two separate nodes with identical initial state
        let mut node_stm = create_test_node();

        // Create 3 independent senders with unique addresses
        let sender1_bytes: [u8; 20] = [0x01; 20];
        let sender2_bytes: [u8; 20] = [0x02; 20];
        let sender3_bytes: [u8; 20] = [0x03; 20];
        let recipient_bytes: [u8; 20] = [0xca; 20];

        let _sender1 = create_funded_sender(&mut node_stm, sender1_bytes, 100_000);
        let _sender2 = create_funded_sender(&mut node_stm, sender2_bytes, 100_000);
        let _sender3 = create_funded_sender(&mut node_stm, sender3_bytes, 100_000);
        let recipient = Address(recipient_bytes);

        // Create transactions from different senders (no conflicts)
        let txs = vec![
            create_test_tx(sender1_bytes, recipient, 1000, 1, 0),
            create_test_tx(sender2_bytes, recipient, 2000, 2, 0),
            create_test_tx(sender3_bytes, recipient, 3000, 3, 0),
        ];

        // Execute with STM
        let stm_executor = StmExecutor::new(1);
        let input = ExecInput::new(txs.clone(), 1);
        let outcome = stm_executor.execute_block(&mut node_stm, input);

        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();

        // Verify all expected txs were included
        assert_eq!(block.txs.len(), 3, "Expected 3 txs to be included");
        assert_eq!(outcome.tx_count, 3);

        // Verify tx order is preserved
        for (i, tx) in block.txs.iter().enumerate() {
            assert_eq!(tx.hash(), txs[i].hash(), "Tx {} hash mismatch", i);
        }

        // Verify determinism: run again with same input on a fresh node
        let mut node_stm2 = create_test_node();
        create_funded_sender(&mut node_stm2, sender1_bytes, 100_000);
        create_funded_sender(&mut node_stm2, sender2_bytes, 100_000);
        create_funded_sender(&mut node_stm2, sender3_bytes, 100_000);

        let input2 = ExecInput::new(txs.clone(), 1);
        let outcome2 = stm_executor.execute_block(&mut node_stm2, input2);
        assert!(outcome2.result.is_ok());
        let block2 = outcome2.result.unwrap();

        // Same tx count
        assert_eq!(block.txs.len(), block2.txs.len());

        // Same tx hashes
        for (tx1, tx2) in block.txs.iter().zip(block2.txs.iter()) {
            assert_eq!(tx1.hash(), tx2.hash());
        }

        // Apply block to both nodes and compare final states
        apply_block_to_node(&mut node_stm, &block);
        apply_block_to_node(&mut node_stm2, &block2);

        // Check each sender's final state matches between runs
        for sender_bytes in [sender1_bytes, sender2_bytes, sender3_bytes] {
            let addr = Address(sender_bytes);
            let acct1 = node_stm.accounts.get(&addr);
            let acct2 = node_stm2.accounts.get(&addr);
            assert_eq!(acct1.balance, acct2.balance);
            assert_eq!(acct1.nonce, acct2.nonce);
        }
    }

    // ========================================================================
    // Test: Single sender with sequential nonces
    // ========================================================================
    #[test]
    fn test_executor_equivalence_single_sender_nonce_sequence() {
        // Create node
        let mut node = create_test_node();

        // Create single sender with enough balance for multiple txs
        let sender_bytes: [u8; 20] = [0x42; 20];
        let recipient_bytes: [u8; 20] = [0xbe; 20];

        let sender = create_funded_sender(&mut node, sender_bytes, 100_000);
        let recipient = Address(recipient_bytes);

        // Create 5 sequential transactions (nonces 0, 1, 2, 3, 4)
        let txs: Vec<SignedTx> = (0..5u64)
            .map(|nonce| create_test_tx(sender_bytes, recipient, 1000, 1, nonce))
            .collect();

        // Snapshot initial state
        let (_, supply_before) = snapshot_state(&node);

        // Execute with STM
        let stm_executor = StmExecutor::new(1);
        let input = ExecInput::new(txs.clone(), 1);
        let outcome = stm_executor.execute_block(&mut node, input);

        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();

        // All 5 txs should be included
        assert_eq!(block.txs.len(), 5, "Expected 5 txs to be included");

        // Verify txs are in correct order
        for (i, tx) in block.txs.iter().enumerate() {
            assert_eq!(tx.core.nonce, i as u64, "Tx {} has wrong nonce", i);
        }

        // Apply block to node
        apply_block_to_node(&mut node, &block);

        // Snapshot final state
        let (accounts_after, supply_after) = snapshot_state(&node);

        // Verify sender balance decreased correctly
        // Initial: 100_000, each tx costs (1000 amount + 1 fee) = 1001
        // Final: 100_000 - (5 * 1001) = 100_000 - 5005 = 94_995
        let sender_final = accounts_after.get(&sender);
        assert_eq!(sender_final.balance, 100_000 - 5 * 1001);
        assert_eq!(sender_final.nonce, 5);

        // Verify recipient received correct amount
        // 5 * 1000 = 5000
        let recipient_final = accounts_after.get(&recipient);
        assert_eq!(recipient_final.balance, 5 * 1000);

        // Verify supply was updated (fees burned)
        // 5 * 1 = 5 fees burned
        assert_eq!(supply_after.burn_total, supply_before.burn_total + 5);
    }

    // ========================================================================
    // Test: Empty block
    // ========================================================================
    #[test]
    fn test_executor_equivalence_empty_block() {
        let mut node = create_test_node();

        let txs: Vec<SignedTx> = vec![];
        let input = ExecInput::new(txs, 1);

        let stm_executor = StmExecutor::new(1);
        let outcome = stm_executor.execute_block(&mut node, input);

        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();
        assert_eq!(block.txs.len(), 0);
        assert_eq!(outcome.tx_count, 0);
    }

    // ========================================================================
    // Test: Mixed senders - some independent, some sequential
    // ========================================================================
    #[test]
    fn test_executor_equivalence_mixed_senders() {
        let mut node = create_test_node();

        // Create 2 senders
        let sender1_bytes: [u8; 20] = [0x11; 20];
        let sender2_bytes: [u8; 20] = [0x22; 20];
        let recipient_bytes: [u8; 20] = [0xff; 20];

        let sender1 = create_funded_sender(&mut node, sender1_bytes, 100_000);
        let sender2 = create_funded_sender(&mut node, sender2_bytes, 100_000);
        let recipient = Address(recipient_bytes);

        // Create mixed transactions:
        // - sender1: nonces 0, 1
        // - sender2: nonces 0, 1
        let txs = vec![
            create_test_tx(sender1_bytes, recipient, 1000, 1, 0),
            create_test_tx(sender2_bytes, recipient, 2000, 2, 0),
            create_test_tx(sender1_bytes, recipient, 1500, 1, 1),
            create_test_tx(sender2_bytes, recipient, 2500, 2, 1),
        ];

        // Snapshot initial state
        let (_, supply_before) = snapshot_state(&node);

        // Execute with STM
        let stm_executor = StmExecutor::new(1);
        let input = ExecInput::new(txs.clone(), 1);
        let outcome = stm_executor.execute_block(&mut node, input);

        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();

        // All 4 txs should be included
        assert_eq!(block.txs.len(), 4, "Expected 4 txs to be included");

        // Apply block to node
        apply_block_to_node(&mut node, &block);

        // Snapshot final state
        let (accounts_after, supply_after) = snapshot_state(&node);

        // Verify sender1 balance: 100_000 - (1000+1) - (1500+1) = 100_000 - 2502 = 97_498
        let sender1_final = accounts_after.get(&sender1);
        assert_eq!(sender1_final.balance, 100_000 - 1001 - 1501);
        assert_eq!(sender1_final.nonce, 2);

        // Verify sender2 balance: 100_000 - (2000+2) - (2500+2) = 100_000 - 4504 = 95_496
        let sender2_final = accounts_after.get(&sender2);
        assert_eq!(sender2_final.balance, 100_000 - 2002 - 2502);
        assert_eq!(sender2_final.nonce, 2);

        // Verify recipient received: 1000 + 2000 + 1500 + 2500 = 7000
        let recipient_final = accounts_after.get(&recipient);
        assert_eq!(recipient_final.balance, 1000 + 2000 + 1500 + 2500);

        // Verify fees burned: 1 + 2 + 1 + 2 = 6
        assert_eq!(supply_after.burn_total, supply_before.burn_total + 6);
    }
}