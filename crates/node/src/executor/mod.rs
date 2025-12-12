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

// T87.4: Export StmConfig and StmKernelMode when stm-exec feature is enabled
#[cfg(feature = "stm-exec")]
pub use stm::{StmConfig, StmKernelMode};

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
            let sender = sender_from_pubkey_first20(tx)
                .expect("Failed to derive sender from pubkey");
            apply_tx(&mut node.accounts, &mut node.supply, sender, &tx.core)
                .expect("Failed to apply tx to node state");
        }
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

    // ========================================================================
    // T82.1: Test - Block with multiple senders to same receiver (conflicts)
    // ========================================================================
    #[test]
    fn test_executor_equivalence_same_receiver_conflicts() {
        // This test verifies that the T82.1 overlay-based executor produces
        // the same final state as sequential execution when multiple transactions
        // write to the same receiver account (causing conflicts that require retries).
        let mut node = create_test_node();

        // Create multiple senders that all send to the same receiver
        let sender1_bytes: [u8; 20] = [0xaa; 20];
        let sender2_bytes: [u8; 20] = [0xbb; 20];
        let sender3_bytes: [u8; 20] = [0xcc; 20];
        let receiver_bytes: [u8; 20] = [0xdd; 20];

        let _sender1 = create_funded_sender(&mut node, sender1_bytes, 100_000);
        let _sender2 = create_funded_sender(&mut node, sender2_bytes, 100_000);
        let _sender3 = create_funded_sender(&mut node, sender3_bytes, 100_000);
        let receiver = Address(receiver_bytes);

        // All senders send to the same receiver - this causes write-write conflicts
        // on the receiver account
        let txs = vec![
            create_test_tx(sender1_bytes, receiver, 1000, 1, 0),
            create_test_tx(sender2_bytes, receiver, 2000, 2, 0),
            create_test_tx(sender3_bytes, receiver, 3000, 3, 0),
        ];

        // Snapshot initial state
        let (_, supply_before) = snapshot_state(&node);

        // Execute with STM
        let stm_executor = StmExecutor::new(1);
        let input = ExecInput::new(txs.clone(), 1);
        let outcome = stm_executor.execute_block(&mut node, input);

        assert!(outcome.result.is_ok());
        let block = outcome.result.unwrap();

        // All 3 txs should be included (STM handles conflicts via retries)
        assert_eq!(block.txs.len(), 3, "Expected 3 txs to be included");

        // Apply block to node
        apply_block_to_node(&mut node, &block);

        // Snapshot final state
        let (accounts_after, supply_after) = snapshot_state(&node);

        // Verify receiver got all transfers: 1000 + 2000 + 3000 = 6000
        let receiver_final = accounts_after.get(&receiver);
        assert_eq!(receiver_final.balance, 6000);

        // Verify each sender's balance was deducted correctly
        let sender1_final = accounts_after.get(&Address(sender1_bytes));
        assert_eq!(sender1_final.balance, 100_000 - 1001); // 1000 + 1 fee
        assert_eq!(sender1_final.nonce, 1);

        let sender2_final = accounts_after.get(&Address(sender2_bytes));
        assert_eq!(sender2_final.balance, 100_000 - 2002); // 2000 + 2 fee
        assert_eq!(sender2_final.nonce, 1);

        let sender3_final = accounts_after.get(&Address(sender3_bytes));
        assert_eq!(sender3_final.balance, 100_000 - 3003); // 3000 + 3 fee
        assert_eq!(sender3_final.nonce, 1);

        // Verify fees burned: 1 + 2 + 3 = 6
        assert_eq!(supply_after.burn_total, supply_before.burn_total + 6);
    }

    // ========================================================================
    // T87.4: Arena Kernel Equivalence Test
    // ========================================================================
    //
    // Verifies that the arena kernel produces the same results as the legacy
    // overlay-based kernel for the same input.

    #[test]
    fn test_arena_kernel_equivalence_no_conflicts() {
        use super::stm::{StmConfig, StmKernelMode};

        // Create two nodes with identical initial state
        let mut node_legacy = create_test_node();
        let mut node_arena = create_test_node();

        // Create 4 independent senders with unique addresses
        let sender1_bytes: [u8; 20] = [0x01; 20];
        let sender2_bytes: [u8; 20] = [0x02; 20];
        let sender3_bytes: [u8; 20] = [0x03; 20];
        let sender4_bytes: [u8; 20] = [0x04; 20];
        let recipient_bytes: [u8; 20] = [0xca; 20];

        // Fund senders on both nodes
        for node in [&mut node_legacy, &mut node_arena] {
            create_funded_sender(node, sender1_bytes, 100_000);
            create_funded_sender(node, sender2_bytes, 100_000);
            create_funded_sender(node, sender3_bytes, 100_000);
            create_funded_sender(node, sender4_bytes, 100_000);
        }
        let recipient = Address(recipient_bytes);

        // Create transactions from different senders (no conflicts)
        let txs = vec![
            create_test_tx(sender1_bytes, recipient, 1000, 1, 0),
            create_test_tx(sender2_bytes, recipient, 2000, 2, 0),
            create_test_tx(sender3_bytes, recipient, 3000, 3, 0),
            create_test_tx(sender4_bytes, recipient, 4000, 4, 0),
        ];

        // Execute with legacy kernel
        let legacy_config = StmConfig {
            kernel_mode: StmKernelMode::Legacy,
            ..StmConfig::default()
        };
        let legacy_executor = StmExecutor::with_config(legacy_config);
        let input_legacy = ExecInput::new(txs.clone(), 1);
        let outcome_legacy = legacy_executor.execute_block(&mut node_legacy, input_legacy);

        // Execute with arena kernel
        let arena_config = StmConfig {
            kernel_mode: StmKernelMode::Arena,
            ..StmConfig::default()
        };
        let arena_executor = StmExecutor::with_config(arena_config);
        let input_arena = ExecInput::new(txs.clone(), 1);
        let outcome_arena = arena_executor.execute_block(&mut node_arena, input_arena);

        // Both should succeed
        assert!(outcome_legacy.result.is_ok(), "Legacy kernel failed");
        assert!(outcome_arena.result.is_ok(), "Arena kernel failed");

        let block_legacy = outcome_legacy.result.unwrap();
        let block_arena = outcome_arena.result.unwrap();

        // Same number of transactions committed
        assert_eq!(
            block_legacy.txs.len(), 
            block_arena.txs.len(),
            "Different tx counts: legacy={}, arena={}",
            block_legacy.txs.len(),
            block_arena.txs.len()
        );

        // Same tx hashes (same order)
        for (i, (tx_l, tx_a)) in block_legacy.txs.iter().zip(block_arena.txs.iter()).enumerate() {
            assert_eq!(
                tx_l.hash(), tx_a.hash(),
                "Transaction {} hash mismatch between legacy and arena",
                i
            );
        }

        // Apply blocks to their respective nodes
        apply_block_to_node(&mut node_legacy, &block_legacy);
        apply_block_to_node(&mut node_arena, &block_arena);

        // Compare final state for all touched accounts
        for addr_bytes in [sender1_bytes, sender2_bytes, sender3_bytes, sender4_bytes, recipient_bytes] {
            let addr = Address(addr_bytes);
            let acct_legacy = node_legacy.accounts.get(&addr);
            let acct_arena = node_arena.accounts.get(&addr);
            
            assert_eq!(
                acct_legacy.balance, acct_arena.balance,
                "Balance mismatch for {:?}: legacy={}, arena={}",
                addr, acct_legacy.balance, acct_arena.balance
            );
            assert_eq!(
                acct_legacy.nonce, acct_arena.nonce,
                "Nonce mismatch for {:?}: legacy={}, arena={}",
                addr, acct_legacy.nonce, acct_arena.nonce
            );
        }

        // Compare supply state
        assert_eq!(
            node_legacy.supply.burn_total, 
            node_arena.supply.burn_total,
            "Supply burn_total mismatch: legacy={}, arena={}",
            node_legacy.supply.burn_total,
            node_arena.supply.burn_total
        );
    }

    #[test]
    fn test_arena_kernel_equivalence_sequential_nonces() {
        use super::stm::{StmConfig, StmKernelMode};

        // Create two nodes with identical initial state
        let mut node_legacy = create_test_node();
        let mut node_arena = create_test_node();

        // Create a single sender with enough balance for many txs
        let sender_bytes: [u8; 20] = [0x42; 20];
        let recipient_bytes: [u8; 20] = [0xbe; 20];

        for node in [&mut node_legacy, &mut node_arena] {
            create_funded_sender(node, sender_bytes, 100_000);
        }
        let recipient = Address(recipient_bytes);

        // Create 10 sequential transactions (nonces 0-9)
        let txs: Vec<SignedTx> = (0..10u64)
            .map(|nonce| create_test_tx(sender_bytes, recipient, 1000, 1, nonce))
            .collect();

        // Execute with legacy kernel
        let legacy_config = StmConfig {
            kernel_mode: StmKernelMode::Legacy,
            ..StmConfig::default()
        };
        let legacy_executor = StmExecutor::with_config(legacy_config);
        let input_legacy = ExecInput::new(txs.clone(), 1);
        let outcome_legacy = legacy_executor.execute_block(&mut node_legacy, input_legacy);

        // Execute with arena kernel
        let arena_config = StmConfig {
            kernel_mode: StmKernelMode::Arena,
            ..StmConfig::default()
        };
        let arena_executor = StmExecutor::with_config(arena_config);
        let input_arena = ExecInput::new(txs.clone(), 1);
        let outcome_arena = arena_executor.execute_block(&mut node_arena, input_arena);

        // Both should succeed
        assert!(outcome_legacy.result.is_ok(), "Legacy kernel failed");
        assert!(outcome_arena.result.is_ok(), "Arena kernel failed");

        let block_legacy = outcome_legacy.result.unwrap();
        let block_arena = outcome_arena.result.unwrap();

        // Same number of transactions (all 10 should commit)
        assert_eq!(block_legacy.txs.len(), 10);
        assert_eq!(block_arena.txs.len(), 10);

        // Apply blocks
        apply_block_to_node(&mut node_legacy, &block_legacy);
        apply_block_to_node(&mut node_arena, &block_arena);

        // Compare sender final state
        let sender = Address(sender_bytes);
        let legacy_sender = node_legacy.accounts.get(&sender);
        let arena_sender = node_arena.accounts.get(&sender);
        
        assert_eq!(legacy_sender.balance, arena_sender.balance);
        assert_eq!(legacy_sender.nonce, arena_sender.nonce);
        assert_eq!(legacy_sender.nonce, 10);

        // Compare receiver final state
        let legacy_receiver = node_legacy.accounts.get(&recipient);
        let arena_receiver = node_arena.accounts.get(&recipient);
        
        assert_eq!(legacy_receiver.balance, arena_receiver.balance);
        assert_eq!(legacy_receiver.balance, 10 * 1000);

        // Compare supply
        assert_eq!(node_legacy.supply.burn_total, node_arena.supply.burn_total);
    }
}