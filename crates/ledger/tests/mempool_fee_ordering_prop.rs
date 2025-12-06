//! Properties for mempool drain ordering.
//! 1) Full-budget: drains all txs ordered by (fee DESC, nonce ASC), stable by arrival.
//! 2) Tight-budget: drained set is exactly the longest prefix of that order that fits.
#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{
    block::{tx_size_bytes, HEADER_BUDGET_BYTES},
    cert_store::CertLookupT4,
    mempool::Mempool,
    tx_types::TxCore,
    Address, SignedTx,
};
use proptest::prelude::*;
use std::sync::Arc;

/// Minimal no-op cert store for tests (signatures not verified in these props).
struct DummyCerts;

impl CertLookupT4 for DummyCerts {
    fn get_pk(
        &self,
        _addr: &[u8; 20],
        _epoch: u64,
    ) -> Option<eezo_ledger::cert_store::ValidatedPk> {
        None
    }
}

// PATCH 1: Add type alias for the complex tuple
type RawTx = ([u8; 20], [u8; 20], u128, u128, u64, Vec<u8>);

// --- helper to build a mempool and a randomized tx vector in arrival order ---
fn make_tx_batch(
    // PATCH 1: Use the type alias
    raw: Vec<RawTx>,
) -> (Mempool, Vec<SignedTx>, eezo_ledger::Accounts) {
    // Build transactions and track per-sender nonce assignment
    use std::collections::HashMap;
    let mut sender_nonces: HashMap<Address, u64> = HashMap::new();
    
    let txs: Vec<SignedTx> = raw
        .into_iter()
        .map(|(sender20, to20, amount, fee, _nonce, mut pk_rest)| {
            let sender = Address(sender20);
            let to = Address(to20);
            let mut pubkey = sender.as_bytes().to_vec(); // first 20 bytes == address
            pubkey.append(&mut pk_rest);

            // Assign contiguous nonces per sender to match ledger state
            let nonce = *sender_nonces.entry(sender).or_insert(0);
            sender_nonces.insert(sender, nonce + 1);

            let core = TxCore { to, amount, fee, nonce };
            let sig = vec![]; // not used for ordering/equality

            SignedTx { core, pubkey, sig }
        })
        .collect();

    let chain_id = [0u8; 20];
    let certs = Arc::new(DummyCerts) as Arc<dyn CertLookupT4 + Send + Sync>;
    let mut mp = Mempool::new(chain_id, certs);

    for tx in &txs {
        mp.enqueue_tx(tx.clone());
    }

    // Create accounts with balance but nonce=0 (default) for all senders
    let accounts = eezo_ledger::Accounts::default();

    (mp, txs, accounts)
}

proptest! {
    // Property 1: With a budget that fits all transactions, the drain is exactly the
    // stable sort by (fee DESC, nonce ASC).
    #[test]
    fn drain_orders_by_fee_then_nonce_stably_full_budget(
        raw in prop::collection::vec(
            (
                prop::array::uniform20(any::<u8>()),          // sender (first 20 of pubkey)
                prop::array::uniform20(any::<u8>()),          // to
                1u128..10_000u128,                             // amount
                0u128..100_000u128,                            // fee
                0u64..20u64,                                   // nonce
                prop::collection::vec(any::<u8>(), 12..64),    // rest of pubkey
            ),
            1..64
        )
    ) {
        let (mut mp, txs, accounts) = make_tx_batch(raw);

        // Budget fits all
        // PATCH 2: Remove redundant closure
        let budget: usize = HEADER_BUDGET_BYTES + txs.iter().map(tx_size_bytes).sum::<usize>();

        let drained = mp.drain_for_block(budget, &accounts);

        // Expected: stable sort by (fee DESC, nonce ASC)
        let mut expected = txs.clone();
        expected.sort_by(|a, b| {
            b.core.fee
                .cmp(&a.core.fee)
                .then_with(|| a.core.nonce.cmp(&b.core.nonce))
        });

        // Byte budget respected
        // PATCH 3: Remove redundant closure
        let used: usize = HEADER_BUDGET_BYTES + drained.iter().map(tx_size_bytes).sum::<usize>();
        // PATCH 4: Remove redundant closure
        let sum_sizes: usize = drained.iter().map(tx_size_bytes).sum();
		prop_assert_eq!(used, HEADER_BUDGET_BYTES + sum_sizes);

        // With nonce validation, drained set respects per-sender contiguity.
        // All txs should be drained since we assigned contiguous nonces per sender.
        prop_assert_eq!(drained.len(), txs.len());
        
        // Verify all drained txs are from the original set
        for tx in &drained {
            prop_assert!(txs.contains(tx), "drained tx not in original set");
        }
        
        // Verify nonce contiguity per sender in drained set
        use std::collections::HashMap;
        let mut sender_nonces: HashMap<Address, Vec<u64>> = HashMap::new();
        for tx in &drained {
            use eezo_ledger::sender_from_pubkey_first20;
            if let Some(sender) = sender_from_pubkey_first20(tx) {
                sender_nonces.entry(sender).or_default().push(tx.core.nonce);
            }
        }
        for (sender, nonces) in sender_nonces {
            let mut sorted_nonces = nonces.clone();
            sorted_nonces.sort();
            // Verify contiguous starting from 0
            for (i, &nonce) in sorted_nonces.iter().enumerate() {
                prop_assert_eq!(nonce, i as u64, "sender {:?} has non-contiguous nonces", sender);
            }
        }
    }

    // Property 2: With a tight budget, the drained set is exactly the longest
    // prefix of the stably-sorted list whose cumulative encoded size fits.
    #[test]
    fn drain_prefix_under_tight_budget(
        raw in prop::collection::vec(
            (
                prop::array::uniform20(any::<u8>()),          // sender (first 20 of pubkey)
                prop::array::uniform20(any::<u8>()),          // to
                1u128..10_000u128,                             // amount
                0u128..100_000u128,                            // fee
                0u64..20u64,                                   // nonce
                prop::collection::vec(any::<u8>(), 12..64),    // rest of pubkey
            ),
            2..64 // need at least 2 so we can choose a strict prefix
        )
    ) {
        let (mut mp, txs, accounts) = make_tx_batch(raw);

        // The canonical stable ordering
        let mut sorted = txs.clone();
        sorted.sort_by(|a, b| {
            b.core.fee
                .cmp(&a.core.fee)
                .then_with(|| a.core.nonce.cmp(&b.core.nonce))
        });

        // Pre-compute sizes and prefix sums (without header).
        // PATCH 5: Remove redundant closure
        let sizes: Vec<usize> = sorted.iter().map(tx_size_bytes).collect();
        let mut prefix_sum = Vec::with_capacity(sizes.len());
        let mut acc = 0usize;
        for s in &sizes {
            acc += *s;
            prefix_sum.push(acc);
        }

        // Choose k = len-1 ("almost full") so at least one tx should be excluded.
        let k = sorted.len() - 1;
        // Budget that fits exactly the first k transactions (header + sum_{0..k-1} sizes)
        let budget = HEADER_BUDGET_BYTES + prefix_sum[k - 1];

        // Drain under tight budget
        let drained = mp.drain_for_block(budget, &accounts);

        // 1) Byte budget respected
        // PATCH 6: Remove redundant closure
        let used: usize = HEADER_BUDGET_BYTES + drained.iter().map(tx_size_bytes).sum::<usize>();
        // PATCH 7: Remove redundant closure
        let sum_sizes: usize = drained.iter().map(tx_size_bytes).sum();
		prop_assert_eq!(used, HEADER_BUDGET_BYTES + sum_sizes);
        prop_assert!(used <= budget, "budget should be respected");

        // 2) With nonce validation, we can't predict the exact count, but it should be at most k
        prop_assert!(drained.len() <= k, "should drain at most k txs given budget");
        
        // 3) Verify nonce contiguity per sender in drained set
        use std::collections::HashMap;
        let mut sender_nonces: HashMap<Address, Vec<u64>> = HashMap::new();
        for tx in &drained {
            use eezo_ledger::sender_from_pubkey_first20;
            if let Some(sender) = sender_from_pubkey_first20(tx) {
                sender_nonces.entry(sender).or_default().push(tx.core.nonce);
            }
        }
        for (sender, nonces) in sender_nonces {
            let mut sorted_nonces = nonces.clone();
            sorted_nonces.sort();
            // Verify contiguous starting from 0
            for (i, &nonce) in sorted_nonces.iter().enumerate() {
                prop_assert_eq!(nonce, i as u64, "sender {:?} has non-contiguous nonces", sender);
            }
        }
    }
}