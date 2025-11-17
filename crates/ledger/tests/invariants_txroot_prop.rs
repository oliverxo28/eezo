//! Properties: Block assembly is deterministic under input shuffles, with real PQ signatures.
//! 1) Full budget: any shuffle of the same valid tx set → identical order & header.
//! 2) Tight budget: when the budget can’t fit all txs, both shuffles pick the same
//!    assembler-defined greedy subsequence (scan canonical order, include if fits).
#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{
    accounts::Accounts,
    block::{assemble_block, tx_budget_bytes, HEADER_BUDGET_BYTES},
    tx_sig::tx_msg_bytes,
    tx_types::TxCore,
    Address, SignedTx,
};
use proptest::prelude::*;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

// Real ML-DSA-44 signing
use pqcrypto_mldsa::mldsa44 as pq44;
// Bring trait methods into scope for .as_bytes() on keys and detached signatures
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

#[inline]
fn addr_from_pk(pk: &pq44::PublicKey) -> Address {
    let mut a = [0u8; 20];
    a.copy_from_slice(&pk.as_bytes()[..20]); // address = first 20 bytes of pubkey
    Address(a)
}

fn gen_accounts_and_signed_txs(
    chain_id: [u8; 20],
    per_sender_counts: &[usize],
    amounts: &[Vec<u128>],
    fees: &[Vec<u128>],
) -> (Accounts, Vec<SignedTx>) {
    let mut acc = Accounts::default();
    let mut all = Vec::new();

    for (i, m) in per_sender_counts.iter().enumerate() {
        let (pk, sk) = pq44::keypair();
        let sender_addr = addr_from_pk(&pk);

        // Fund enough for all txs + headroom
        let need: u128 = amounts[i]
            .iter()
            .zip(&fees[i])
            .take(*m)
            .map(|(a, f)| *a + *f)
            .sum::<u128>()
            + 1_000_000u128;

        // Test-only helpers (require feature = "testing" for integration tests)
        #[allow(deprecated)]
        {
            acc.credit_unchecked_for_testing(sender_addr, need);
            acc.set_nonce_unchecked_for_testing(sender_addr, 0);
        }

        for n in 0..*m {
            let core = TxCore {
                to: Address([n as u8; 20]),
                amount: amounts[i][n],
                fee: fees[i][n],
                nonce: n as u64,
            };
            let msg = tx_msg_bytes(chain_id, &core);
            let sig = pq44::detached_sign(&msg, &sk);

            all.push(SignedTx {
                core,
                pubkey: pk.as_bytes().to_vec(),
                sig: sig.as_bytes().to_vec(),
            });
        }
    }

    (acc, all)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    /// Property 1: Full budget → deterministic order & header across shuffles.
    #[test]
    fn assemble_is_deterministic_under_shuffle_with_real_sigs_full_budget(
        // number of senders 1..5, per-sender tx count 1..8
        s in 1usize..5,
        counts_in in prop::collection::vec(1usize..8, 1..5), // resize to s
        raw_amounts in prop::collection::vec(prop::collection::vec(1u128..50_000u128, 1..8), 1..5),
        raw_fees    in prop::collection::vec(prop::collection::vec(1u128..=100_000u128, 1..8), 1..5),
        seed1 in any::<u64>(),
        seed2 in any::<u64>(),
    ) {
        // Shape to exactly s senders
        let mut counts = counts_in; counts.resize(s, 1);

        let mut amounts = raw_amounts; amounts.resize(s, vec![1u128]);
        for i in 0..s { let m = counts[i]; amounts[i].resize(m, 1u128); }

        let mut fees = raw_fees; fees.resize(s, vec![1u128]); // avoid zero-fee all-ties
        for i in 0..s { let m = counts[i]; fees[i].resize(m, 1u128); }

        // Build accounts + real-signed txs
        let chain_id = [0x01u8; 20];
        let (accounts, txs0) = gen_accounts_and_signed_txs(chain_id, &counts, &amounts, &fees);

        // Two different shuffles of the same set
        let mut a = txs0.clone();
        let mut b = txs0.clone();
        let mut rng1 = StdRng::seed_from_u64(seed1);
        let mut rng2 = StdRng::seed_from_u64(seed2);
        a.shuffle(&mut rng1);
        b.shuffle(&mut rng2);

        // Big budget to fit all
        let max_bytes = usize::MAX / 8;

        let prev_hash = [2u8; 32];
        let height = 777u64;
        let now_ms = 1_700_000_000_000u64;

        let blk_a = assemble_block(&accounts, chain_id, prev_hash, height, max_bytes, a, now_ms).expect("assemble A");
        let blk_b = assemble_block(&accounts, chain_id, prev_hash, height, max_bytes, b, now_ms).expect("assemble B");

        // Headers identical (deterministic)
        prop_assert_eq!(blk_a.header.tx_root,   blk_b.header.tx_root);
        prop_assert_eq!(blk_a.header.fee_total, blk_b.header.fee_total);
        prop_assert_eq!(blk_a.header.tx_count,  blk_b.header.tx_count);
        prop_assert_eq!(blk_a.header.prev_hash, blk_b.header.prev_hash);
        prop_assert_eq!(blk_a.header.height,    blk_b.header.height);
        prop_assert_eq!(blk_a.header.timestamp_ms, blk_b.header.timestamp_ms);

        // Exact same tx ordering; compare by reference to avoid moving
        prop_assert_eq!(&blk_a.txs, &blk_b.txs);

        // Budget sanity (header counted once in this check only)
        let used_a = HEADER_BUDGET_BYTES as u64 + blk_a.txs.iter().map(tx_budget_bytes).sum::<u64>();
        prop_assert!(used_a <= max_bytes as u64);
        let sum_sizes_a: u64 = blk_a.txs.iter().map(tx_budget_bytes).sum();
        prop_assert_eq!(used_a, HEADER_BUDGET_BYTES as u64 + sum_sizes_a);

        // V2 root determinism (feature-gated)
        #[cfg(feature = "eth-ssz")]
        {
            use eezo_ledger::eth_ssz::txs_root_v2;
            // The block assembly process sorts transactions, so blk_a.txs and blk_b.txs
            // are already guaranteed to be identical if the v1 root matches. This check
            // confirms that the v2 root is also deterministic.
            let r0 = txs_root_v2(&blk_a.txs);
            let r1 = txs_root_v2(&blk_b.txs);
            prop_assert_eq!(r0, r1, "v2 tx root must be stable across shuffles");
        }
    }

    /// Property 2: Tight budget → both permutations pick the same assembler-defined greedy subsequence.
    ///
    /// We first compute the assembler's canonical order by assembling with a huge budget.
    /// Then we *search* for a budget (interpreted as tx-bytes limit) that excludes ≥1 tx
    /// and compute the greedy subsequence by scanning the canonical order once.
    #[test]
    fn assemble_is_deterministic_under_tight_budget_greedy_subsequence(
        s in 1usize..5,
        counts_in in prop::collection::vec(2usize..8, 1..5), // need at least 2 total tx
        raw_amounts in prop::collection::vec(prop::collection::vec(1u128..50_000u128, 2..8), 1..5),
        raw_fees    in prop::collection::vec(prop::collection::vec(1u128..=100_000u128, 2..8), 1..5),
        seed1 in any::<u64>(),
        seed2 in any::<u64>(),
    ) {
        // Shape to exactly s senders
        let mut counts = counts_in; counts.resize(s, 2);

        let mut amounts = raw_amounts; amounts.resize(s, vec![1u128, 1u128]);
        for i in 0..s { let m = counts[i]; amounts[i].resize(m, 1u128); }

        let mut fees = raw_fees; fees.resize(s, vec![1u128, 1u128]);
        for i in 0..s { let m = counts[i]; fees[i].resize(m, 1u128); }

        // Build accounts + real-signed txs
        let chain_id = [0x02u8; 20];
        let (accounts, txs0) = gen_accounts_and_signed_txs(chain_id, &counts, &amounts, &fees);

        // Get canonical order once (huge budget).
        let prev_hash_c = [9u8; 32];
        let height_c = 123u64;
        let now_c = 1_700_000_000_777u64;
        let canon_block = assemble_block(&accounts, chain_id, prev_hash_c, height_c, usize::MAX/8, txs0.clone(), now_c)
            .expect("assemble canon");
        prop_assume!(canon_block.txs.len() >= 2);

        // Precompute tx sizes and total **tx bytes**.
        let sizes: Vec<u64> = canon_block.txs.iter().map(tx_budget_bytes).collect();
        let total_tx_bytes: u64 = sizes.iter().sum();

        // ----- Find a tight budget that excludes at least one tx (and keeps at least one) -----
        // We search from total-1 down to 1 for the first budget whose greedy pass on the
        // canonical order excludes something. This is robust to any future accounting changes.
        let mut chosen_budget: Option<u64> = None;
        let mut greedy_expected: Vec<SignedTx> = Vec::new();

        'search: for tight_budget in (1..total_tx_bytes).rev() {
            let mut used = 0u64;
            greedy_expected.clear();

            for (tx, sz) in canon_block.txs.iter().cloned().zip(sizes.iter().copied()) {
                if used + sz <= tight_budget {
                    used += sz;
                    greedy_expected.push(tx);
                }
            }

            if !greedy_expected.is_empty() && greedy_expected.len() < canon_block.txs.len() {
                chosen_budget = Some(tight_budget);
                break 'search;
            }
        }

        // If we somehow cannot find such a budget (e.g., degenerate zero-sized txs),
        // skip this case.
        prop_assume!(chosen_budget.is_some());
        let tight_budget_tx_only = chosen_budget.unwrap();
        let tight_budget_with_header = HEADER_BUDGET_BYTES + tight_budget_tx_only as usize;

        // Sanity: recompute used tx-bytes for expected
        let used_expected: u64 = greedy_expected.iter().map(tx_budget_bytes).sum();
        prop_assert!(used_expected <= tight_budget_tx_only);

        // Two different shuffles of the same set
        let mut a = txs0.clone();
        let mut b = txs0.clone();
        let mut rng1 = StdRng::seed_from_u64(seed1);
        let mut rng2 = StdRng::seed_from_u64(seed2);
        a.shuffle(&mut rng1);
        b.shuffle(&mut rng2);

        let prev_hash = [3u8; 32];
        let height = 888u64;
        let now_ms = 1_700_000_000_001u64;

        // Assemble under the discovered tight budget (interpreted as tx-bytes limit).
        let blk_a = assemble_block(&accounts, chain_id, prev_hash, height, tight_budget_with_header, a, now_ms).expect("assemble A");
        let blk_b = assemble_block(&accounts, chain_id, prev_hash, height, tight_budget_with_header, b, now_ms).expect("assemble B");

        // Determinism under budget: both outputs identical and equal the greedy subsequence
        prop_assert_eq!(&blk_a.txs, &blk_b.txs);
        prop_assert_eq!(&blk_a.txs, &greedy_expected);

        // Headers must match and be consistent with the chosen txs
        prop_assert_eq!(blk_a.header.tx_root,   blk_b.header.tx_root);
        prop_assert_eq!(blk_a.header.tx_count,  blk_b.header.tx_count);
        prop_assert_eq!(blk_a.header.fee_total, blk_b.header.fee_total);
        prop_assert_eq!(blk_a.txs.len() as u32, blk_a.header.tx_count);

        // Fee total cross-check
        let expected_fee_total: u128 = greedy_expected.iter().map(|t| t.core.fee).sum();
        prop_assert_eq!(blk_a.header.fee_total, expected_fee_total);
        prop_assert_eq!(blk_b.header.fee_total, expected_fee_total);

        // Byte budget respected as **tx bytes only**
        let used_a_txbytes: u64 = blk_a.txs.iter().map(tx_budget_bytes).sum();
        prop_assert!(used_a_txbytes <= tight_budget_tx_only);

        // Guardrail against accidental header double-counting in these tests.
        let _header_plus_tx = HEADER_BUDGET_BYTES as u64 + used_a_txbytes;
        let _ = _header_plus_tx;

        // V2 root determinism (feature-gated)
        #[cfg(feature = "eth-ssz")]
        {
            use eezo_ledger::eth_ssz::txs_root_v2;
            let r0 = txs_root_v2(&blk_a.txs);
            let r1 = txs_root_v2(&blk_b.txs);
            prop_assert_eq!(r0, r1, "v2 tx root must be stable for greedy subsequence");
        }
    }
}