//! Property: No gap/replay per sender under random bags of txs.
//! For each sender, the assembled block must include a consecutive
//! nonce prefix starting at the account's current nonce (0 in these tests),
//! with strictly increasing nonces and no duplicates.
//!
//! We deliberately generate "bags" containing duplicates and gaps,
//! then assert the assembler only picks a valid prefix per sender.
#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{
    accounts::Accounts,
    block::assemble_block,
    tx_sig::tx_msg_bytes,
    tx_types::TxCore,
    Address, SignedTx,
};
use proptest::prelude::*;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

// Real ML-DSA-44 signing
use pqcrypto_mldsa::mldsa44 as pq44;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

#[inline]
fn addr_from_pk(pk: &pq44::PublicKey) -> Address {
    let mut a = [0u8; 20];
    a.copy_from_slice(&pk.as_bytes()[..20]); // address = first 20 bytes of pubkey
    Address(a)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    /// Random-bag nonce integrity:
    /// - Multiple senders (1..5)
    /// - For each sender, target contiguous nonce span size m in 1..8
    /// - We build a "bag" of txs by sampling nonces from 0..m+3 with duplicates and gaps,
    ///   and random fees/amounts. Then we shuffle the union across senders.
    /// The assembled block (huge budget) must include, for each sender, a **consecutive prefix**
    /// of nonces starting at 0 with no duplicates/gaps.
    #[test]
    fn nonce_integrity_no_gap_no_replay_under_random_bags(
        s in 1usize..5,                                   // senders
        m_in in prop::collection::vec(1usize..8, 1..5),   // target spans per sender (will resize to s)
        seed_shuffle in any::<u64>(),
        // fees/amounts are small but positive to avoid zero-fee/ties weirdness
        raw_amounts in prop::collection::vec(prop::collection::vec(1u128..50_000u128, 1..16), 1..5),
        raw_fees    in prop::collection::vec(prop::collection::vec(1u128..=100_000u128, 1..16), 1..5),
    ) {
        // Normalize lengths to exactly s senders
        let mut spans = m_in; spans.resize(s, 1);

        // We will create a bag per sender of length between m..(2m+3)
        // Nonces sampled from 0..(m+3), with duplicates allowed.
        // Also prepare per-sender amounts/fees pools (we'll pull as needed).
        let mut amounts_pool = raw_amounts; amounts_pool.resize(s, vec![1u128]);
        let mut fees_pool    = raw_fees;    fees_pool.resize(s, vec![1u128]);

        // Build accounts and signed bags
        let chain_id = [0xA5u8; 20];
        let mut accounts = Accounts::default();
        let mut all_txs: Vec<SignedTx> = Vec::new();

        for i in 0..s {
            let m = spans[i];
            // generous bag length
            let bag_len = m + (m % 3 + 3); // in [m+3 .. m+5] mildly variable
            // ensure pools big enough
            let need_pool = bag_len.max(1);
            amounts_pool[i].resize(need_pool, 1u128);
            fees_pool[i].resize(need_pool, 1u128);

            // keypair & fund heavily so funds never constrain acceptance
            let (pk, sk) = pq44::keypair();
            let sender_addr = addr_from_pk(&pk);

            // Fund plenty (covers any prefix up to m and then some)
            #[allow(deprecated)]
            {
                accounts.credit_unchecked_for_testing(sender_addr, 1_000_000_000_000u128);
                accounts.set_nonce_unchecked_for_testing(sender_addr, 0);
            }

            // Build a random bag of nonces in 0..(m+3), with duplicates
            // We rely on proptest randomness for fee/amount variety; amounts/fees are aligned by index.
            let mut nonces: Vec<u64> = Vec::with_capacity(bag_len);
            for k in 0..bag_len {
                // spread: pick in 0..(m+3)
                let v = ((k * 37 + i * 11) % (m + 3)) as u64;
                nonces.push(v);
            }

            for (idx, &nonce) in nonces.iter().enumerate().take(bag_len) {
                let core = TxCore {
                    to: Address([nonce as u8; 20]),
                    amount: amounts_pool[i][idx % amounts_pool[i].len()],
                    fee:    fees_pool[i][idx % fees_pool[i].len()],
                    nonce,
                };
                let msg = tx_msg_bytes(chain_id, &core);
                let sig = pq44::detached_sign(&msg, &sk);
                all_txs.push(SignedTx {
                    core,
                    pubkey: pk.as_bytes().to_vec(),
                    sig: sig.as_bytes().to_vec(),
                });
            }
        }

        // Shuffle the union across all senders (adversarial interleaving)
        let mut rng = StdRng::seed_from_u64(seed_shuffle);
        all_txs.shuffle(&mut rng);

        // Assemble with a huge budget to remove budget as a factor;
        // the assembler must enforce per-sender nonce discipline via stateful rules.
        let prev_hash = [0x42u8; 32];
        let height = 4242u64;
        let now_ms = 1_700_123_456_789u64;
        let max_bytes = usize::MAX / 8;

        let blk = assemble_block(&accounts, chain_id, prev_hash, height, max_bytes, all_txs, now_ms)
            .expect("assemble");

        // Skip degenerate cases where nothing was included.
        prop_assume!(!blk.txs.is_empty());

        // --- Assertions: For each sender, included nonces form a consecutive prefix starting at 0
        use std::collections::BTreeMap;
        let mut by_sender: BTreeMap<Address, Vec<u64>> = BTreeMap::new();
        for tx in &blk.txs {
            // Resolve sender; if it doesn't resolve, the assembler wouldn't have accepted it
            if let Some(s) = eezo_ledger::sender_from_pubkey_first20(tx) {
                by_sender.entry(s).or_default().push(tx.core.nonce);
            }
        }

        for (_sender, ns) in by_sender {
            // Check for duplicates (belt-and-suspenders, already implied by strict increase check)
            let mut sorted_ns = ns.clone();
            sorted_ns.sort_unstable();
            let original_len = sorted_ns.len();
            sorted_ns.dedup();
            prop_assert_eq!(sorted_ns.len(), original_len, "duplicate nonces found for sender");

            // nonces in the block for a sender must be strictly increasing (assembler processes canonical order + state)
            let mut prev: Option<u64> = None;
            for n in &ns {
                if let Some(p) = prev {
                    prop_assert!(n > &p, "nonces must be strictly increasing within a sender ({} > {})", n, p);
                }
                prev = Some(*n);
            }

            // and they must start at 0 and be a *consecutive prefix*: 0,1,2,...,k
            if !ns.is_empty() {
                // check start
                prop_assert_eq!(ns[0], 0, "first nonce for a sender must be 0");
                // check gaps
                for (i, &n) in ns.iter().enumerate() {
                    prop_assert_eq!(n, i as u64, "gap detected: expected {}, got {}", i, n);
                }
            }
        }
    }
}