use eezo_ledger::{
    block::{assemble_block, tx_budget_bytes, txs_root, HEADER_BUDGET_BYTES},
    sender_from_pubkey_first20,
    tx_types::tx_domain_bytes,
    Address, Accounts, SignedTx, TxCore,
};
#[cfg(feature = "pq44-runtime")]
use pqcrypto_mldsa::mldsa44::{detached_sign, keypair};
#[cfg(feature = "pq44-runtime")]
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use proptest::prelude::*;
use rand::{seq::SliceRandom, thread_rng};
use std::convert::TryFrom;

#[cfg(feature = "pq44-runtime")]
fn sign_with_pk_sk(
    chain_id: [u8; 20],
    core: TxCore,
    pk: &pqcrypto_mldsa::mldsa44::PublicKey,
    sk: &pqcrypto_mldsa::mldsa44::SecretKey,
) -> SignedTx {
    let msg = tx_domain_bytes(chain_id, &core);
    let sig = detached_sign(&msg, sk);
    SignedTx {
        core,
        pubkey: pk.as_bytes().to_vec(),
        sig: sig.as_bytes().to_vec(),
    }
}

#[cfg(feature = "pq44-runtime")]
fn sign_tx(chain_id: [u8; 20], core: TxCore) -> SignedTx {
    let (pk, sk) = keypair();
    let msg = tx_domain_bytes(chain_id, &core);
    let sig = detached_sign(&msg, &sk);
    SignedTx {
        core,
        pubkey: pk.as_bytes().to_vec(),
        sig: sig.as_bytes().to_vec(),
    }
}

#[test]
#[cfg(feature = "pq44-runtime")]
fn block_assembly_deterministic_and_fee_ordered() {
    let mut accounts = Accounts::default();
    let chain_id = [0x11u8; 20];
    let prev = [0x33u8; 32];

    // Three different signers
    let (pk1, sk1) = keypair();
    let (pk2, sk2) = keypair();
    let (pk3, sk3) = keypair();

    let t1 = sign_with_pk_sk(
        chain_id,
        TxCore {
            to: Address::from_bytes([1; 20]),
            amount: 10,
            fee: 1000,
            nonce: 0,
        },
        &pk1,
        &sk1,
    );
    let t2 = sign_with_pk_sk(
        chain_id,
        TxCore {
            to: Address::from_bytes([2; 20]),
            amount: 10,
            fee: 500,
            nonce: 0,
        },
        &pk2,
        &sk2,
    );
    let t3 = sign_with_pk_sk(
        chain_id,
        TxCore {
            to: Address::from_bytes([3; 20]),
            amount: 10,
            fee: 1500,
            nonce: 0,
        },
        &pk3,
        &sk3,
    );

    // FUND each sender sufficiently
    let a1 = sender_from_pubkey_first20(&t1).expect("sender a1");
    let a2 = sender_from_pubkey_first20(&t2).expect("sender a2");
    let a3 = sender_from_pubkey_first20(&t3).expect("sender a3");
    accounts.credit(a1, 1_000_000);
    accounts.credit(a2, 1_000_000);
    accounts.credit(a3, 1_000_000);

    let cands = vec![t1, t2, t3];
    let blk1 = assemble_block(&accounts, chain_id, prev, 42, 1_000_000, cands.clone(), 123456)
        .unwrap();

    // Shuffle and reassemble: should be deterministic and fee-ordered (desc)
    let mut cands2 = cands.clone();
    cands2.shuffle(&mut thread_rng());
    let blk2 = assemble_block(&accounts, chain_id, prev, 42, 1_000_000, cands2, 123456).unwrap();

    assert_eq!(
        blk1.header.tx_root,
        blk2.header.tx_root,
        "deterministic tx_root"
    );
    assert_eq!(blk1.txs.len(), 3, "all funded → all included");
    assert!(blk1.txs[0].core.fee >= blk1.txs[1].core.fee);
    assert!(blk1.txs[1].core.fee >= blk1.txs[2].core.fee);
}

#[test]
#[cfg(feature = "pq44-runtime")]
fn block_respects_byte_budget() {
    let mut accounts = Accounts::default();
    let chain_id = [0x22u8; 20];
    let prev = [0x44u8; 32];

    // One signer, multiple nonces (same sender)
    let (pk, sk) = keypair();

    // create one tx to derive the sender address
    let first = sign_with_pk_sk(
        chain_id,
        TxCore {
            to: Address::from_bytes([9; 20]),
            amount: 1,
            fee: 1000,
            nonce: 0,
        },
        &pk,
        &sk,
    );
    let sender = sender_from_pubkey_first20(&first).expect("sender");
    accounts.credit(sender, 1_000_000); // enough to cover all txs

    let mut cands = vec![first];
    for n in 1..10u64 {
        let core = TxCore {
            to: Address::from_bytes([9; 20]),
            amount: 1,
            fee: 1000,
            nonce: n,
        };
        cands.push(sign_with_pk_sk(chain_id, core, &pk, &sk));
    }

    let example_sz = tx_budget_bytes(&cands[0]) as usize;
    let max_bytes = HEADER_BUDGET_BYTES + 5 * example_sz;
    let blk = assemble_block(&accounts, chain_id, prev, 7, max_bytes, cands, 999).unwrap();

    // Compute the expected count from real sizes so the test is stable across features.
    // Budget accounting is: header_base_bytes() + N * tx_budget_bytes(sample_tx)
    let hdr_bytes = eezo_ledger::block::header_base_bytes() as usize;
    // Use any tx from the picked set (they all have the same budget shape in this test)
    let sample = blk.txs.get(0).expect("at least one tx picked");
    let per_tx = eezo_ledger::block::tx_budget_bytes(sample) as usize;
    // max_bytes is whatever this test configured earlier; if it’s a local var, substitute that.
    let allowed = (max_bytes - hdr_bytes) / per_tx;
    assert_eq!(blk.header.tx_count as usize, allowed);

    let used_budget = hdr_bytes + blk.txs.len() * example_sz;
    assert!(used_budget <= max_bytes, "must respect byte budget");
}

/// Assembling an empty set of txs should yield a valid empty block.
#[test]
fn assemble_empty_block() {
    let accounts = Accounts::default();
    let chain_id = [0u8; 20];
    let prev = [0u8; 32];
    let txs: Vec<SignedTx> = vec![];
    let blk = assemble_block(&accounts, chain_id, prev, 0, 1_000_000, txs.clone(), 0).unwrap();
    assert_eq!(blk.txs.len(), 0);
    assert_eq!(blk.header.tx_root, txs_root(&txs));
}

/// Oversized tx should be rejected.
#[test]
#[cfg(feature = "pq44-runtime")]
fn assemble_rejects_oversized_tx() {
    let accounts = Accounts::default();
    let chain_id = [0u8; 20];
    let prev = [0u8; 32];

    // This signature is artificially huge to make the tx oversized.
    let big_sig = vec![0u8; 2_000_000];

    let tx = SignedTx {
        core: TxCore {
            to: Address::from_bytes([2; 20]),
            amount: 1,
            fee: 1,
            nonce: 0,
        },
        pubkey: vec![0; 32],
        sig: big_sig,
    };

    // Assemble a block with just this one oversized transaction.
    // The assemble_block function should filter it out.
    let blk = assemble_block(&accounts, chain_id, prev, 1, 1_000_000, vec![tx], 123).unwrap();

    // The block should be empty because the only candidate was rejected.
    assert_eq!(blk.txs.len(), 0, "Assembler must reject oversized tx");
}

// Property-based randomized invariants
proptest! {
  #![proptest_config(ProptestConfig {
      failure_persistence: None,
      .. ProptestConfig::default()
  })]
  #[test]
  #[cfg(feature = "pq44-runtime")]
  fn assemble_randomized_blocks_respect_budget(
      // Generate 1 to 200 transactions.
      tx_count in 1..200usize,
      // Select a random number of transactions to fit in the budget.
      tx_to_fit in 1..200usize,
  ) {
      let accounts = Accounts::default();
      let chain_id = [0u8; 20];
      let prev_hash = [1u8; 32];
      let to = Address::from_bytes([7; 20]);

      let txs: Vec<SignedTx> = (0..tx_count)
          .map(|n| {
              sign_tx(
                  chain_id,
                  TxCore { to, amount: 1, fee: (n % 3) as u128, nonce: n as u64 },
              )
          })
          .collect();

      // Ensure we have at least one tx to calculate size from.
      if txs.is_empty() {
          return Ok(());
      }

      let example_sz = tx_budget_bytes(&txs[0]) as usize;
      // Set a budget that fits a specific number of txs.
      let num_to_include = std::cmp::min(tx_count, tx_to_fit);
      let budget = HEADER_BUDGET_BYTES + num_to_include * example_sz;
      let budget_u64 = u64::try_from(budget).expect("test budget fits in u64");

      let blk = assemble_block(&accounts, chain_id, prev_hash, 1, budget_u64 as usize, txs, 12345).unwrap();

      // The number of transactions in the block should not exceed what the budget allows.
      prop_assert!(blk.txs.len() <= num_to_include, "Block must not exceed budgeted tx count");

      // Also check that the tx_root is calculated correctly.
      prop_assert_eq!(blk.header.tx_root, txs_root(&blk.txs));
  }
}