use eezo_ledger::{
    block::{apply_block, validate_block, Block, BlockValidationError},
    tx_domain_bytes,
    tx_types::TxCore,
    {Account, Accounts, Address, MintSource, SignedTx, Supply},
};
#[cfg(feature = "eth-ssz")]
use eezo_ledger::eth_ssz::txs_root_v2;
use pqcrypto_mldsa::mldsa44::{detached_sign, keypair};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

// PATCH 1: Define the args struct for mk_header
struct MkHeaderArgs {
    height: u64,
    prev_hash: [u8; 32],
    tx_root: [u8; 32],
    #[cfg(feature = "eth-ssz")]
    tx_root_v2: [u8; 32],
    fee_total: u128,
    tx_count: u32,
    timestamp_ms: u64,
    #[cfg(feature = "checkpoints")]
    qc_hash: [u8; 32],
}

// PATCH 1: Update function signature and body
fn mk_header(args: MkHeaderArgs) -> eezo_ledger::BlockHeader {
    eezo_ledger::BlockHeader {
        height: args.height,
        prev_hash: args.prev_hash,
        tx_root: args.tx_root,
        // fill v2 root when eth-ssz is enabled
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: args.tx_root_v2,
        fee_total: args.fee_total,
        tx_count: args.tx_count,
        timestamp_ms: args.timestamp_ms,
        #[cfg(feature = "checkpoints")]
        qc_hash: args.qc_hash,
    }
}

fn mk_signed_tx(chain_id: [u8; 20], to: Address, amount: u128, fee: u128, nonce: u64) -> SignedTx {
    let (pk, sk) = keypair();
    let core = TxCore {
        to,
        amount,
        fee,
        nonce,
    };
    let msg = tx_domain_bytes(chain_id, &core);
    let sig = detached_sign(&msg, &sk);
    SignedTx {
        core,
        pubkey: pk.as_bytes().to_vec(),
        sig: sig.as_bytes().to_vec(),
    }
}

#[test]
fn block_validate_and_apply_happy_path() {
    let chain_id = [0x11; 20];
    let mut accounts = Accounts::default();
    let mut supply = Supply::default();

    let to1 = Address::from_bytes([0x01; 20]);
    let to2 = Address::from_bytes([0x02; 20]);

    // First transaction from a fresh account uses nonce 0 (current nonce).
    let tx1 = mk_signed_tx(chain_id, to1, 100, 5, 0);
    let sender1 = Address::from_bytes(tx1.pubkey[0..20].try_into().unwrap());
    accounts.put(
        sender1,
        Account {
            balance: 1_000_000,
            nonce: 0,
        },
    );

    let tx2 = mk_signed_tx(chain_id, to2, 200, 7, 0);
    let sender2 = Address::from_bytes(tx2.pubkey[0..20].try_into().unwrap());
    accounts.put(
        sender2,
        Account {
            balance: 1_000_000,
            nonce: 0,
        },
    );

    let hard_cap: u128 = 1_000_000_000_000;
    supply
        .apply_mint_checked(1_000_000, hard_cap, MintSource::Native)
        .unwrap();

    let txs = vec![tx1, tx2];
    let fee_total: u128 = txs.iter().map(|t| t.core.fee).sum();
    let tx_count = txs.len() as u32;
    let tx_root = eezo_ledger::block::txs_root(&txs);

    // PATCH 1: Update mk_header call site
    let header = mk_header(MkHeaderArgs {
        height: 1,
        prev_hash: [0u8; 32],
        tx_root,
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: txs_root_v2(&txs),
        fee_total,
        tx_count,
        timestamp_ms: 12345,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    });
    let blk = Block { header, txs };

    // The call to apply_block will validate the block internally.
    apply_block(chain_id, &mut accounts, &mut supply, &blk).expect("applies");
}

// This negative test requires signature verification to be compiled in.
// We skip it in `testing` builds because those intentionally omit sig checks.
#[test]
#[cfg(all(not(feature = "skip-sig-verify"), not(feature = "testing")))]
fn block_rejects_bad_sig() {
    let chain_id = [0x22; 20];
    let mut accounts = Accounts::default();
    let to = Address::from_bytes([0xAA; 20]);

    // Set up account with balance and current nonce = 0 (first tx must use 0)
    let (pk, sk) = keypair();
    let core = TxCore {
        to,
        amount: 50,
        fee: 3,
        nonce: 0,
    };
    let msg = tx_domain_bytes(chain_id, &core);
    let sig = detached_sign(&msg, &sk);
    let mut tx = SignedTx {
        core,
        pubkey: pk.as_bytes().to_vec(),
        sig: sig.as_bytes().to_vec(),
    };

    let sender = Address::from_bytes(tx.pubkey[0..20].try_into().unwrap());
    accounts.put(
        sender,
        Account {
            balance: 100,
            nonce: 0,
        },
    );

    // Now corrupt the signature
    tx.sig[0] ^= 0xFF;

    let txs = vec![tx];
    // PATCH 1: Update mk_header call site
    let header = mk_header(MkHeaderArgs {
        height: 1,
        prev_hash: [0u8; 32],
        tx_root: eezo_ledger::block::txs_root(&txs),
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: txs_root_v2(&txs),
        fee_total: 3,
        tx_count: 1,
        timestamp_ms: 1,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    });
    let blk = Block { header, txs };

    let err = validate_block(&accounts, &Supply::default(), chain_id, &blk).unwrap_err();
    assert!(matches!(err, BlockValidationError::BadSignature { .. }));
}

#[test]
fn block_validate_accepts_empty_block() {
    let chain = [0u8; 20];
    let accounts = Accounts::default();
    let supply = Supply::default();

    let blk = Block {
        // PATCH 1: Update mk_header call site
        header: mk_header(MkHeaderArgs {
            height: 1,
            prev_hash: [0u8; 32],
            tx_root: [0u8; 32],
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: txs_root_v2(&[]),
            fee_total: 0,
            tx_count: 0,
            timestamp_ms: 0,
            #[cfg(feature = "checkpoints")]
            qc_hash: [0u8; 32],
        }),
        txs: vec![],
    };

    assert!(validate_block(&accounts, &supply, chain, &blk).is_ok());
}

#[test]
fn block_validate_rejects_tx_root_mismatch() {
    let chain = [0u8; 20];
    let accounts = Accounts::default();
    let supply = Supply::default();

    let mut blk = Block {
        // PATCH 1: Update mk_header call site
        header: mk_header(MkHeaderArgs {
            height: 1,
            prev_hash: [0u8; 32],
            tx_root: [1u8; 32], // deliberately wrong
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: txs_root_v2(&[]),
            fee_total: 0,
            tx_count: 0,
            timestamp_ms: 0,
            #[cfg(feature = "checkpoints")]
            qc_hash: [0u8; 32],
        }),
        txs: vec![],
    };

    let res = validate_block(&accounts, &supply, chain, &blk);
    assert!(matches!(res, Err(BlockValidationError::TxRootMismatch)));

    // fix tx_root so it passes
    blk.header.tx_root = [0u8; 32];
    // v2 root already correct for empty set via txs_root_v2(&[])
    assert!(validate_block(&accounts, &supply, chain, &blk).is_ok());
}

#[test]
fn block_validate_rejects_fee_total_mismatch() {
    let chain = [0u8; 20];
    let mut accounts = Accounts::default();
    let supply = Supply::default();

    // Build a real signed tx and fund the correct sender (derived from the real pubkey)
    let to = Address::from_bytes([2u8; 20]);
    let tx = mk_signed_tx(chain, to, 10, 5, 0);
    let sender = Address::from_bytes(tx.pubkey[0..20].try_into().unwrap());
    accounts.put(sender, Account { balance: 100, nonce: 0 });

    let blk = Block {
        // PATCH 1: Update mk_header call site
        header: mk_header(MkHeaderArgs {
            height: 1,
            prev_hash: [0u8; 32],
            // PATCH 2: Use std::slice::from_ref
            tx_root: eezo_ledger::block::txs_root(std::slice::from_ref(&tx)),
            #[cfg(feature = "eth-ssz")]
            // PATCH 3: Use std::slice::from_ref
            tx_root_v2: txs_root_v2(std::slice::from_ref(&tx)),
            fee_total: 99, // deliberately wrong
            tx_count: 1,
            timestamp_ms: 0,
            #[cfg(feature = "checkpoints")]
            qc_hash: [0u8; 32],
        }),
        txs: vec![tx],
    };

    let res = validate_block(&accounts, &supply, chain, &blk);
    assert!(matches!(
        res,
        Err(BlockValidationError::FeeTotalMismatch { .. })
    ));
}

#[test]
fn block_validate_rejects_tx_count_mismatch() {
    let chain = [0u8; 20];
    let accounts = Accounts::default();
    let supply = Supply::default();

    let blk = Block {
        // PATCH 1: Update mk_header call site
        header: mk_header(MkHeaderArgs {
            height: 1,
            prev_hash: [0u8; 32],
            tx_root: [0u8; 32],
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: txs_root_v2(&[]),
            fee_total: 0,
            tx_count: 1, // mismatch: no txs in vec
            timestamp_ms: 0,
            #[cfg(feature = "checkpoints")]
            qc_hash: [0u8; 32],
        }),
        txs: vec![],
    };

    let res = validate_block(&accounts, &supply, chain, &blk);
    assert!(matches!(
        res,
        Err(BlockValidationError::TxCountMismatch { .. })
    ));
}

#[test]
fn block_apply_rejects_replay_nonce() {
    let chain = [0u8; 20];
    let mut accounts = Accounts::default();
    let mut supply = Supply::default();

    // Build a real signed tx and fund the matching sender
    let to = Address::from_bytes([2u8; 20]);
    let tx = mk_signed_tx(chain, to, 10, 0, 0);
    let sender = Address::from_bytes(tx.pubkey[0..20].try_into().unwrap());
    accounts.put(sender, Account { balance: 50, nonce: 0 });

    let blk1 = Block {
        // PATCH 1: Update mk_header call site
        header: mk_header(MkHeaderArgs {
            height: 1,
            prev_hash: [0u8; 32],
            // PATCH 4: Use std::slice::from_ref
            tx_root: eezo_ledger::block::txs_root(std::slice::from_ref(&tx)),
            #[cfg(feature = "eth-ssz")]
            // PATCH 5: Use std::slice::from_ref
            tx_root_v2: txs_root_v2(std::slice::from_ref(&tx)),
            fee_total: 0,
            tx_count: 1,
            timestamp_ms: 0,
            #[cfg(feature = "checkpoints")]
            qc_hash: [0u8; 32],
        }),
        txs: vec![tx.clone()],
    };

    // apply once should succeed (nonce advances from 0 -> 1)
    apply_block(chain, &mut accounts, &mut supply, &blk1).unwrap();

    // second apply with same tx should fail due to nonce
    let blk2 = Block {
        header: blk1.header.clone(),
        txs: vec![tx],
    };
    let res = apply_block(chain, &mut accounts, &mut supply, &blk2);
    assert!(res.is_err(), "second apply should fail due to nonce replay under stateful validation");
}