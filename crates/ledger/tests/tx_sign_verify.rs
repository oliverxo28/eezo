#![cfg(all(feature = "pq44-runtime", not(feature = "testing"), not(feature = "skip-sig-verify")))]

use eezo_ledger::{Address, SignedTx, TxCore};
use eezo_ledger::tx_types::tx_domain_bytes;
use eezo_ledger::block::txs_root;
use eezo_ledger::verify_signed_tx;
use pqcrypto_mldsa::mldsa44::{detached_sign, keypair};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

#[test]
fn tx_sign_and_verify_roundtrip() {
    let chain_id = [9u8; 20];
    let core = TxCore { to: Address::from_bytes([0x11; 20]), amount: 12345, fee: 100, nonce: 7 };

    let (pk, sk) = keypair();
    let msg = tx_domain_bytes(chain_id, &core);
    let sig = detached_sign(&msg, &sk);

    let mut tx = SignedTx { core, pubkey: pk.as_bytes().to_vec(), sig: sig.as_bytes().to_vec() };

    // Should succeed with correct signature
    assert!(verify_signed_tx(chain_id, &tx));

    // Corrupt one byte; should fail
    tx.sig[0] ^= 1;
    assert!(!verify_signed_tx(chain_id, &tx));
}

#[test]
fn fails_on_wrong_chain_id() {
    let chain_a = [0xAA; 20];
    let chain_b = [0xBB; 20];
    let core = TxCore { to: Address::from_bytes([0x22; 20]), amount: 1, fee: 1, nonce: 0 };

    let (pk, sk) = keypair();
    let msg_a = tx_domain_bytes(chain_a, &core);
    let sig_a = detached_sign(&msg_a, &sk);

    let tx = SignedTx { core, pubkey: pk.as_bytes().to_vec(), sig: sig_a.as_bytes().to_vec() };

    // Verifies on the chain it was signed for…
    assert!(verify_signed_tx(chain_a, &tx));
    // …but must NOT verify on a different chain id.
    assert!(!verify_signed_tx(chain_b, &tx));
}

#[test]
fn pubkey_mismatch_fails() {
    let chain_id = [0xCC; 20];
    let core = TxCore { to: Address::from_bytes([0x33; 20]), amount: 10, fee: 2, nonce: 1 };

    let (pk1, sk1) = keypair();
    let msg = tx_domain_bytes(chain_id, &core);
    let sig1 = detached_sign(&msg, &sk1);

    // Start with a valid tx from keypair 1…
    let mut tx = SignedTx { core: core.clone(), pubkey: pk1.as_bytes().to_vec(), sig: sig1.as_bytes().to_vec() };
    assert!(verify_signed_tx(chain_id, &tx));

    // …then swap in a different pubkey without re-signing -> must fail.
    let (pk2, _sk2) = keypair();
    tx.pubkey = pk2.as_bytes().to_vec();
    assert!(!verify_signed_tx(chain_id, &tx));
}

#[test]
fn resign_after_tamper_succeeds() {
    let chain_id = [0xDD; 20];
    let mut core = TxCore { to: Address::from_bytes([0x44; 20]), amount: 77, fee: 3, nonce: 2 };

    let (pk, sk) = keypair();
    let msg0 = tx_domain_bytes(chain_id, &core);
    let sig0 = detached_sign(&msg0, &sk);
    let mut tx = SignedTx { core: core.clone(), pubkey: pk.as_bytes().to_vec(), sig: sig0.as_bytes().to_vec() };
    assert!(verify_signed_tx(chain_id, &tx));

    // Tamper with payload -> verification must fail…
    tx.core.amount += 1;
    assert!(!verify_signed_tx(chain_id, &tx));

    // …but if we re-sign the modified payload, it should pass again.
    core = tx.core.clone();
    let msg1 = tx_domain_bytes(chain_id, &core);
    let sig1 = detached_sign(&msg1, &sk);
    tx.sig = sig1.as_bytes().to_vec();
    assert!(verify_signed_tx(chain_id, &tx));
}

#[test]
fn tx_root_changes_when_sig_changes_and_is_stable_when_equal() {
    // Build two identical, valid txs
    let chain_id = [0xEE; 20];
    let core = TxCore { to: Address::from_bytes([0x55; 20]), amount: 5, fee: 1, nonce: 0 };
    let (pk, sk) = keypair();

    let msg = tx_domain_bytes(chain_id, &core);
    let sig = detached_sign(&msg, &sk).as_bytes().to_vec();
    let tx1 = SignedTx { core: core.clone(), pubkey: pk.as_bytes().to_vec(), sig: sig.clone() };
    let tx2 = SignedTx { core: core.clone(), pubkey: pk.as_bytes().to_vec(), sig };

    // Determinism: identical txs -> identical root
    let r1 = txs_root(&[tx1.clone()]);
    let r2 = txs_root(&[tx2.clone()]);
    assert_eq!(r1, r2, "equal txs must produce equal tx root");

    // Flip one bit in the signature -> different root
    let mut tx3 = tx2.clone();
    tx3.sig[0] ^= 1;
    let r3 = txs_root(&[tx3]);
    assert_ne!(r1, r3, "signature mutation must change tx root");
}
