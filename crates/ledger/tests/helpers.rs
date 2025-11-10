// crates/ledger/tests/helpers.rs
#![allow(dead_code)]

use eezo_ledger::{SignedTx, tx_types::TxCore, tx_domain_bytes};
use pqcrypto_mldsa::mldsa44::{detached_sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

/// Build a fully signed tx that `tx_sig::verify_signed_tx` will accept under pq44-runtime.
pub fn mk_signed_tx(core: TxCore, pk: &PublicKey, sk: &SecretKey, chain_id: [u8; 20]) -> SignedTx {
    // ✅ Use the canonical domain function from the crate
    let msg = tx_domain_bytes(chain_id, &core);
    let sig = detached_sign(&msg, sk); // ML-DSA-44 detached signature

    SignedTx {
        core,
        pubkey: pk.as_bytes().to_vec(),
        sig: sig.as_bytes().to_vec(),
    }
}
