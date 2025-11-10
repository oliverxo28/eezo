#![allow(dead_code)]
#![cfg(feature = "pq44-runtime")]

use eezo_ledger::{tx_domain_bytes, Address, SignedTx, TxCore};
use pqcrypto_mldsa::mldsa44::{detached_sign, keypair, PublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

pub struct TxBuilder {
    chain_id: [u8; 20],
    sk: SecretKey,
    pk: PublicKey,
    sender: Address,
}

impl TxBuilder {
    pub fn new(chain_id: [u8; 20]) -> Self {
        let (pk, sk) = keypair();
        let mut a = [0u8; 20];
        a.copy_from_slice(&pk.as_bytes()[..20]);
        let sender = Address::from_bytes(a);
        Self {
            chain_id,
            sk,
            pk,
            sender,
        }
    }

    #[allow(dead_code)]
    pub fn from_keys(chain_id: [u8; 20], sk: SecretKey, pk: PublicKey) -> Self {
        let mut a = [0u8; 20];
        a.copy_from_slice(&pk.as_bytes()[..20]);
        let sender = Address::from_bytes(a);
        Self {
            chain_id,
            sk,
            pk,
            sender,
        }
    }

    pub fn sender(&self) -> Address {
        self.sender
    }

    /// Sign TxCore under ML-DSA-44 and return raw signature bytes.
    fn sign_core(&self, core: &TxCore) -> Vec<u8> {
        let msg = tx_domain_bytes(self.chain_id, core);
        let sig = detached_sign(&msg, &self.sk);
        sig.as_bytes().to_vec()
    }

    pub fn build(&self, to: Address, amount: u128, fee: u128, nonce: u64) -> SignedTx {
        let core = TxCore {
            to,
            amount,
            fee,
            nonce,
        };
        // Sign BEFORE moving `core` into the struct to avoid borrow-after-move.
        let sig_bytes = self.sign_core(&core);
        SignedTx {
            core, // moved here after we've used &core above
            pubkey: self.pk.as_bytes().to_vec(),
            sig: sig_bytes,
        }
    }

    /// Build a tx with a deliberately corrupted signature (for BadSignature tests).
    pub fn build_bad_sig(&self, to: Address, amount: u128, fee: u128, nonce: u64) -> SignedTx {
        let core = TxCore { to, amount, fee, nonce };
        let mut sig = self.sign_core(&core);
        if let Some(last) = sig.last_mut() {
            *last ^= 0x01; // flip one bit
        }
        SignedTx {
            core,
            pubkey: self.pk.as_bytes().to_vec(),
            sig,
        }
    }
}

pub fn new_many(chain_id: [u8; 20], n: usize) -> Vec<TxBuilder> {
    (0..n).map(|_| TxBuilder::new(chain_id)).collect()
}

pub fn addr(b: u8) -> Address {
    Address::from_bytes([b; 20])
}