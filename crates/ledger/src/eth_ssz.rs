#![cfg(feature = "eth-ssz")]

use eezo_serde::eth::{Decode, Encode, HashTreeRoot, Result as EthResult};
use crate::block::BlockHeader;
use crate::{Address, SignedTx, TxCore};

/// Public SSZ wire-format version for the ledger implementation.
/// Bump this when you add/remove/reorder fields in SSZ that affect encoding/decoding or roots.
pub const LEDGER_SSZ_VERSION: u8 = 2;

// ---- Address helper (20 bytes) ------------------------------------------------
#[allow(dead_code)]
trait AddressAsBytes {
    fn as_20(&self) -> &[u8; 20];
}
impl AddressAsBytes for Address {
    fn as_20(&self) -> &[u8; 20] { self.as_bytes() }
}

// ---- Encode for core types ----------------------------------------------------
impl Encode for TxCore {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        // fixed field order (v2 contract)
        out.extend_from_slice(self.to.as_bytes()); // [u8;20]
        self.amount.ssz_write(out);               // u128
        self.fee.ssz_write(out);                  // u128
        self.nonce.ssz_write(out);                // u64
    }
}

impl Encode for SignedTx {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        self.core.ssz_write(out);
        self.pubkey.ssz_write(out); // Vec<u8>
        self.sig.ssz_write(out);    // Vec<u8>
    }
}

// BlockHeader v2 encoding: height, prev_hash, tx_root, [tx_root_v2], fee_total,
//                          tx_count, timestamp_ms, [qc_hash]
impl Encode for BlockHeader {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        self.height.ssz_write(out);
        self.prev_hash.ssz_write(out);
        self.tx_root.ssz_write(out);
        // v2 field (present only when the feature is enabled)
        #[cfg(feature = "eth-ssz")]
        self.tx_root_v2.ssz_write(out);
        // remaining v1 fields
        self.fee_total.ssz_write(out);
        self.tx_count.ssz_write(out);
        self.timestamp_ms.ssz_write(out);
        // checkpoints-only field at the end (as Decode expects)
        #[cfg(feature = "checkpoints")]
        self.qc_hash.ssz_write(out);
    }
}

// ---- txs_root_v2: vector-of-roots then root that vector ----------------------
pub fn txs_root_v2(txs: &[SignedTx]) -> [u8; 32] {
    // compute per-tx SSZ v2 roots, sort for order-independence, then hash that vector
    let mut per_tx_roots: Vec<[u8; 32]> = txs.iter().map(|tx| tx.hash_tree_root()).collect();
    per_tx_roots.sort_unstable(); // lexicographic
    per_tx_roots.hash_tree_root()
}

// ---- state_root_v2: combine roots of (accounts, supply) ----------------------
/// compute the SSZ v2 "state root" by hashing the vector `[accounts_root, supply_root]`.
/// generic over any state types that implement `HashTreeRoot`.
pub fn state_root_v2<A: HashTreeRoot, S: HashTreeRoot>(accounts: &A, supply: &S) -> [u8; 32] {
    let a = accounts.hash_tree_root();
    let s = supply.hash_tree_root();
    vec![a, s].hash_tree_root()
}

/* ----------------------- Decode impls (Phase 2) ------------------------------- */
impl Decode for TxCore {
    fn ssz_read(input: &[u8]) -> EthResult<(Self, usize)> {
        let (to_bytes, u1) = <[u8; 20]>::ssz_read(input)?;
        let (amount,   u2) = u128::ssz_read(&input[u1..])?;
        let (fee,      u3) = u128::ssz_read(&input[u1+u2..])?;
        let (nonce,    u4) = u64::ssz_read(&input[u1+u2+u3..])?;
        Ok((TxCore {
            to: Address::from_bytes(to_bytes),
            amount, fee, nonce,
        }, u1 + u2 + u3 + u4))
    }
}

impl Decode for SignedTx {
    fn ssz_read(input: &[u8]) -> EthResult<(Self, usize)> {
        let (core,   u1) = TxCore::ssz_read(input)?;
        let (pk,     u2) = <Vec<u8>>::ssz_read(&input[u1..])?;
        let (sig,    u3) = <Vec<u8>>::ssz_read(&input[u1+u2..])?;
        Ok((SignedTx { core, pubkey: pk, sig }, u1 + u2 + u3))
    }
}

impl Decode for BlockHeader {
    fn ssz_read(input: &[u8]) -> EthResult<(Self, usize)> {
        let (height,    u1) = u64::ssz_read(input)?;
        let (prev_hash, u2) = <[u8;32]>::ssz_read(&input[u1..])?;
        let (tx_root,   u3) = <[u8;32]>::ssz_read(&input[u1+u2..])?;
        #[cfg(feature = "eth-ssz")]
        let (tx_root_v2, u3b) = <[u8;32]>::ssz_read(&input[u1+u2+u3..])?;
        let (fee_total, u4) = u128::ssz_read(&input[u1+u2+u3
            + if cfg!(feature="eth-ssz") { u3b } else { 0 } ..])?;
        let (tx_count,  u5) = u32::ssz_read(&input[u1+u2+u3
            + if cfg!(feature="eth-ssz") { u3b } else { 0 } + u4 ..])?;
        let (timestamp_ms, u6) = u64::ssz_read(&input[u1+u2+u3
            + if cfg!(feature="eth-ssz") { u3b } else { 0 } + u4 + u5 ..])?;
        #[cfg(feature = "checkpoints")]
        let (qc_hash, u7) = <[u8;32]>::ssz_read(&input[u1+u2+u3
            + if cfg!(feature="eth-ssz") { u3b } else { 0 } + u4 + u5 + u6 ..])?;

        let header = BlockHeader {
            height, prev_hash, tx_root,
            #[cfg(feature = "eth-ssz")]
            tx_root_v2,
            fee_total, tx_count, timestamp_ms,
            #[cfg(feature = "checkpoints")]
            qc_hash,
        };

        // compute 'used' without referencing u3b/u7 when features are off
        let mut used = u1 + u2 + u3 + u4 + u5 + u6;
        #[cfg(feature = "eth-ssz")] { used += u3b; }
        #[cfg(feature = "checkpoints")] { used += u7; }
        Ok((header, used))
    }
}
