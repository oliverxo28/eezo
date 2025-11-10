use crate::{tx_domain_bytes, SignedTx, TxCore};
use eezo_crypto::verify_sig;

/// Canonical message = domain-separated bytes from chain_id + TxCore.
/// This must match exactly what the wallet signs.
pub fn tx_msg_bytes(chain_id: [u8; 20], core: &TxCore) -> Vec<u8> {
    tx_domain_bytes(chain_id, core)
}

/// Verify a SignedTx using the crypto crate’s unified verifier.
/// Scheme-agnostic: works for ML-DSA / SLH-DSA per runtime features.
pub fn verify_signed_tx(chain_id: [u8; 20], tx: &SignedTx) -> bool {
    let msg = tx_msg_bytes(chain_id, &tx.core);
    verify_sig(&tx.pubkey, &msg, &tx.sig)
}
