use crate::address::Address;
use serde::{Deserialize, Serialize};

/// 8-byte domain tag for transaction signing.
pub const TX_DOMAIN_TAG: &[u8; 8] = b"EEZO-TX\0";

/// Core (unsigned) transfer tx
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TxCore {
    pub to: Address,
    pub amount: u128,
    pub fee: u128,
    pub nonce: u64,
}

/// Signed transaction (signature wiring comes next step)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SignedTx {
    pub core: TxCore,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Deterministic domain-bound bytes for signing/verifying.
/// Format: b"EEZO-TX\0" || chain_id(20) || nonce(u64 LE) || amount(u128 LE) || fee(u128 LE) || to(20)
pub fn tx_domain_bytes(chain_id: [u8; 20], core: &TxCore) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 20 + 8 + 16 + 16 + 20);
    out.extend_from_slice(TX_DOMAIN_TAG);
    out.extend_from_slice(&chain_id);
    out.extend_from_slice(&core.nonce.to_le_bytes());
    out.extend_from_slice(&core.amount.to_le_bytes());
    out.extend_from_slice(&core.fee.to_le_bytes());
    out.extend_from_slice(core.to.as_bytes());
    out
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TxStatelessError {
    #[error("amount must be > 0")]
    AmountZero,
    #[error("fee too large")]
    FeeTooLarge,
    #[error("nonce exhausted")]
    NonceTooLarge,
    #[error("amount + fee overflows")]
    AmountPlusFeeOverflow,
}

/// Pure shape checks (no signature, no state)
pub fn validate_tx_shape(core: &TxCore) -> Result<(), TxStatelessError> {
    if core.amount == 0 {
        return Err(TxStatelessError::AmountZero);
    }
    // Placeholder guardrails; hard limits can move to config later:
    if core.fee > (u128::MAX / 2) {
        return Err(TxStatelessError::FeeTooLarge);
    }
    if core.nonce == u64::MAX {
        return Err(TxStatelessError::NonceTooLarge);
    }
    if core.amount.checked_add(core.fee).is_none() {
        return Err(TxStatelessError::AmountPlusFeeOverflow);
    }
    Ok(())
}