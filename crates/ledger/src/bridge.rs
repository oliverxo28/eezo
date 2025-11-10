// crates/ledger/src/bridge.rs
use crate::{Accounts, Address, Supply};
#[cfg(all(not(feature = "skip-sig-verify"), not(feature = "testing")))]
use eezo_crypto::sig::registry::verify as verify_sig;
use sha3::{Digest, Sha3_256};

pub type ExtChain = u8; // 1 = Sepolia (example)
pub type DepositId = [u8; 32]; // hash(source_chain || source_tx || log_index || amount || to)

/// Domain separator for bridge mint signing & leaves (stable contract).
pub const BRIDGE_MINT_DOMAIN: &[u8] = b"EEZO:bridge:mint:v1";

#[derive(Clone, Debug)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct BridgeMintVoucher {
    pub deposit_id: DepositId,
    pub ext_chain: ExtChain,
    pub source_tx: [u8; 32],
    pub to: Address, // EEZO recipient (20B)
    pub amount: u128,
    pub sig: Vec<u8>, // ML-DSA-44 signature by Bridge Admin
}

#[derive(Default, Clone, Debug)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct BridgeState {
    pub processed_deposits: std::collections::HashSet<DepositId>,
    pub outbox_nonce: u64, // monotone id for outbox events
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct OutboxEvent {
    pub id: u64, // outbox_nonce value used
    pub from: Address,
    pub amount: u128,
    pub ext_chain: ExtChain,
    pub hint: [u8; 20], // external addr hint (Alpha: sender bytes)
    pub height: u64,
}

#[derive(Debug)]
pub enum BridgeError {
    AlreadyProcessed,
    BadSignature,
}

/// Canonical message for admin signing (domain-separated, stable).
pub fn canonical_mint_msg(chain_id: [u8; 20], v: &BridgeMintVoucher) -> Vec<u8> {
    // BRIDGE_MINT_DOMAIN || chain_id || deposit_id || ext_chain || source_tx || to || amount(le)
    let mut b = BRIDGE_MINT_DOMAIN.to_vec();
    b.extend_from_slice(&chain_id);
    b.extend_from_slice(&v.deposit_id);
    b.push(v.ext_chain);
    b.extend_from_slice(&v.source_tx);
    b.extend_from_slice(v.to.as_bytes());
    b.extend_from_slice(&v.amount.to_le_bytes());
    b
}

/// Compute a canonical deposit_id from parts (useful for off-chain tooling and tests).
/// Layout hashed with SHA3-256:
///   ext_chain(1) || source_tx(32) || to(20) || amount(le 16)
pub fn compute_deposit_id(
    ext_chain: ExtChain,
    source_tx: [u8; 32],
    to: Address,
    amount: u128,
) -> DepositId {
    let mut buf = Vec::with_capacity(1 + 32 + 20 + 16);
    buf.push(ext_chain);
    buf.extend_from_slice(&source_tx);
    buf.extend_from_slice(to.as_bytes());
    buf.extend_from_slice(&amount.to_le_bytes());
    let mut h = Sha3_256::new();
    h.update(&buf);
    let out = h.finalize();
    out.into()
}

/// Canonical Merkle **leaf** for a bridge mint (used in inclusion proofs next step).
/// We bind the leaf to the *signed* message so proof verification re-uses the same contract.
pub fn mint_leaf(chain_id: [u8; 20], v: &BridgeMintVoucher) -> [u8; 32] {
    let msg = canonical_mint_msg(chain_id, v);
    let mut h = Sha3_256::new();
    h.update(&msg);
    let out = h.finalize();
    out.into()
}

/// Apply a deposit voucher (in-ledger, replay-safe).
pub fn apply_bridge_mint(
    accts: &mut Accounts,
    _supply: &mut Supply, // reserved (burn/mint accounting if needed later)
    bridge: &mut BridgeState,
    chain_id: [u8; 20],
    voucher: &BridgeMintVoucher,
    admin_pubkey: &[u8],
) -> Result<(), BridgeError> {
    // 1) replay guard
    if bridge.processed_deposits.contains(&voucher.deposit_id) {
        return Err(BridgeError::AlreadyProcessed);
    }

    // 2) signature verify
    //    Skip in tests (and when skip-sig-verify is on) so replay logic is tested independently.
    #[cfg(all(not(feature = "skip-sig-verify"), not(feature = "testing")))]
    {
        let msg = canonical_mint_msg(chain_id, voucher);
        if !verify_sig(admin_pubkey, &msg, &voucher.sig) {
            return Err(BridgeError::BadSignature);
        }
    }
    // When built with skip-sig-verify **or** testing, silence unused param warnings
    #[cfg(any(feature = "skip-sig-verify", feature = "testing"))]
    let _ = (&chain_id, &admin_pubkey);

    // 3) credit & record
    accts.credit(voucher.to, voucher.amount);
    bridge.processed_deposits.insert(voucher.deposit_id);
    Ok(())
}

/// Record a withdrawal placeholder (outbox skeleton).
pub fn record_outbox_skeleton(
    bridge: &mut BridgeState,
    from: Address,
    amount: u128,
    ext_chain: ExtChain,
    hint: [u8; 20],
    height: u64,
) -> OutboxEvent {
    let id = bridge.outbox_nonce;
    bridge.outbox_nonce = bridge.outbox_nonce.wrapping_add(1);
    OutboxEvent {
        id,
        from,
        amount,
        ext_chain,
        hint,
        height,
    }
}
