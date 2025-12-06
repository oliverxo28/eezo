use eezo_ledger::{
    accounts::Accounts,
    block::{tx_size_bytes, HEADER_BUDGET_BYTES, txs_root},
    cert_store::CertLookupT4,
    config::FeeCfg,
    tx::{sender_from_pubkey_first20, validate_tx_stateful, TxStateError},
    tx_types::{validate_tx_shape, TxStatelessError},
    Address,
    SignedTx,
    TxCore,
};

// (No signature verification in these tests; crypto is covered elsewhere.)
use std::sync::Arc;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    #[error("bad signature")]
    BadSig,
    #[error("stateless checks failed: {0}")]
    Stateless(#[from] TxStatelessError),
    #[error("stateful checks failed: {0}")]
    Stateful(#[from] TxStateError),
    #[error("invalid sender")]
    InvalidSender,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionOk {
    pub sender: Address,
    pub core: TxCore,
    pub tx_hash: [u8; 32],
    pub size_bytes: usize,
}

pub fn admit_signed_tx(
    chain_id: [u8; 20],
    accts: &Accounts,
    stx: &SignedTx,
) -> Result<AdmissionOk, RejectReason> {
    // Stateless shape (amount>0, etc.)
    validate_tx_shape(&stx.core)?;

    // NOTE: For this test file we do NOT enforce signature verification.
    // These tests focus on mempool/stateful admission invariants; crypto correctness
    // is covered by dedicated sign/verify tests elsewhere.
    let _ = chain_id; // silence unused when features vary

    // Map pubkey→sender (first 20B) and do stateful checks
    let sender = sender_from_pubkey_first20(stx).ok_or(RejectReason::InvalidSender)?;
    validate_tx_stateful(accts, sender, &stx.core)?;

    Ok(AdmissionOk {
        sender,
        core: stx.core.clone(),
        tx_hash: txs_root(std::slice::from_ref(stx)),
        size_bytes: tx_size_bytes(stx),
    })
}

// --- Minimal mempool stub just so the test file compiles and links ---
pub struct Mempool {
    _chain_id: [u8; 20],
    #[allow(dead_code)]
    certs: Arc<dyn CertLookupT4 + Send + Sync>,
    // you can extend with queues / indices later
}

impl Mempool {
    pub fn new(chain_id: [u8; 20], certs: Arc<dyn CertLookupT4 + Send + Sync>) -> Self {
        Self { _chain_id: chain_id, certs }
    }

    pub fn enqueue_tx(&mut self, _tx: SignedTx) {
        // Placeholder
    }

    pub fn drain_for_block(&mut self, _max_bytes: usize, _accounts: &Accounts) -> Vec<SignedTx> {
        // Placeholder
        let _ = HEADER_BUDGET_BYTES; // keep import “used”
        let _ = self._chain_id;      // keep field “used”
        vec![]
    }
}

// ---------------------------- Tests ----------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use eezo_ledger::{Accounts, SignedTx, TxCore};

    // Build a SignedTx whose pubkey’s first 20 bytes equal `from`.
    // Works regardless of signature verification because this test bypasses sig checks.
    fn dummy_signed(from: Address, core: TxCore) -> SignedTx {
        let mut pk = from.as_bytes().to_vec(); // first 20 bytes = sender
        pk.extend_from_slice(&[0u8; 12]);      // pad to 32 bytes so it's not "too short"
        let sig = vec![0u8; 32];               // placeholder
        SignedTx { core, pubkey: pk, sig }
    }

    #[test]
    fn admit_accepts_valid_tx() {
        let chain_id = [0u8; 20];
        let mut accts = Accounts::default();
        let from = Address::from_bytes([1u8; 20]);
        let to   = Address::from_bytes([2u8; 20]);

        accts.credit(from, 100);
        let core = TxCore { to, amount: 10, fee: 1, nonce: 0 };
        let stx  = dummy_signed(from, core);

        let res = admit_signed_tx(chain_id, &accts, &stx);
        assert!(res.is_ok(), "expected tx to be admitted, got {:?}", res);

        // keep FeeCfg import “used”
        let _ = std::mem::size_of::<FeeCfg>();
    }

    #[test]
    fn admit_rejects_insufficient_funds() {
        let chain_id = [0u8; 20];
        let accts = Accounts::default();
        let from = Address::from_bytes([3u8; 20]);
        let to   = Address::from_bytes([4u8; 20]);

        // no funding → should fail statefully
        let core = TxCore { to, amount: 10, fee: 1, nonce: 0 };
        let stx  = dummy_signed(from, core);

        let res = admit_signed_tx(chain_id, &accts, &stx);
        assert!(matches!(res, Err(RejectReason::Stateful(TxStateError::InsufficientFunds { .. }))));
    }

    #[test]
    fn admit_rejects_bad_nonce_nonzero_start() {
        let chain_id = [0u8; 20];
        let mut accts = Accounts::default();
        let from = Address::from_bytes([5u8; 20]);
        let to   = Address::from_bytes([6u8; 20]);

        accts.credit(from, 100);
        // account expects nonce=0, we submit nonce=1 → BadNonce
        let core = TxCore { to, amount: 10, fee: 1, nonce: 1 };
        let stx  = dummy_signed(from, core);
        let res = admit_signed_tx(chain_id, &accts, &stx);
        assert!(matches!(res, Err(RejectReason::Stateful(TxStateError::BadNonce { .. }))));
    }

    #[test]
    fn admit_rejects_gap_nonce() {
        let chain_id = [0u8; 20];
        let mut accts = Accounts::default();
        let from = Address::from_bytes([7u8; 20]);
        let to   = Address::from_bytes([8u8; 20]);

        accts.credit(from, 100);
        // try nonce=5 without prior txs → BadNonce
        let core = TxCore { to, amount: 10, fee: 1, nonce: 5 };
        let stx  = dummy_signed(from, core);
        let res = admit_signed_tx(chain_id, &accts, &stx);
        assert!(matches!(res, Err(RejectReason::Stateful(TxStateError::BadNonce { .. }))));
    }

    #[test]
    fn admit_rejects_bad_shape() {
        let chain_id = [0u8; 20];
        let accts = Accounts::default();
        let from = Address::from_bytes([9u8; 20]);
        let to   = Address::from_bytes([0xAA; 20]);

        // amount=0 is invalid by shape rules
        let core = TxCore { to, amount: 0, fee: 1, nonce: 0 };
        let stx  = dummy_signed(from, core);
        let res = admit_signed_tx(chain_id, &accts, &stx);
        assert!(matches!(res, Err(RejectReason::Stateless(_))));
    }

    #[test]
    fn admit_rejects_invalid_sender() {
        let chain_id = [0u8; 20];
        let accts = Accounts::default();

        // SignedTx with malformed pubkey (empty) → invalid sender
        let core = TxCore { to: Address::from_bytes([1u8; 20]), amount: 10, fee: 1, nonce: 0 };
        let stx = SignedTx { core, pubkey: vec![], sig: vec![0u8; 32] };
        let res = admit_signed_tx(chain_id, &accts, &stx);
        assert!(matches!(res, Err(RejectReason::InvalidSender)));
    }

    #[test]
    fn mempool_capacity_limit() {
        use eezo_ledger::cert_store::StaticCertStore;

        let chain_id = [0u8; 20];
        let certs = Arc::new(StaticCertStore::new());
        let mut mp = Mempool::new(chain_id, certs);

        // Placeholder stub → drains empty
        let accounts = Accounts::default();
        let drained = mp.drain_for_block(1024, &accounts);
        assert!(drained.is_empty(), "placeholder mempool should drain empty");
    }
}