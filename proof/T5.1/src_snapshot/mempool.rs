use crate::tx::TxWitness;
use crate::consensus::{SignedConsensusMsg};
use crate::consensus_sig;
use crate::cert_store::CertLookup;
use bincode;

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("witness too large: {0} bytes")]
    WitnessTooLarge(usize),
    #[error("invalid signature")]
    InvalidSignature,
}

pub trait VerifyCache {
    fn verify_witness(&mut self, payload_hash: &[u8], witness: &TxWitness) -> bool;
}

/// Hard cap to avoid DoS with giant witnesses (tune in config)
pub const MAX_WITNESS_BYTES: usize = 4096;

#[cfg(feature = "mempool-batch-verify")]
const MP_BATCH_MIN: usize = 64;

pub fn validate_witness(
    payload_hash: &[u8],
    w: &TxWitness,
    cache: &mut impl VerifyCache,
) -> Result<(), MempoolError> {
    let sz = bincode::serialized_size(w).unwrap_or(0) as usize;
    if sz > MAX_WITNESS_BYTES {
        return Err(MempoolError::WitnessTooLarge(sz));
    }
    if !cache.verify_witness(payload_hash, w) {
        return Err(MempoolError::InvalidSignature);
    }
    Ok(())
}

pub struct Mempool {
    chain_id: [u8; 20],
    cert_store: Box<dyn CertLookup + Sync + Send>,
}

impl Mempool {
    pub fn new(chain_id: [u8; 20], cert_store: Box<dyn CertLookup + Sync + Send>) -> Self {
        Mempool { chain_id, cert_store }
    }

    pub fn admit_incoming(&mut self, msgs: Vec<SignedConsensusMsg>) {
        #[cfg(all(feature = "pq44-runtime", feature = "mempool-batch-verify"))]
        if msgs.len() >= MP_BATCH_MIN {
            let flags = consensus_sig::verify_many::<crate::pq44_runtime::Pq44>(
                &msgs, self.chain_id, &*self.cert_store,
            );
            let mut kept = Vec::with_capacity(msgs.len());
            for (i, m) in msgs.into_iter().enumerate() {
                if flags[i] { kept.push(m); }
            }
            self.enqueue_all(kept);
            return;
        }

        // default path: single-message verify
        for m in msgs {
            if self.verify_single(&m) {
                self.enqueue(m);
            }
        }
    }

    fn verify_single(&self, msg: &SignedConsensusMsg) -> bool {
        #[cfg(feature = "pq44-runtime")]
        {
            consensus_sig::verify_core::<crate::pq44_runtime::Pq44>(msg, &self.chain_id, &*self.cert_store).is_ok()
        }
        #[cfg(not(feature = "pq44-runtime"))]
        {
            consensus_sig::verify_core::<eezo_crypto::sig::ml_dsa::MlDsa2>(msg, &self.chain_id, &*self.cert_store).is_ok()
        }
    }

    fn enqueue(&mut self, _msg: SignedConsensusMsg) {
        // Placeholder: implement actual enqueue logic
    }
    #[allow(dead_code)]
    fn enqueue_all(&mut self, msgs: Vec<SignedConsensusMsg>) {
        // Placeholder: implement actual enqueue_all logic
        for msg in msgs {
            self.enqueue(msg);
        }
    }
}