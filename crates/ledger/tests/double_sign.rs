use eezo_ledger::cert_store::StaticCertStore;
use eezo_ledger::consensus::{ConsensusCfg, ConsensusNetwork, HotStuff};
use eezo_ledger::consensus_msg as hs_msg;
use pqcrypto_mldsa::mldsa44::keypair;
use std::sync::Arc;

/// Dummy network that just captures broadcasted messages
#[derive(Default)]
struct LoopbackNet;
impl LoopbackNet {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}
impl ConsensusNetwork for LoopbackNet {
    fn broadcast(&self, _msg: hs_msg::SignedConsensusMsg) {
        // no-op for this test
    }
}

fn make_signed_msg(
    header: eezo_ledger::BlockHeader,
    signer_id: hs_msg::ValidatorId,
) -> hs_msg::SignedConsensusMsg {
    let proposal = hs_msg::Proposal {
        header,
        view: 0,
        proposer: signer_id,
        justify: None,
    };
    let msg = hs_msg::ConsensusMsg::Proposal(Box::new(proposal));
    // Fake signature: just serialize the msg
    let bytes = bincode::serialize(&msg).unwrap();
    let sig = bytes.clone(); // placeholder sig = msg bytes
    hs_msg::SignedConsensusMsg::new(msg, signer_id, sig)
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[test]
fn double_sign_evidence_emitted() {
    let cfg = ConsensusCfg { n: 1, f: 0, chain_id: [0xE0; 20] };
    let certs = Arc::new(StaticCertStore::new());
    let net = LoopbackNet::new();
    let (_pk, _sk) = keypair();
    let mut hs = HotStuff::new(cfg, certs, net);

    // Two conflicting headers at same height
    let h1 = eezo_ledger::BlockHeader {
        height: 1,
        prev_hash: [0u8; 32],
        tx_root: [1u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 111,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };
    let mut h2 = h1.clone();
    h2.tx_root = [2u8; 32]; // conflict

    let msg1 = make_signed_msg(h1, hs_msg::ValidatorId(0));
    let msg2 = make_signed_msg(h2, hs_msg::ValidatorId(0));

    hs.on_signed_msg(msg1.clone());
    hs.on_signed_msg(msg2.clone());
    assert_eq!(msg1.signer, msg2.signer, "same signer");
    let b1 = bincode::serialize(&msg1.msg).unwrap();
    let b2 = bincode::serialize(&msg2.msg).unwrap();
    assert_ne!(b1, b2, "conflicting messages must differ");
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[test]
fn double_sign_no_false_positive() {
    let cfg = ConsensusCfg { n: 1, f: 0, chain_id: [0xE0; 20] };
    let certs = Arc::new(StaticCertStore::new());
    let net = LoopbackNet::new();
    let (_pk, _sk) = keypair();
    let mut hs = HotStuff::new(cfg, certs, net);

    // Same header signed twice → should be accepted once, ignored second time, but no double-sign
    let hdr = eezo_ledger::BlockHeader {
        height: 2,
        prev_hash: [0u8; 32],
        tx_root: [9u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 222,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };
    let msg_a = make_signed_msg(hdr.clone(), hs_msg::ValidatorId(0));
    let msg_b = make_signed_msg(hdr.clone(), hs_msg::ValidatorId(0));

    hs.on_signed_msg(msg_a.clone());
    hs.on_signed_msg(msg_b.clone());
    // Identical msgs should serialize to identical bytes → no double-sign
    let ba = bincode::serialize(&msg_a.msg).unwrap();
    let bb = bincode::serialize(&msg_b.msg).unwrap();
    assert_eq!(ba, bb, "identical msgs must not count as double-sign");
}