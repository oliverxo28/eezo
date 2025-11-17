#![cfg(feature = "pq44-runtime")]
use eezo_ledger::{
    block::{BlockHeader, BlockId},
    consensus_msg::{ConsensusMsg, Phase, Proposal, SignedConsensusMsg, ValidatorId, Vote},
};
use eezo_net::consensus_wire::{decode_envelope, encode_envelope, GossipEnvelope, WireKind};

/// Build a minimal, syntactically valid signed consensus message for wire tests.
/// Signature bytes are dummy; we do not perform cryptographic verification here.
fn dummy_signed_msg(kind: WireKind) -> SignedConsensusMsg {
    let dummy_header = BlockHeader {
        height: 1,
        prev_hash: [6u8; 32],
        tx_root: [7u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0,
        tx_count: 0,
        timestamp_ms: 0,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };

    // Construct a deterministic core by kind
    let msg = match kind {
        WireKind::Proposal => {
            let p = Proposal {
                header: dummy_header,
                view: 0,
                proposer: ValidatorId(0),
                justify: None,
            };
            ConsensusMsg::Proposal(Box::new(p))
        }
        WireKind::Vote => {
            let v = Vote {
                phase: Phase::Prepare,
                view: 0,
                block_id: BlockId([7u8; 32]),
                voter: ValidatorId(0),
            };
            ConsensusMsg::Vote(v)
        }
    };

    // Dummy signature bytes (ML-DSA-44 signature length = 2420)
    let sig = vec![0u8; 2420];

    SignedConsensusMsg {
        msg,
        sig,
        signer: ValidatorId(0),
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
    }
}

#[test]
fn wire_envelope_roundtrip() {
    // happy path for each kind
    for kind in [WireKind::Proposal, WireKind::Vote] {
        let msg = dummy_signed_msg(kind);
        let env: GossipEnvelope = encode_envelope(&msg);
        let decoded = decode_envelope(&env).expect("decode must succeed");

        match (kind, decoded.msg) {
            (WireKind::Proposal, ConsensusMsg::Proposal(p)) => {
                assert_eq!(p.header.height, 1);
            }
            (WireKind::Vote, ConsensusMsg::Vote(v)) => {
                assert_eq!(v.voter, ValidatorId(0));
            }
            _ => panic!("kind mismatch after decode"),
        }
    }

    // mismatch case: corrupt kind byte -> should error
    let msg = dummy_signed_msg(WireKind::Proposal);
    let mut env = encode_envelope(&msg);
    env.kind = 99; // invalid kind tag
    let err = decode_envelope(&env).unwrap_err();
    assert!(err.contains("mismatch") || err.contains("unknown"));
}