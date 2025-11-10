#![cfg(feature = "pq44-runtime")]
use eezo_net::consensus::{
    kind_of, signer_id_from_pk, ConsensusMsgCore, MsgKind, PkBytes, PreCommit, PreVote, Proposal,
    SigBytes, SignedConsensusMsg,
};
use eezo_net::consensus_wire::{decode_envelope, encode_envelope, GossipEnvelope};

/// Build a minimal, syntactically valid signed consensus message for wire tests.
/// Signature bytes are dummy; we do not perform cryptographic verification here.
fn dummy_signed_msg(kind: MsgKind) -> SignedConsensusMsg {
    // Construct a deterministic core by kind
    let (core, height, round) = match kind {
        MsgKind::Proposal => {
            let p = Proposal {
                height: 1,
                round: 0,
                block_id: [7u8; 32],
            };
            (ConsensusMsgCore::Proposal(p), 1, 0)
        }
        MsgKind::PreVote => {
            let pv = PreVote {
                height: 1,
                round: 0,
                block_id: [7u8; 32],
            };
            (ConsensusMsgCore::PreVote(pv), 1, 0)
        }
        MsgKind::PreCommit => {
            let pc = PreCommit {
                height: 1,
                round: 0,
                block_id: [7u8; 32],
            };
            (ConsensusMsgCore::PreCommit(pc), 1, 0)
        }
    };

    // Dummy public key bytes (ML-DSA-44 public key length = 1312)
    let pk = PkBytes([3u8; 1312]);
    let signer_id = signer_id_from_pk(&pk);

    // Dummy signature bytes (ML-DSA-44 signature length = 2420)
    let sig = SigBytes([0u8; 2420]);

    SignedConsensusMsg {
        core,
        signer_id,
        signer_pk: pk,
        sig,
        height,
        round,
    }
}

#[test]
fn wire_envelope_roundtrip() {
    // happy path for each kind
    for kind in [MsgKind::Proposal, MsgKind::PreVote, MsgKind::PreCommit] {
        let msg = dummy_signed_msg(kind);
        let env: GossipEnvelope = encode_envelope(&msg);
        let decoded = decode_envelope(&env).expect("decode must succeed");
        assert_eq!(kind_of(&decoded.core), kind);
        assert_eq!(decoded.height, 1);
    }

    // mismatch case: corrupt kind byte -> should error
    let msg = dummy_signed_msg(MsgKind::Proposal);
    let mut env = encode_envelope(&msg);
    env.kind = 99; // invalid kind tag
    let err = decode_envelope(&env).unwrap_err();
    assert!(err.contains("mismatch") || err.contains("unknown"));
}
