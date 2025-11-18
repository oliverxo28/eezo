#![cfg(feature = "t16-sim")]

use eezo_net::harness::MultiNodeHarness;
use eezo_net::sim::NetworkSimulator;
use std::time::Duration;

use eezo_ledger::{
    block::{BlockHeader, BlockId},
    cert_store::CertLookup,
    consensus_msg::{ConsensusMsg, Phase, Proposal, SignedConsensusMsg, ValidatorId, Vote},
};
use pqcrypto_mldsa::mldsa44::PublicKey;

/// Minimal dummy cert store for T16.4 sims (no real validation).
#[allow(dead_code)]
struct DummyCerts;
impl CertLookup for DummyCerts {
    fn public_key(&self, _signer: ValidatorId) -> Option<PublicKey> {
        None
    }
}

#[derive(Clone, Copy)]
enum MsgKind {
    Proposal,
    PreVote,
}

/// Build a syntactically valid signed consensus message (dummy PK/sig).
fn dummy_signed(kind: MsgKind, height: u64, view: u64, block_id: BlockId) -> SignedConsensusMsg {
    let msg = match kind {
        MsgKind::Proposal => ConsensusMsg::Proposal(Box::new(Proposal {
            header: BlockHeader {
                height,
                prev_hash: [0u8; 32],
                tx_root: [0u8; 32],
                #[cfg(feature = "eth-ssz")]
                tx_root_v2: [0u8; 32],
                fee_total: 0,
                tx_count: 0,
                timestamp_ms: 0,
                #[cfg(feature = "checkpoints")]
                qc_hash: [0u8; 32],
            },
            view,
            proposer: ValidatorId(0),
            justify: None,
        })),
        MsgKind::PreVote => ConsensusMsg::Vote(Vote {
            phase: Phase::Prepare,
            view,
            block_id,
            voter: ValidatorId(0),
        }),
    };

    SignedConsensusMsg {
        msg,
        sig: vec![],
        signer: ValidatorId(0),
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
    }
}

/// Byzantine: same signer sends two PreVotes for different blocks at same (h, r).
#[test]
fn byzantine_double_prevote() {
    let mut sim = NetworkSimulator::new();
    let h = MultiNodeHarness::new(&mut sim, &[1, 2, 3]);

    let block_a = BlockId([1u8; 32]);
    let block_b = BlockId([2u8; 32]);

    // Node 1 equivocates towards node 2
    let pv_a = dummy_signed(MsgKind::PreVote, 1, 0, block_a);
    let pv_b = dummy_signed(MsgKind::PreVote, 1, 0, block_b);

    assert!(h.send_msg(&sim, 1, 2, &pv_a));
    assert!(h.send_msg(&sim, 1, 2, &pv_b));

    let m1 = h
        .node(2)
        .recv_msg(Duration::from_millis(200))
        .expect("first prevote");
    let m2 = h
        .node(2)
        .recv_msg(Duration::from_millis(200))
        .expect("second prevote");

    // Both are PreVotes, but with different block_ids (equivocation signal).
    let bid1 = match m1.msg {
        ConsensusMsg::Vote(v) => v.block_id,
        _ => panic!("expected Vote"),
    };
    let bid2 = match m2.msg {
        ConsensusMsg::Vote(v) => v.block_id,
        _ => panic!("expected Vote"),
    };
    assert_ne!(
        bid1, bid2,
        "byzantine double prevote must carry different block ids"
    );
}

/// Partition halts propagation; healing resumes message flow.
#[test]
fn partition_and_heal() {
    let mut sim = NetworkSimulator::new();
    sim.set_latency(Duration::from_millis(5));
    let h = MultiNodeHarness::new(&mut sim, &[1, 2, 3]);

    let block = BlockId([9u8; 32]);
    let prop = dummy_signed(MsgKind::Proposal, 1, 0, block);

    // Partition {1} | {2,3}
    sim.set_partition(&[1], &[2, 3]);

    // Proposal blocked while partitioned
    let delivered = h.send_msg(&sim, 1, 2, &prop);
    assert!(!delivered, "delivery must fail across active partition");
    assert!(
        h.node(2).recv_msg(Duration::from_millis(50)).is_none(),
        "no message should arrive"
    );

    // Heal and resend
    sim.heal_partition();
    let delivered = h.send_msg(&sim, 1, 2, &prop);
    assert!(delivered, "delivery must succeed after healing");
    let recv = h
        .node(2)
        .recv_msg(Duration::from_millis(200))
        .expect("proposal after heal");
    assert!(matches!(recv.msg, ConsensusMsg::Proposal(_)));
}