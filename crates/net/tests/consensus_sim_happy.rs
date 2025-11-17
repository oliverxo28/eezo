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
    PreCommit,
}

/// Build a syntactically valid signed consensus message (dummy PK/sig).
fn dummy_signed(
    kind: MsgKind,
    height: u64,
    view: u64,
    block_id: BlockId,
    signer: ValidatorId,
) -> SignedConsensusMsg {
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
            proposer: signer,
            justify: None,
        })),
        MsgKind::PreVote => ConsensusMsg::Vote(Vote {
            phase: Phase::Prepare,
            view,
            block_id,
            voter: signer,
        }),
        MsgKind::PreCommit => ConsensusMsg::Vote(Vote {
            phase: Phase::PreCommit,
            view,
            block_id,
            voter: signer,
        }),
    };

    SignedConsensusMsg {
        msg,
        sig: vec![],
        signer,
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
    }
}

#[test]
fn consensus_happy_path_smoke() {
    let mut sim = NetworkSimulator::new();
    sim.set_latency(Duration::from_millis(5));

    // 3-node harness
    let h = MultiNodeHarness::new(&mut sim, &[1, 2, 3]);

    // Height=1, view=0, deterministic proposer (node 1)
    let block = BlockId([7u8; 32]);

    // 1) Proposer sends Proposal to others
    let prop = dummy_signed(MsgKind::Proposal, 1, 0, block, ValidatorId(0));
    assert!(h.send_msg(&sim, 1, 2, &prop));
    assert!(h.send_msg(&sim, 1, 3, &prop));

    // Nodes 2 and 3 receive Proposal
    let p2 = h
        .node(2)
        .recv_msg(Duration::from_millis(200))
        .expect("node2 got proposal");
    let p3 = h
        .node(3)
        .recv_msg(Duration::from_millis(200))
        .expect("node3 got proposal");
    assert!(matches!(p2.msg, ConsensusMsg::Proposal(_)));
    assert!(matches!(p3.msg, ConsensusMsg::Proposal(_)));

    // 2) They send PreVotes back to everyone
    let pv2 = dummy_signed(MsgKind::PreVote, 1, 0, block, ValidatorId(1));
    let pv3 = dummy_signed(MsgKind::PreVote, 1, 0, block, ValidatorId(2));
    assert!(h.send_msg(&sim, 2, 1, &pv2));
    assert!(h.send_msg(&sim, 2, 3, &pv2));
    assert!(h.send_msg(&sim, 3, 1, &pv3));
    assert!(h.send_msg(&sim, 3, 2, &pv3));

    // Node 1 aggregates PreVotes (just receive at least two)
    let r1_a = h
        .node(1)
        .recv_msg(Duration::from_millis(200))
        .expect("node1 got prevote a");
    let r1_b = h
        .node(1)
        .recv_msg(Duration::from_millis(200))
        .expect("node1 got prevote b");
    assert!(matches!(r1_a.msg, ConsensusMsg::Vote(v) if v.phase == Phase::Prepare));
    assert!(matches!(r1_b.msg, ConsensusMsg::Vote(v) if v.phase == Phase::Prepare));

    // 3) PreCommits: proposer + others (simulating 2/3 lock)
    let pc1 = dummy_signed(MsgKind::PreCommit, 1, 0, block, ValidatorId(0));
    let pc2 = dummy_signed(MsgKind::PreCommit, 1, 0, block, ValidatorId(1));
    let pc3 = dummy_signed(MsgKind::PreCommit, 1, 0, block, ValidatorId(2));
    // broadcast precommits
    assert!(h.send_msg(&sim, 1, 2, &pc1));
    assert!(h.send_msg(&sim, 1, 3, &pc1));
    assert!(h.send_msg(&sim, 2, 1, &pc2));
    assert!(h.send_msg(&sim, 3, 1, &pc3));

    // Collect a few messages for each node and check PreCommit quorum.
    let mut got_pc2 = false;
    for _ in 0..3 {
        if let Some(msg) = h.node(2).recv_msg(Duration::from_millis(200)) {
            if matches!(msg.msg, ConsensusMsg::Vote(v) if v.phase == Phase::PreCommit) {
                got_pc2 = true;
                break;
            }
        }
    }
    assert!(got_pc2, "node2 must eventually get a PreCommit");

    let mut got_pc3 = false;
    for _ in 0..3 {
        if let Some(msg) = h.node(3).recv_msg(Duration::from_millis(200)) {
            if matches!(msg.msg, ConsensusMsg::Vote(v) if v.phase == Phase::PreCommit) {
                got_pc3 = true;
                break;
            }
        }
    }
    assert!(got_pc3, "node3 must eventually get a PreCommit");

    let mut pc_count_node1 = 0;
    for _ in 0..5 {
        if let Some(msg) = h.node(1).recv_msg(Duration::from_millis(200)) {
            if matches!(msg.msg, ConsensusMsg::Vote(v) if v.phase == Phase::PreCommit) {
                pc_count_node1 += 1;
            }
        }
    }
    // require quorum: node1 must see at least 2 PreCommits
    assert!(pc_count_node1 >= 2, "node1 must see quorum of PreCommits");
}