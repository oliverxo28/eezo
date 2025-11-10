#![cfg(feature = "t16-sim")]

use eezo_net::harness::MultiNodeHarness;
use eezo_net::sim::NetworkSimulator;
use std::time::Duration;

// Bring in the canonical consensus types from ledger.
use eezo_ledger::consensus::{
    kind_of, signer_id_from_pk, ConsensusMsgCore, MsgKind, PkBytes, PreCommit, PreVote, Proposal,
    SigBytes, SignedConsensusMsg,
};

/// Build a minimal, syntactically valid signed consensus message for wire tests.
/// Signature and PK are dummy; we are not performing crypto verification here.
fn dummy_signed(kind: MsgKind, height: u64, round: u32, block: [u8; 32]) -> SignedConsensusMsg {
    let core = match kind {
        MsgKind::Proposal => ConsensusMsgCore::Proposal(Proposal {
            height,
            round,
            block_id: block,
        }),
        MsgKind::PreVote => ConsensusMsgCore::PreVote(PreVote {
            height,
            round,
            block_id: block,
        }),
        MsgKind::PreCommit => ConsensusMsgCore::PreCommit(PreCommit {
            height,
            round,
            block_id: block,
        }),
    };

    // ML-DSA-44 sizes for PK/Sig per your consensus types
    let pk = PkBytes([3u8; 1312]);
    let signer_id = signer_id_from_pk(&pk);
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
fn consensus_happy_path_smoke() {
    let mut sim = NetworkSimulator::new();
    sim.set_latency(Duration::from_millis(5));

    // 3-node harness
    let h = MultiNodeHarness::new(&mut sim, &[1, 2, 3]);

    // Height=1, round=0, deterministic proposer (node 1)
    let block = [7u8; 32];

    // 1) Proposer sends Proposal to others
    let prop = dummy_signed(MsgKind::Proposal, 1, 0, block);
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
    assert!(matches!(kind_of(&p2.core), MsgKind::Proposal));
    assert!(matches!(kind_of(&p3.core), MsgKind::Proposal));

    // 2) They send PreVotes back to everyone
    let pv2 = dummy_signed(MsgKind::PreVote, 1, 0, block);
    let pv3 = dummy_signed(MsgKind::PreVote, 1, 0, block);
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
    assert!(matches!(kind_of(&r1_a.core), MsgKind::PreVote));
    assert!(matches!(kind_of(&r1_b.core), MsgKind::PreVote));

    // 3) PreCommits: proposer + others (simulating 2/3 lock)
    let pc1 = dummy_signed(MsgKind::PreCommit, 1, 0, block);
    let pc2 = dummy_signed(MsgKind::PreCommit, 1, 0, block);
    let pc3 = dummy_signed(MsgKind::PreCommit, 1, 0, block);
    // broadcast precommits
    assert!(h.send_msg(&sim, 1, 2, &pc1));
    assert!(h.send_msg(&sim, 1, 3, &pc1));
    assert!(h.send_msg(&sim, 2, 1, &pc2));
    assert!(h.send_msg(&sim, 3, 1, &pc3));

    // Collect a few messages for each node and check PreCommit quorum.
    let mut got_pc2 = false;
    for _ in 0..3 {
        if let Some(msg) = h.node(2).recv_msg(Duration::from_millis(200)) {
            if matches!(kind_of(&msg.core), MsgKind::PreCommit) {
                got_pc2 = true;
                break;
            }
        }
    }
    assert!(got_pc2, "node2 must eventually get a PreCommit");

    let mut got_pc3 = false;
    for _ in 0..3 {
        if let Some(msg) = h.node(3).recv_msg(Duration::from_millis(200)) {
            if matches!(kind_of(&msg.core), MsgKind::PreCommit) {
                got_pc3 = true;
                break;
            }
        }
    }
    assert!(got_pc3, "node3 must eventually get a PreCommit");

    let mut pc_count_node1 = 0;
    for _ in 0..5 {
        if let Some(msg) = h.node(1).recv_msg(Duration::from_millis(200)) {
            if matches!(kind_of(&msg.core), MsgKind::PreCommit) {
                pc_count_node1 += 1;
            }
        }
    }
    // require quorum: node1 must see at least 2 PreCommits
    assert!(pc_count_node1 >= 2, "node1 must see quorum of PreCommits");
}
