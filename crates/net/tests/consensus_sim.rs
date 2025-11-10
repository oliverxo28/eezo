#![cfg(feature = "t16-sim")]

use eezo_net::harness::MultiNodeHarness;
use eezo_net::sim::NetworkSimulator;
use std::time::Duration;

use eezo_ledger::cert_store::{CertLookup, ValidatedPk};
use eezo_ledger::consensus::{
    kind_of, signer_id_from_pk, ConsensusMsgCore, MsgKind, PkBytes, PreCommit, PreVote, Proposal,
    SigBytes, SignedConsensusMsg,
};

/// Minimal dummy cert store for T16.4 sims (no real validation).
struct DummyCerts;
impl CertLookup for DummyCerts {
    fn get_pk(&self, _signer_id: &[u8; 20], _at: u64) -> Option<ValidatedPk> {
        None
    }
}

/// Build a syntactically valid signed consensus message (dummy PK/sig).
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
    // ML-DSA-44 sizes that your types expect
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

/// Byzantine: same signer sends two PreVotes for different blocks at same (h, r).
#[test]
fn byzantine_double_prevote() {
    let mut sim = NetworkSimulator::new();
    let h = MultiNodeHarness::new(&mut sim, &[1, 2, 3]);

    let block_a = [1u8; 32];
    let block_b = [2u8; 32];

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
    let bid1 = match m1.core {
        ConsensusMsgCore::PreVote(p) => p.block_id,
        _ => panic!("expected PreVote"),
    };
    let bid2 = match m2.core {
        ConsensusMsgCore::PreVote(p) => p.block_id,
        _ => panic!("expected PreVote"),
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

    let block = [9u8; 32];
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
    assert!(matches!(kind_of(&recv.core), MsgKind::Proposal));
}
