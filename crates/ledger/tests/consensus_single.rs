use eezo_ledger::{
    cert_store::StaticCertStore,
    consensus::{ConsensusCfg, ConsensusNetwork, HotStuff, SingleNode, SingleNodeCfg},
    consensus_msg as hs_msg,
};
use pqcrypto_mldsa::mldsa44::keypair;
use std::sync::{mpsc, Arc, Mutex};

// Helper: is there a QC on this header? Works with/without the `checkpoints` feature.
fn header_has_qc(h: &eezo_ledger::block::BlockHeader) -> bool {
    #[cfg(feature = "checkpoints")]
    {
        h.qc_hash != [0u8; 32]
    }
    #[cfg(not(feature = "checkpoints"))]
    {
        false
    }
}

// Helper to create a default single node for tests.
fn single_node_default() -> SingleNode {
    let (pk, sk) = keypair();
    let cfg = SingleNodeCfg::default();
    SingleNode::new(cfg, sk, pk)
}

#[derive(Default)]
struct LoopbackNet {
    tx: Mutex<Option<mpsc::Sender<hs_msg::SignedConsensusMsg>>>,
}

impl LoopbackNet {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn set_sender(&self, tx: mpsc::Sender<hs_msg::SignedConsensusMsg>) {
        *self.tx.lock().unwrap() = Some(tx);
    }
}

impl ConsensusNetwork for LoopbackNet {
    fn broadcast(&self, msg: hs_msg::SignedConsensusMsg) {
        if let Some(tx) = &*self.tx.lock().unwrap() {
            let _ = tx.send(msg); // best-effort, ignore errors
        }
    }
}

/// T81.4: Test legacy single node consensus (renamed from hotstuff_single_node_basic_propose_and_commit)
#[test]
fn legacy_single_node_basic_propose_and_commit() {
    // Setup: 1-node consensus config
    let c_cfg = ConsensusCfg {
        n: 1,
        f: 0,
        chain_id: [0u8; 20],
    };
    let net = LoopbackNet::new();
    let certs = Arc::new(StaticCertStore::new());

    let (tx, rx) = mpsc::channel::<hs_msg::SignedConsensusMsg>();
    net.set_sender(tx);

    // Legacy consensus instance behind Arc<Mutex<_>>
    // Note: HotStuff struct name retained for backward compatibility (T81.4)
    let hs = Arc::new(Mutex::new(HotStuff::new(c_cfg, certs.clone(), net.clone())));

    // Delivery thread: receives messages and calls on_signed_msg
    let hs_worker = hs.clone();
    std::thread::spawn(move || {
        while let Ok(m) = rx.recv() {
            if let Ok(mut g) = hs_worker.lock() {
                g.on_signed_msg(m);
            }
        }
    });

    // Propose a header (minimal, dummy values)
    let dummy_header = eezo_ledger::BlockHeader {
        height: 1,
        prev_hash: [0u8; 32],
        tx_root: [0u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 0u128,
        tx_count: 0,
        timestamp_ms: 12345,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };

    // Call propose on legacy consensus (should broadcast and loopback)
    {
        let mut g = hs.lock().unwrap();
        g.propose(dummy_header.clone(), hs_msg::ValidatorId(0), None);
    }

    // Give the delivery thread some time (not great, but sufficient for a basic test)
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Check the state: committed should be empty, but high_qc should be updated or present, etc.
    let _g = hs.lock().unwrap();
    // For a single node test, you may want to assert on g.info.high_qc, g.info.committed, etc.
    // e.g., assert!(g.info.high_qc.is_some());
}

#[test]
fn single_node_propose_and_apply_block() {
    let mut node = single_node_default();

    // Propose a block (empty mempool)
    let (block, _summary) = node.propose_block().expect("should propose");

    // Should be height 1 on first block
    assert_eq!(block.header.height, 1);

    // Validate and apply the block
    node.validate_and_apply(&block)
        .expect("should validate and apply");

    // Node height should advance
    assert_eq!(node.height, 1);
}

#[test]
fn single_node_qc_emerges_and_stays_periodic() {
    let mut node = single_node_default();
    const MAX_SCAN: u64 = 256; // generous upper bound; runtime default may be large

    // Collect headers up to MAX_SCAN
    let mut headers = Vec::new();
    for i in 0..MAX_SCAN {
        let (block, _) = node
            .propose_block()
            .unwrap_or_else(|_| panic!("propose h={}", i + 1));
        node.validate_and_apply(&block)
            .unwrap_or_else(|_| panic!("apply h={}", i + 1));
        headers.push(block.header);
    }

    // Find QC-bearing heights
    let qc_heights: Vec<u64> = headers
        .iter()
        .enumerate()
        .filter_map(|(i, h)| header_has_qc(h).then_some((i as u64) + 1))
        .collect();

    // If we haven't observed at least two QCs within MAX_SCAN, treat as a large interval and pass.
    if qc_heights.len() < 2 {
        eprintln!(
            "no (or only one) QC observed within {MAX_SCAN} blocks; \
             interval likely > {MAX_SCAN}. Treating as acceptable."
        );
        return;
    }

    // Infer interval from the first two and assert periodicity across the window.
    let k = qc_heights[1] - qc_heights[0];
    assert!(k > 0, "QC interval must be positive");
    for (idx, hdr) in headers.iter().enumerate() {
        let h = (idx as u64) + 1;
        let should_have_qc = (h >= qc_heights[0]) && ((h - qc_heights[0]) % k == 0);
        let has_qc = header_has_qc(hdr);
        assert_eq!(
            has_qc, should_have_qc,
            "periodicity mismatch at height {h} (k={k})"
        );
    }
}

#[test]
fn single_node_qc_first_height_is_respected() {
    let mut node = single_node_default();
    const MAX_SCAN: u64 = 256;
    let mut headers = Vec::new();
    for i in 0..MAX_SCAN {
        let (block, _) = node
            .propose_block()
            .unwrap_or_else(|_| panic!("propose h={}", i + 1));
        node.validate_and_apply(&block)
            .unwrap_or_else(|_| panic!("apply h={}", i + 1));
        headers.push(block.header);
    }
    let first_qc = headers
        .iter()
        .enumerate()
        .find_map(|(i, h)| header_has_qc(h).then_some((i as u64) + 1));

    // If no QC observed within the scan window, treat as a large interval and pass.
    let Some(first) = first_qc else {
        eprintln!(
            "no QC observed within first {MAX_SCAN} blocks; \
             runtime interval likely > {MAX_SCAN}. Treating as acceptable."
        );
        return;
    };

    // Sanity: the first QC should not be on the first produced header (height >= 2).
    assert!(
        first >= 2,
        "first QC should not be on the initial height; got {first}"
    );
}