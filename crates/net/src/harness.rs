#![cfg(feature = "pq44-runtime")]
//! T16.3: Minimal multi-node harness built on the in-process NetworkSimulator.
//! This file provides thin helpers to send/receive SignedConsensusMsg over the simulator.

use crate::consensus_wire::*;
use crate::sim::NetworkSimulator;
use eezo_ledger::SignedConsensusMsg;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

pub type NodeId = u32;

pub struct SingleNodeHandle {
    pub id: NodeId,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl SingleNodeHandle {
    /// Receive a SignedConsensusMsg with a timeout. Returns None on timeout or decode error.
    pub fn recv_msg(&self, timeout: Duration) -> Option<SignedConsensusMsg> {
        let bytes = self.rx.recv_timeout(timeout).ok()?;
        let env: GossipEnvelope = bincode::deserialize(&bytes).ok()?;
        decode_envelope(&env).ok()
    }
}

pub struct MultiNodeHarness {
    nodes: HashMap<NodeId, SingleNodeHandle>,
}

impl MultiNodeHarness {
    /// Create handles for each node id, registering inboxes in the simulator.
    pub fn new(sim: &mut NetworkSimulator, ids: &[NodeId]) -> Self {
        let mut nodes = HashMap::new();
        for &id in ids {
            let rx = sim.add_node(id);
            nodes.insert(id, SingleNodeHandle { id, rx });
        }
        Self { nodes }
    }

    /// Get a reference to a node handle.
    pub fn node(&self, id: NodeId) -> &SingleNodeHandle {
        &self.nodes[&id]
    }

    /// Encode and send a consensus message from -> to via the simulator.
    /// Returns true if the receiver accepted the bytes.
    pub fn send_msg(
        &self,
        sim: &NetworkSimulator,
        from: NodeId,
        to: NodeId,
        msg: &SignedConsensusMsg,
    ) -> bool {
        let env = encode_envelope(msg);
        let bytes = bincode::serialize(&env).expect("encode envelope");
        sim.send(from, to, bytes)
    }
}