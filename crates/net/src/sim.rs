//! T16.2: Deterministic in-process network simulator (no async runtime).

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub type NodeId = u32;

#[derive(Default)]
pub struct NetworkSimulator {
    latency: Duration,
    // simple 2-way partition: messages across A<->B are blocked
    part_a: HashSet<NodeId>,
    part_b: HashSet<NodeId>,
    has_partition: bool,
    inbox: HashMap<NodeId, mpsc::Sender<Vec<u8>>>,
}

impl NetworkSimulator {
    pub fn new() -> Self {
        Self {
            latency: Duration::from_millis(0),
            ..Default::default()
        }
    }

    /// Register a node with an inbox. Returns its receiver.
    pub fn add_node(&mut self, id: NodeId) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        self.inbox.insert(id, tx);
        rx
    }

    /// Set a fixed, uniform one-way latency for deliveries.
    pub fn set_latency(&mut self, d: Duration) {
        self.latency = d;
    }

    /// Define a partition A | B. Messages from A->B or B->A are blocked.
    pub fn set_partition(&mut self, a: &[NodeId], b: &[NodeId]) {
        self.part_a = a.iter().copied().collect();
        self.part_b = b.iter().copied().collect();
        self.has_partition = true;
    }

    /// Heal any active partition.
    pub fn heal_partition(&mut self) {
        self.part_a.clear();
        self.part_b.clear();
        self.has_partition = false;
    }

    fn is_blocked(&self, from: NodeId, to: NodeId) -> bool {
        if !self.has_partition {
            return false;
        }
        (self.part_a.contains(&from) && self.part_b.contains(&to))
            || (self.part_b.contains(&from) && self.part_a.contains(&to))
    }

    /// Deliver bytes from one node to another.
    /// Returns true iff the message was accepted into the receiver's inbox.
    pub fn send(&self, from: NodeId, to: NodeId, bytes: Vec<u8>) -> bool {
        if self.is_blocked(from, to) {
            return false;
        }
        let tx = match self.inbox.get(&to) {
            Some(tx) => tx.clone(),
            None => return false,
        };
        // Simulate latency deterministically.
        if self.latency > Duration::from_millis(0) {
            thread::sleep(self.latency);
        }
        tx.send(bytes).is_ok()
    }
}
