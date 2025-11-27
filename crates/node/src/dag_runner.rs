// crates/node/src/dag_runner.rs
// T55.3 — minimal DAG runner skeleton on top of HotStuff baseline.
//
// This file does NOT implement real DAG consensus yet.
// It just provides a clean DagRunnerHandle + DagStatus that we can
// flesh out in later T55.x tasks.
//
// Important: this module is not wired into main.rs yet. The node
// still runs with the existing single-node / hotstuff-like runner.
//
// We keep it behind the same `pq44-runtime` feature gate as the
// rest of the consensus code so it only builds in that mode.

#![cfg(feature = "pq44-runtime")]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Mutex;

use eezo_ledger::consensus::SingleNode;

/// High-level status of the DAG runner.
///
/// For now this is just a placeholder. Later we can add more
/// detailed states (e.g. InitialSync, Working, Backoff, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagStatus {
    /// DAG consensus is not active / has been stopped.
    Disabled,
    /// DAG consensus background task is running.
    Running,
}

/// Handle to a background DAG runner task.
///
/// In T55.3 this is intentionally minimal: it just owns a stop flag,
/// a reference to the `SingleNode`, and a Tokio join handle. The
/// actual DAG logic will be introduced in later T55.x tasks.
pub struct DagRunnerHandle {
    stop: Arc<AtomicBool>,
    #[allow(dead_code)]
    node: Arc<Mutex<SingleNode>>,
    join: tokio::task::JoinHandle<()>,
}

impl DagRunnerHandle {
    /// Spawn a placeholder DAG runner.
    ///
    /// For T55.3 this does not implement ordering or DAG consensus.
    /// It simply keeps a background task alive until `stop()` is
    /// called. This lets us wire types and signatures without
    /// changing behaviour.
    pub fn spawn(node: SingleNode) -> Arc<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let node = Arc::new(Mutex::new(node));

        let stop_c = Arc::clone(&stop);
        let node_c = Arc::clone(&node);

        let join = tokio::spawn(async move {
            // Placeholder loop: we hold onto `node_c` so that later
            // we can reuse this structure to drive real DAG logic.
            let _ = node_c; // avoid unused-variable warning for now

            // Later T55.x tasks will replace this with the actual
            // DAG event loop (vertex production, ordering, etc.).
            while !stop_c.load(Ordering::Relaxed) {
                // Small sleep to avoid a busy loop.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });

        Arc::new(Self { stop, node, join })
    }

    /// Signal the DAG runner to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Await completion of the background task.
    pub async fn join(self: Arc<Self>) {
        let _ = self.join.await;
    }

    /// Report the current (coarse) status.
    pub fn status(&self) -> DagStatus {
        if self.stop.load(Ordering::Relaxed) {
            DagStatus::Disabled
        } else {
            DagStatus::Running
        }
    }
}
