// crates/node/src/dag_runner.rs
// T55.3 — minimal DAG runner skeleton on top of HotStuff baseline.

#![cfg(feature = "pq44-runtime")]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Mutex;

use eezo_ledger::consensus::SingleNode;

/// High-level status of the DAG runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagStatus {
    /// DAG consensus is not active / has been stopped.
    Disabled,
    /// DAG consensus background task is running.
    Running,
}

/// Handle to a background DAG runner task.
pub struct DagRunnerHandle {
    stop: Arc<AtomicBool>,
    #[allow(dead_code)]
    node: Arc<Mutex<SingleNode>>,
    join: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DagRunnerHandle {
    /// Spawn a placeholder DAG runner.
    pub fn spawn(node: SingleNode) -> Arc<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let node = Arc::new(Mutex::new(node));

        let stop_c = Arc::clone(&stop);
        let node_c = Arc::clone(&node);

        let join_handle = tokio::spawn(async move {
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

        Arc::new(Self {
            stop,
            node,
            join: Mutex::new(Some(join_handle)),
        })
    }

    /// Signal the DAG runner to stop. (Synchronous, returns ())
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Await completion of the background task.
    pub async fn join(self: Arc<Self>) {
        // Take the JoinHandle once, then await it
        if let Some(handle) = self.join.lock().await.take() {
            let _ = handle.await;
        }
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