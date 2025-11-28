// crates/node/src/dag_runner.rs
// T56.0–T56.5 — DAG vertex model + in-memory DAG store (skeleton, no tx flow yet).

#![cfg(feature = "pq44-runtime")]

use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use eezo_ledger::consensus::SingleNode;

// -----------------------------------------------------------------------------
// DAG vertex model
// -----------------------------------------------------------------------------

/// Unique identifier for a DAG vertex.
/// For now this is just a monotonically increasing counter local to the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DagVertexId(u64);

/// Metadata about a DAG vertex.
/// We keep this separate so later we can swap out payload handling without
/// changing the structural fields (round, parents, etc.).
#[derive(Debug, Clone)]
pub struct DagVertexMeta {
    /// Local identifier of this vertex.
    pub id: DagVertexId,
    /// Logical round (or time-step) of the DAG algorithm.
    pub round: u64,
    /// Logical height in the underlying ledger (placeholder for now).
    pub height: u64,
    /// Parent vertices this vertex directly references.
    pub parent_ids: Vec<DagVertexId>,
    /// Creation time (seconds since UNIX epoch).
    pub created_at_unix: u64,
}

/// T56.5: a lightweight reference to a transaction to be included in a
/// DAG vertex payload. For now this only carries the hash; later we could
/// add more fields (e.g. size, priority, etc.).
#[derive(Debug, Clone, Copy)]
pub struct DagTxRef {
    pub hash: [u8; 32],
}

impl DagTxRef {
    pub fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }
}

/// T56.5: trait for "things that have a tx hash".
/// We don't implement this here for any concrete type yet; that will be done
/// alongside ledger / mempool integration. For now it lets us define a clean
/// conversion helper from "real tx types" into DAG payloads.
pub trait HasTxHash {
    /// Return the canonical 32-byte transaction hash for this value.
    fn tx_hash_bytes(&self) -> [u8; 32];
}

/// Structured payload for a DAG vertex.
///
/// In T56.5 we still *do not* attach real tx payloads to live vertices; all
/// vertices are created with `DagPayload::Empty`. The TxHashes variant and
/// helpers below are here so that later tasks can start wiring real tx lists
/// into the DAG without touching this file again.
#[derive(Debug, Clone)]
pub enum DagPayload {
    /// No payload (placeholder, used for all vertices in T56.x).
    Empty,
    /// Ordered list of tx references (hash-only for now).
    TxHashes(Vec<DagTxRef>),
}

impl DagPayload {
    /// T56.5: build a TxHashes payload from raw 32-byte hashes.
    pub fn from_tx_hashes_raw<I>(hashes: I) -> Self
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let refs: Vec<DagTxRef> = hashes.into_iter().map(DagTxRef::new).collect();
        DagPayload::TxHashes(refs)
    }

    /// T56.5: build a TxHashes payload from DagTxRef values directly.
    pub fn from_tx_refs<I>(refs: I) -> Self
    where
        I: IntoIterator<Item = DagTxRef>,
    {
        DagPayload::TxHashes(refs.into_iter().collect())
    }

    /// T56.5: generic helper that can turn *any* tx-like type implementing
    /// HasTxHash into a TxHashes payload. This lets ledger/mempool code
    /// implement HasTxHash for their tx type and then call this helper
    /// without adding more coupling here.
    pub fn from_hashed_txs<I, T>(txs: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: HasTxHash,
    {
        let refs: Vec<DagTxRef> = txs
            .into_iter()
            .map(|tx| DagTxRef::new(tx.tx_hash_bytes()))
            .collect();
        DagPayload::TxHashes(refs)
    }
}

/// A DAG vertex.
/// For T56.x we still do not attach real tx payloads; all vertices are created
/// with `DagPayload::Empty`. Later tasks will start populating this.
#[derive(Debug, Clone)]
pub struct DagVertex {
    pub meta: DagVertexMeta,
    pub payload: DagPayload,
}

// -----------------------------------------------------------------------------
// In-memory DAG store
// -----------------------------------------------------------------------------

#[derive(Debug, Default)]
struct DagStoreInner {
    vertices: HashMap<DagVertexId, DagVertex>,
    /// Reverse edges: parent -> children
    children: HashMap<DagVertexId, HashSet<DagVertexId>>,
    /// Current "tips" (vertices with no known children).
    tips: HashSet<DagVertexId>,
    /// Next id to assign.
    next_id: u64,
    /// T56.3: track maximum round and height observed so far.
    max_round: u64,
    max_height: u64,
}

/// Minimal, in-memory DAG store.
///
/// This is intentionally simple and in-proc only for now:
/// - No persistence
/// - No network gossip
/// - No pruning
///
/// It gives us a clean place to plug in real DAG logic later without touching
/// the rest of the node.
#[derive(Debug, Default)]
pub struct DagStore {
    inner: Mutex<DagStoreInner>,
}

impl DagStore {
    /// Create an empty DAG store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DagStoreInner::default()),
        }
    }

    /// Insert a new vertex with the given parents, round, and height.
    ///
    /// For T56.x this uses an empty payload and returns the constructed vertex.
    pub async fn insert_vertex(
        &self,
        parent_ids: Vec<DagVertexId>,
        round: u64,
        height: u64,
    ) -> DagVertex {
        let mut inner = self.inner.lock().await;

        let id = DagVertexId(inner.next_id);
        inner.next_id = inner.next_id.saturating_add(1);

        let created_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let vertex = DagVertex {
            meta: DagVertexMeta {
                id,
                round,
                height,
                parent_ids: parent_ids.clone(),
                created_at_unix,
            },
            // T56.4: all vertices use an empty payload for now.
            payload: DagPayload::Empty,
        };

        // Insert vertex.
        inner.vertices.insert(id, vertex.clone());

        // Maintain tips and children maps.
        if parent_ids.is_empty() && inner.vertices.len() == 1 {
            // First vertex (genesis-like) – just treat it as a tip.
            inner.tips.insert(id);
        } else {
            for parent in &parent_ids {
                // Parent cannot be a tip anymore if it has a child.
                inner.tips.remove(parent);
                inner
                    .children
                    .entry(*parent)
                    .or_insert_with(HashSet::new)
                    .insert(id);
            }
            // New vertex is always a tip until it gets children.
            inner.tips.insert(id);
        }

        // T56.3: track max round / height observed so far.
        inner.max_round = inner.max_round.max(round);
        inner.max_height = inner.max_height.max(height);

        // Update DAG structure + observability metrics.
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::{
                EEZO_DAG_HEIGHT_MAX,
                EEZO_DAG_ROUND_MAX,
                EEZO_DAG_TIPS_CURRENT,
                EEZO_DAG_VERTICES_CURRENT,
                EEZO_DAG_VERTICES_TOTAL,
            };

            EEZO_DAG_VERTICES_TOTAL.inc();
            EEZO_DAG_VERTICES_CURRENT.set(inner.vertices.len() as i64);
            EEZO_DAG_TIPS_CURRENT.set(inner.tips.len() as i64);
            EEZO_DAG_ROUND_MAX.set(inner.max_round as i64);
            EEZO_DAG_HEIGHT_MAX.set(inner.max_height as i64);
        }

        vertex
    }

    /// Get a vertex by id, if present.
    pub async fn get_vertex(&self, id: DagVertexId) -> Option<DagVertex> {
        let inner = self.inner.lock().await;
        inner.vertices.get(&id).cloned()
    }

    /// Return the current set of tips.
    pub async fn tips(&self) -> Vec<DagVertexId> {
        let inner = self.inner.lock().await;
        inner.tips.iter().copied().collect()
    }

    /// Total number of vertices stored.
    pub async fn len(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.vertices.len()
    }

    /// T56.1: compact snapshot for `/dag/debug`.
    pub async fn debug_snapshot(&self) -> DagDebugSnapshot {
        let inner = self.inner.lock().await;

        let vertex_count = inner.vertices.len();
        let tips: Vec<u64> = inner
            .tips
            .iter()
            .map(|DagVertexId(id)| *id)
            .collect();

        DagDebugSnapshot {
            vertex_count,
            tips,
            max_round: inner.max_round,
            max_height: inner.max_height,
        }
    }
}

// -----------------------------------------------------------------------------
// Debug snapshot DTO
// -----------------------------------------------------------------------------

/// Small, serializable-friendly view of the DAG for `/dag/debug`.
#[derive(Debug, Clone)]
pub struct DagDebugSnapshot {
    pub vertex_count: usize,
    /// Raw vertex ids of current tips.
    pub tips: Vec<u64>,
    /// T56.3: observability of DAG logical progression.
    pub max_round: u64,
    pub max_height: u64,
}

// -----------------------------------------------------------------------------
// DAG runner handle + status
// -----------------------------------------------------------------------------

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
    /// In-memory DAG store owned by this runner.
    dag: Arc<DagStore>,
    join: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DagRunnerHandle {
    /// Spawn the DAG runner.
    ///
    /// For T56.x this uses a simple internal loop that periodically
    /// creates dummy vertices on top of current tips. No tx flow yet.
    pub fn spawn(node: SingleNode) -> Arc<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let node = Arc::new(Mutex::new(node));
        let dag = Arc::new(DagStore::new());

        // T55.3: metrics – record that a DAG runner is active
        #[cfg(feature = "metrics")]
        {
            crate::metrics::EEZO_DAG_RUNNER_STATE.set(2); // running
            crate::metrics::EEZO_DAG_RUNNER_RESTARTS_TOTAL.inc();
        }

        let stop_c = Arc::clone(&stop);
        let node_c = Arc::clone(&node);
        let dag_c = Arc::clone(&dag);

        let join_handle = tokio::spawn(async move {
            // Placeholder: we keep the node handle so later we can drive real
            // ledger commits based on DAG ordering.
            let _ = node_c; // avoid unused-variable warning for now

            log::info!("dag: runner task started (T56.x skeleton)");

            let mut ticks: u64 = 0;
            let mut round: u64 = 0;
            let mut height: u64 = 0;

            // Later T56.x tasks will replace this with the actual DAG event
            // loop (vertex production, ordering, commit to ledger, etc.).
            while !stop_c.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                ticks = ticks.saturating_add(1);

                // Every 50 ticks (~5s) create a dummy vertex on top of current tips.
                if ticks % 50 == 0 {
                    let parents = dag_c.tips().await;
                    let vtx = dag_c.insert_vertex(parents, round, height).await;
                    round = round.saturating_add(1);
                    height = height.saturating_add(1);

                    let snapshot = dag_c.debug_snapshot().await;

                    log::debug!(
                        "dag: heartbeat ticks={} stop_flag={} vertices={} last_vertex_round={} tips={:?} max_round={} max_height={}",
                        ticks,
                        stop_c.load(Ordering::Relaxed),
                        snapshot.vertex_count,
                        vtx.meta.round,
                        snapshot.tips,
                        snapshot.max_round,
                        snapshot.max_height,
                    );
                }
            }

            log::info!("dag: runner task stopping after {} ticks", ticks);
        });

        Arc::new(Self {
            stop,
            node,
            dag,
            join: Mutex::new(Some(join_handle)),
        })
    }

    /// Signal the DAG runner to stop. (Synchronous, returns ())
    pub fn stop(&self) {
        log::info!("dag: stop() requested");
        self.stop.store(true, Ordering::Relaxed);

        // T55.3: metrics – mark runner as disabled
        #[cfg(feature = "metrics")]
        {
            crate::metrics::EEZO_DAG_RUNNER_STATE.set(1); // disabled
        }
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

    /// T56.1: expose a compact debug snapshot for `/dag/debug`.
    pub async fn debug_snapshot(&self) -> DagDebugSnapshot {
        self.dag.debug_snapshot().await
    }
}
