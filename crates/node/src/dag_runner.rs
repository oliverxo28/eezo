// crates/node/src/dag_runner.rs
// T56.0–T56.5 — DAG vertex model + in-memory DAG store (skeleton, no tx flow yet).
// T58.0 — Store shadow payload in DAG vertices instead of just logging
// T58.1 — Add /dag/vertex/{id} debug endpoint

#![cfg(feature = "pq44-runtime")]

use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

use eezo_ledger::consensus::SingleNode;
use eezo_ledger::tx_types::HasTxHash;
use eezo_ledger::SignedTx;
use crate::mempool::{SharedMempool, TxHash};

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

/// t57.0: build a "shadow" dag payload from the current mempool view.
///
/// this is read-only: it does not remove txs, does not affect ordering,
/// and is not wired into the live dag runner yet. it exists so later
/// tasks can call it from the dag loop in a safe way.
#[allow(dead_code)]
pub async fn dag_shadow_payload_from_mempool(
    mempool: &SharedMempool,
    max_txs: usize,
) -> DagPayload {
    if max_txs == 0 {
        return DagPayload::Empty;
    }

    // sample up to max_txs hashes from the current mempool snapshot
    let hashes: Vec<TxHash> = mempool.sample_hashes(max_txs).await;

    if hashes.is_empty() {
        DagPayload::Empty
    } else {
        log::debug!(
            "dag shadow payload: sampled {} tx hashes for hypothetical vertex",
            hashes.len()
        );
        DagPayload::from_tx_hashes_raw(hashes)
    }
}

/// t56.7: debug-only helper to build a dag payload from real signed txs.
///
/// this is not wired into any live path yet (no /tx changes, no mempool
/// changes, no dag runner behaviour changes). it just gives us a concrete
/// function we can call later when we start feeding real txs into vertices.
#[allow(dead_code)]
pub fn build_dag_payload_from_signed_txs<I>(txs: I) -> DagPayload
where
    I: IntoIterator<Item = SignedTx>,
{
    DagPayload::from_hashed_txs(txs)
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

    /// Insert a new vertex with the given parents, round, height and payload.
    ///
    /// T62.x: payload is now supplied by the caller (e.g. tx hashes from mempool).
    pub async fn insert_vertex_with_payload(
        &self,
        parent_ids: Vec<DagVertexId>,
        round: u64,
        height: u64,
        payload: DagPayload,
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
            payload,
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

    /// Insert a new vertex with the given parents, round, and height.
    ///
    /// For callers that don't care about payload yet, this keeps the
    /// old behaviour of using an empty payload.
    pub async fn insert_vertex(
        &self,
        parent_ids: Vec<DagVertexId>,
        round: u64,
        height: u64,
    ) -> DagVertex {
        self
            .insert_vertex_with_payload(parent_ids, round, height, DagPayload::Empty)
            .await
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

    /// T58.1: Return a debug view of a single vertex, if it exists.
    pub async fn vertex_debug(&self, id: DagVertexId) -> Option<DagVertexDebug> {
        let inner = self.inner.lock().await;
        inner.vertices.get(&id).map(DagVertexDebug::from_vertex)
    }

    /// T59.0: build a synthetic "block candidate" view from a single vertex.
    pub async fn candidate_debug_for_vertex(
        &self,
        id: DagVertexId,
    ) -> Option<DagBlockCandidateDebug> {
        let inner = self.inner.lock().await;
        let v = inner.vertices.get(&id)?;

        let tx_hashes = match &v.payload {
            DagPayload::Empty => Vec::new(),
            DagPayload::TxHashes(ref refs) => {
                refs.iter().map(|r| hash_to_hex(&r.hash)).collect()
            }
        };

        Some(DagBlockCandidateDebug {
            vertex_id: v.meta.id.0,
            round: v.meta.round,
            height: v.meta.height,
            tx_hashes,
        })
    }

    /// T59.0: pick a "best-effort" latest candidate from current DAG tips.
    ///
    /// preference:
    ///   * if exactly one tip exists → use that tip
    ///   * if multiple tips → choose the one with the largest id
    ///   * if no tips but vertices exist → choose the vertex with the largest id
    pub async fn latest_candidate_debug(&self) -> Option<DagBlockCandidateDebug> {
        let inner = self.inner.lock().await;

        if inner.vertices.is_empty() {
            return None;
        }

        let chosen_id = if inner.tips.len() == 1 {
            *inner.tips.iter().next().unwrap()
        } else if !inner.tips.is_empty() {
            *inner.tips
                .iter()
                .max_by_key(|DagVertexId(id)| *id)
                .unwrap()
        } else {
            *inner
                .vertices
                .keys()
                .max_by_key(|DagVertexId(id)| *id)
                .unwrap()
        };

        let v = inner.vertices.get(&chosen_id)?;

        let tx_hashes = match &v.payload {
            DagPayload::Empty => Vec::new(),
            DagPayload::TxHashes(ref refs) => {
                refs.iter().map(|r| hash_to_hex(&r.hash)).collect()
            }
        };

        Some(DagBlockCandidateDebug {
            vertex_id: v.meta.id.0,
            round: v.meta.round,
            height: v.meta.height,
            tx_hashes,
        })
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
// T58.1: Debug vertex DTO for /dag/vertex/{id}
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, serde::Serialize)]
pub struct DagPayloadDebug {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hashes: Option<Vec<String>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DagVertexDebug {
    pub id: u64,
    pub round: u64,
    pub height: u64,
    pub parent_ids: Vec<u64>,
    pub created_at_unix: u64,
    pub payload: DagPayloadDebug,
}
/// T59.0: synthetic "block candidate" view derived from a single DAG vertex.
///
/// this is debug-only and not wired into real block production. it answers:
/// "if we built a block from this vertex, which tx hashes would it contain?"
#[derive(Clone, Debug, serde::Serialize)]
pub struct DagBlockCandidateDebug {
    pub vertex_id: u64,
    pub round: u64,
    pub height: u64,
    /// ordered list of tx hashes (hex "0x..." strings) from the vertex payload.
    pub tx_hashes: Vec<String>,
}

/// T62.0: decoded transaction info for block preview.
///
/// Contains a subset of human-readable fields decoded from a SignedTxEnvelope.
/// This is debug-only and does not change consensus or real block production.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DagBlockPreviewTx {
    pub hash: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub amount: Option<String>,
    pub fee: Option<String>,
    pub nonce: Option<u64>,
}

/// T62.0: synthetic "block preview" from the current DAG candidate + mempool.
///
/// This is debug-only and does NOT commit anything to the ledger.
/// It answers: "If we built a block from the current DAG candidate right now,
/// what would that block look like (with decoded tx fields)?"
#[derive(Debug, Clone, serde::Serialize)]
pub struct DagBlockPreview {
    pub vertex_id: u64,
    pub round: u64,
    pub height: u64,
    pub txs: Vec<DagBlockPreviewTx>,
}

impl DagPayloadDebug {
    fn from_payload(payload: &DagPayload) -> Self {
        match payload {
            DagPayload::Empty => DagPayloadDebug {
                kind: "empty".to_string(),
                tx_hashes: None,
            },
            DagPayload::TxHashes(ref refs) => {
                let hashes = refs.iter().map(|r| hash_to_hex(&r.hash)).collect();
                DagPayloadDebug {
                    kind: "tx_hashes".to_string(),
                    tx_hashes: Some(hashes),
                }
            }
        }
    }
}

impl DagVertexDebug {
    fn from_vertex(v: &DagVertex) -> Self {
        DagVertexDebug {
            id: v.meta.id.0,
            round: v.meta.round,
            height: v.meta.height,
            parent_ids: v.meta.parent_ids.iter().map(|p| p.0).collect(),
            created_at_unix: v.meta.created_at_unix,
            payload: DagPayloadDebug::from_payload(&v.payload),
        }
    }
}

/// Hex-encode a 32-byte hash as `0x...` for debug JSON.
fn hash_to_hex(hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(2 + 64);
    s.push_str("0x");
    for b in hash {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

// -----------------------------------------------------------------------------
// T62.0: SignedTxEnvelope decoding for block preview
// -----------------------------------------------------------------------------

/// Minimal mirror of the TransferTx type from main.rs for decoding.
/// Only used internally for block preview deserialization.
#[derive(serde::Deserialize)]
struct TransferTxPreview {
    from: String,
    to: String,
    amount: String,
    fee: String,
    nonce: String,
}

/// Minimal mirror of the SignedTxEnvelope type from main.rs for decoding.
/// Only used internally for block preview deserialization.
#[derive(serde::Deserialize)]
struct SignedTxEnvelopePreview {
    tx: TransferTxPreview,
}

/// Decode raw tx bytes into a DagBlockPreviewTx for the debug endpoint.
///
/// If decoding fails, returns an entry with only the hash filled in.
fn decode_tx_for_preview(hash: &[u8; 32], bytes: &[u8]) -> DagBlockPreviewTx {
    let hash_hex = hash_to_hex(hash);

    match serde_json::from_slice::<SignedTxEnvelopePreview>(bytes) {
        Ok(env) => {
            let nonce = env.tx.nonce.parse::<u64>().ok();
            DagBlockPreviewTx {
                hash: hash_hex,
                from: Some(env.tx.from),
                to: Some(env.tx.to),
                amount: Some(env.tx.amount),
                fee: Some(env.tx.fee),
                nonce,
            }
        }
        Err(_) => {
            // Decoding failed; return entry with only the hash
            DagBlockPreviewTx {
                hash: hash_hex,
                from: None,
                to: None,
                amount: None,
                fee: None,
                nonce: None,
            }
        }
    }
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
    // T57.2: mempool handle for shadow payload sampling
    mempool: crate::mempool::SharedMempool,
    // T57.2: max txs to sample for shadow payload logging
    shadow_max_txs: usize,
}

impl DagRunnerHandle {
    /// Spawn the DAG runner.
    ///
    /// For T56.x this uses a simple internal loop that periodically
    /// creates dummy vertices on top of current tips. No tx flow yet.
    pub fn spawn(
        node: SingleNode,
        mempool: crate::mempool::SharedMempool,
        shadow_max_txs: usize,
    ) -> Arc<Self> {
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
        let mempool_c = mempool.clone();

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

                // Every 50 ticks (~5s) create a vertex on top of current tips.
                if ticks % 50 == 0 {
                    let parents = dag_c.tips().await;

                    // T62.x: build payload from mempool (still read-only) and
                    // actually attach it to the vertex.
                    let payload = if shadow_max_txs > 0 {
                        dag_shadow_payload_from_mempool(&mempool_c, shadow_max_txs).await
                    } else {
                        DagPayload::Empty
                    };

                    let vtx = dag_c
                        .insert_vertex_with_payload(parents, round, height, payload)
                        .await;

                    // Keep the logging behaviour from T57.2, now based on the
                    // stored vertex payload.
                    if shadow_max_txs > 0 {
                        match &vtx.payload {
                            DagPayload::Empty => {
                                log::debug!(
                                    "dag: shadow payload empty at round={} height={}",
                                    vtx.meta.round,
                                    vtx.meta.height,
                                );
                            }
                            DagPayload::TxHashes(ref refs) => {
                                let first_prefix = refs
                                    .first()
                                    .map(|r| format!("{:02x?}", &r.hash[..4]));
                                log::debug!(
                                    "dag: vertex round={} height={} txs={} first_hash_prefix={:?}",
                                    vtx.meta.round,
                                    vtx.meta.height,
                                    refs.len(),
                                    first_prefix,
                                );
                            }
                        }
                    }

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
            mempool,
            shadow_max_txs,
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

    /// T58.1: Return a debug view of a single DAG vertex by numeric id.
    pub async fn vertex_debug(&self, id: u64) -> Option<DagVertexDebug> {
        let id = DagVertexId(id);
        self.dag.vertex_debug(id).await
    }

    /// T59.0: expose a debug-only synthetic "block candidate"
    /// built from the current DAG tip.
    pub async fn latest_candidate_debug(&self) -> Option<DagBlockCandidateDebug> {
        self.dag.latest_candidate_debug().await
    }

    /// T62.0: Build a synthetic "block preview" from the current DAG candidate.
    ///
    /// This does NOT commit anything; it only inspects the DAG + mempool.
    /// Returns None if there is no candidate or no tx hashes in the candidate.
    pub async fn block_preview(&self) -> Option<DagBlockPreview> {
        // 1) Get the current candidate from DAG (same as /dag/candidate)
        let candidate = self.dag.latest_candidate_debug().await?;

        // If there are no tx hashes in the candidate, return None
        if candidate.tx_hashes.is_empty() {
            return None;
        }

        // 2) Convert hex strings back to raw TxHash bytes for mempool lookup
        let hashes: Vec<crate::mempool::TxHash> = candidate
            .tx_hashes
            .iter()
            .filter_map(|hex_str| {
                let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
                let bytes = hex::decode(stripped).ok()?;
                if bytes.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            })
            .collect();

        if hashes.is_empty() {
            return None;
        }

        // 3) Fetch raw bytes from mempool for these hashes
        let raw_bytes = self.mempool.get_bytes_for_hashes(&hashes).await;

        // 4) Decode each tx and build DagBlockPreviewTx entries
        let txs: Vec<DagBlockPreviewTx> = raw_bytes
            .into_iter()
            .map(|(hash, bytes)| {
                decode_tx_for_preview(&hash, &bytes)
            })
            .collect();

        // If no txs were found in mempool (already drained), return None
        if txs.is_empty() {
            return None;
        }

        Some(DagBlockPreview {
            vertex_id: candidate.vertex_id,
            round: candidate.round,
            height: candidate.height,
            txs,
        })
    }
}


// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::{SharedMempool, Mempool, TxHash};
    use std::net::{IpAddr, Ipv4Addr};

    /// basic sanity check: empty store has no vertices or tips.
    #[tokio::test]
    async fn dag_store_starts_empty() {
        let store = DagStore::new();

        assert_eq!(store.len().await, 0);
        assert!(store.tips().await.is_empty());

        let snapshot = store.debug_snapshot().await;
        assert_eq!(snapshot.vertex_count, 0);
        assert!(snapshot.tips.is_empty());
        assert_eq!(snapshot.max_round, 0);
        assert_eq!(snapshot.max_height, 0);
    }

    /// inserting a root and then a child should update tips + max_round/height.
    #[tokio::test]
    async fn dag_store_inserts_update_tips_and_snapshot() {
        let store = DagStore::new();

        // insert a root vertex (no parents) at round=0, height=0
        let root = store
            .insert_vertex(Vec::new(), 0, 0)
            .await;
        assert_eq!(root.meta.id, DagVertexId(0));

        // after first insert: one vertex, tip is {0}
        assert_eq!(store.len().await, 1);
        let tips = store.tips().await;
        assert_eq!(tips, vec![DagVertexId(0)]);

        let snap1 = store.debug_snapshot().await;
        assert_eq!(snap1.vertex_count, 1);
        assert_eq!(snap1.tips, vec![0]);
        assert_eq!(snap1.max_round, 0);
        assert_eq!(snap1.max_height, 0);

        // insert a child on top of the root at round=1, height=1
        let child = store
            .insert_vertex(vec![root.meta.id], 1, 1)
            .await;
        assert_eq!(child.meta.id, DagVertexId(1));

        // after second insert: two vertices, tip is now {1}
        assert_eq!(store.len().await, 2);
        let tips2 = store.tips().await;
        assert_eq!(tips2, vec![DagVertexId(1)]);

        let snap2 = store.debug_snapshot().await;
        assert_eq!(snap2.vertex_count, 2);
        assert_eq!(snap2.tips, vec![1]);
        assert_eq!(snap2.max_round, 1);
        assert_eq!(snap2.max_height, 1);
    }

    /// dag payload helpers should construct TxHashes payload correctly from raw hashes.
    #[test]
    fn dag_payload_from_tx_hashes_raw() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];

        let payload = DagPayload::from_tx_hashes_raw(vec![h1, h2]);

        match payload {
            DagPayload::Empty => panic!("expected TxHashes payload, got Empty"),
            DagPayload::TxHashes(ref refs) => {
                assert_eq!(refs.len(), 2);
                assert_eq!(refs[0].hash, h1);
                assert_eq!(refs[1].hash, h2);
            }
        }
    }

    /// dag payload helpers should construct TxHashes payload correctly from DagTxRef values.
    #[test]
    fn dag_payload_from_tx_refs() {
        let r1 = DagTxRef::new([3u8; 32]);
        let r2 = DagTxRef::new([4u8; 32]);

        let payload = DagPayload::from_tx_refs(vec![r1, r2]);

        match payload {
            DagPayload::Empty => panic!("expected TxHashes payload, got Empty"),
            DagPayload::TxHashes(ref refs) => {
                assert_eq!(refs.len(), 2);
                assert_eq!(refs[0].hash, r1.hash);
                assert_eq!(refs[1].hash, r2.hash);
            }
        }
    }

    /// dag payload helper should work with any type implementing HasTxHash.
    #[test]
    fn dag_payload_from_hashed_txs() {
        #[derive(Clone)]
        struct DummyTx {
            hash: [u8; 32],
        }

        impl HasTxHash for DummyTx {
            fn tx_hash_bytes(&self) -> [u8; 32] {
                self.hash
            }
        }

        let t1 = DummyTx { hash: [5u8; 32] };
        let t2 = DummyTx { hash: [6u8; 32] };

        let payload = DagPayload::from_hashed_txs(vec![t1, t2]);

        match payload {
            DagPayload::Empty => panic!("expected TxHashes payload, got Empty"),
            DagPayload::TxHashes(ref refs) => {
                assert_eq!(refs.len(), 2);
                assert_eq!(refs[0].hash, [5u8; 32]);
                assert_eq!(refs[1].hash, [6u8; 32]);
            }
        }
    }

    /// T58.1: test debug vertex serialization
    #[tokio::test]
    async fn dag_vertex_debug_serialization() {
        let store = DagStore::new();

        // Insert a vertex with TxHashes payload
        let tx_hashes = vec![[1u8; 32], [2u8; 32]];
        let payload = DagPayload::from_tx_hashes_raw(tx_hashes.clone());
        let vertex = store
            .insert_vertex_with_payload(vec![], 1, 2, payload)
            .await;

        // Get debug view
        let debug_view = store.vertex_debug(vertex.meta.id).await.unwrap();

        assert_eq!(debug_view.id, 0);
        assert_eq!(debug_view.round, 1);
        assert_eq!(debug_view.height, 2);
        assert_eq!(debug_view.parent_ids, Vec::<u64>::new());
        assert_eq!(debug_view.payload.kind, "tx_hashes");
        assert_eq!(debug_view.payload.tx_hashes.unwrap().len(), 2);
    }

    /// simple helper to build a TxHash from a u8 tag, for tests.
    fn h(tag: u8) -> TxHash {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes
    }

    #[tokio::test]
    async fn dag_shadow_payload_empty_when_mempool_empty() {
        // small mempool config: len=4, bytes cap large, trivial rate limits
        let mempool = SharedMempool::new(Mempool::new(
            4,
            1024 * 1024,
            100,
            600,
        ));

        // no txs submitted yet
        let payload = dag_shadow_payload_from_mempool(&mempool, 10).await;

        match payload {
            DagPayload::Empty => {}
            DagPayload::TxHashes(_) => {
                panic!("expected Empty payload for empty mempool");
            }
        }
    }

    #[tokio::test]
    async fn dag_shadow_payload_samples_hashes_from_mempool() {
        let mempool = SharedMempool::new(Mempool::new(
            8,
            1024 * 1024,
            100,
            600,
        ));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // submit three dummy txs with distinct hashes
        mempool.submit(ip, h(1), vec![0u8; 10]).await.unwrap();
        mempool.submit(ip, h(2), vec![0u8; 10]).await.unwrap();
        mempool.submit(ip, h(3), vec![0u8; 10]).await.unwrap();

        // ask for at most 2 hashes
        let payload = dag_shadow_payload_from_mempool(&mempool, 2).await;

        match payload {
            DagPayload::Empty => {
                panic!("expected TxHashes payload, got Empty");
            }
            DagPayload::TxHashes(ref refs) => {
                // we asked for 2; we should get at most 2
                assert!(refs.len() <= 2);
                assert!(refs.len() >= 1);

                // the first hash should be the earliest submitted (h(1))
                assert_eq!(refs[0].hash, h(1));
            }
        }

        // mempool is read-only: still has 3 entries
        assert_eq!(mempool.len().await, 3);
    }

    /// T62.0: test decode_tx_for_preview with valid JSON
    #[test]
    fn decode_tx_for_preview_valid_envelope() {
        let hash = h(42);
        let envelope_json = r#"{
            "tx": {
                "from": "0x1234",
                "to": "0x5678",
                "amount": "1000",
                "fee": "10",
                "nonce": "5",
                "chain_id": "0x01"
            },
            "pubkey": "",
            "sig": ""
        }"#;
        let result = decode_tx_for_preview(&hash, envelope_json.as_bytes());

        assert_eq!(result.hash, hash_to_hex(&hash));
        assert_eq!(result.from, Some("0x1234".to_string()));
        assert_eq!(result.to, Some("0x5678".to_string()));
        assert_eq!(result.amount, Some("1000".to_string()));
        assert_eq!(result.fee, Some("10".to_string()));
        assert_eq!(result.nonce, Some(5));
    }

    /// T62.0: test decode_tx_for_preview with invalid JSON
    #[test]
    fn decode_tx_for_preview_invalid_envelope() {
        let hash = h(99);
        let invalid_json = b"not valid json";
        let result = decode_tx_for_preview(&hash, invalid_json);

        // Should return entry with only hash filled
        assert_eq!(result.hash, hash_to_hex(&hash));
        assert!(result.from.is_none());
        assert!(result.to.is_none());
        assert!(result.amount.is_none());
        assert!(result.fee.is_none());
        assert!(result.nonce.is_none());
    }
}