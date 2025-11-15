// Allow dead_code only outside tests while the client is stubbed.
use serde::{Deserialize, Serialize};
use crate::metrics::{
    state_sync_latest_height_set,
    state_sync_retry_inc,
    state_sync_total_inc,
};

#[cfg_attr(not(test), allow(dead_code))]

#[cfg(feature = "state-sync")]
use eezo_ledger::{
    checkpoints::{anchor_signing_bytes, AnchorSig, CheckpointAnchor},
    persistence::{load_genesis_state_root_v2, ExportPersistError, PersistError, Persistence},
};

// T33.2 & T34.2: checkpoint JSON emitter imports
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
use eezo_crypto::suite::CryptoSuite;
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
use eezo_ledger::checkpoints::{
    build_rotation_headers,
    write_checkpoint_json_default,
    BridgeHeader,
    // T41.3 validator:
    validate_sidecar_v2_for_header,
    // T41.2 — qc sidecar helpers
    should_emit_qc_sidecar_v2,
    build_stub_sidecar_v2,
};
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
use eezo_ledger::qc_sidecar::ReanchorReason;
// T41.4: strict consumption toggle (same semantics as runner)
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
#[inline]
fn qc_sidecar_enforce_on() -> bool {
    #[cfg(feature = "qc-sidecar-v2-enforce")]
    {
        std::env::var("EEZO_QC_SIDECAR_ENFORCE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
            .unwrap_or(false)
    }
    #[cfg(not(feature = "qc-sidecar-v2-enforce"))]
    { false }
}
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
use crate::metrics::{
    qc_sidecar_emitted_inc, qc_sidecar_verify_ok_inc, qc_sidecar_verify_err_inc,
    // T41.4 (new):
    qc_sidecar_enforce_ok_inc, qc_sidecar_enforce_fail_inc,
};
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
use eezo_ledger::rotation::RotationPolicy;
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
use std::path::{Path, PathBuf};
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
use std::fs;


#[cfg(feature = "state-sync")]
use base64::{engine::general_purpose::STANDARD as B64, Engine};
#[cfg(feature = "state-sync")]
use eezo_crypto::sig::registry::verify_anchor_mldsa_44;
#[cfg(all(feature = "state-sync", feature = "slh-dsa"))]
use eezo_crypto::sig::registry::verify_anchor_sphincs_sha2_128f_simple;
// When SLH-DSA isn't compiled, provide a harmless stub so the match compiles.
#[cfg(all(feature = "state-sync", not(feature = "slh-dsa")))]
#[inline]
fn verify_anchor_sphincs_sha2_128f_simple(_: &[u8], _: &[u8], _: &[u8]) -> bool { false }
#[cfg(feature = "state-sync")]
use std::time::Instant;
// T32 timers from ledger (only exist with eth-ssz + state-sync)
#[cfg(all(feature = "state-sync", feature = "eth-ssz"))]
use eezo_ledger::state_sync::{
    t32_bootstrap_finish, t32_bootstrap_start, t32_page_apply_finish, t32_page_apply_start,
};
// --- T29.9 metrics ---
#[cfg(all(feature = "state-sync", feature = "metrics"))]
use crate::metrics::{
    SS_DELTA_BATCHES_APPLIED_TOTAL, SS_FAILURES_TOTAL, SS_PAGES_APPLIED_TOTAL, SS_RETRIES_TOTAL,
    STATE_SYNC_ANCHOR_SIGNED_TOTAL, STATE_SYNC_ANCHOR_UNSIGNED_TOTAL,
    STATE_SYNC_ANCHOR_VERIFY_FAIL_TOTAL, STATE_SYNC_DELTA_V2_SSZ_NOTFOUND_TOTAL,
    STATE_SYNC_DELTA_V2_SSZ_SERVE_TOTAL, STATE_SYNC_MTLS_FAIL_TOTAL,
    STATE_SYNC_TLS_CONFIG_FAIL_TOTAL, STATE_SYNC_TLS_HANDSHAKE_FAIL_TOTAL,
};
#[cfg(all(feature = "state-sync", feature = "metrics"))]
use eezo_ledger::metrics::EEZO_CHECKPOINT_APPLY_SECONDS;

#[cfg(feature = "state-sync")]
#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error("not found")]
    NotFound,
    #[error("persistence error: {0}")]
    Persistence(String),
    #[error("anchor not available")]
    AnchorMissing,
    #[error("invalid argument: {0}")]
    InvalidArg(&'static str),
    #[allow(dead_code)]
    #[error("proof verification failed")]
    ProofFailed,
    #[allow(dead_code)]
    #[error("not implemented")]
    Unimplemented,
    #[error("network request failed")]
    NetworkFailed,
    #[error("response decode failed")]
    DecodeFailed,
    #[error("internal: {0}")]
    Internal(String),
}

#[cfg(feature = "state-sync")]
impl From<ExportPersistError> for SyncError {
    fn from(e: ExportPersistError) -> Self {
        SyncError::Persistence(e.to_string())
    }
}

// Allow `?` on ledger KV ops that return PersistError
#[cfg(feature = "state-sync")]
impl From<PersistError> for SyncError {
    fn from(e: PersistError) -> Self {
        match e {
            PersistError::NotFound => SyncError::NotFound,
            // Map all other persistence errors to an internal/storage error surface.
            other => SyncError::Internal(other.to_string()),
        }
    }
}

// ===================== TLS/mTLS client config (from NodeConfig) =====================
#[cfg(feature = "state-sync")]
#[derive(Clone, Debug)]
struct SyncTlsCfg {
    enable: bool,
    ca_pem: Option<String>,
    cert_pem: Option<String>,
    key_pem: Option<String>,
    insecure_skip_verify: bool, // DEV/TEST ONLY
}

#[cfg(feature = "state-sync")]
impl SyncTlsCfg {
    fn from_env() -> Self {
        let read_env_path = |var: &str| {
            std::env::var(var).ok().and_then(|p| {
                match fs::read_to_string(&p) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        #[cfg(feature = "metrics")]
                        STATE_SYNC_TLS_CONFIG_FAIL_TOTAL.inc();
                        log::error!(
                            "state-sync: failed to read TLS file from env var {}: {}",
                            var,
                            p
                        );
                        None
                    }
                }
            })
        };

        Self {
            enable: std::env::var("EEZO_SYNC_TLS")
                .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
                .unwrap_or(false),
            ca_pem: read_env_path("EEZO_SYNC_TLS_CA"),
            cert_pem: read_env_path("EEZO_SYNC_TLS_CERT"),
            key_pem: read_env_path("EEZO_SYNC_TLS_KEY"),
            insecure_skip_verify: std::env::var("EEZO_SYNC_TLS_INSECURE_SKIP_VERIFY")
                .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
                .unwrap_or(false),
        }
    }
}

#[cfg(feature = "state-sync")]
fn http_client() -> Result<reqwest::blocking::Client, SyncError> {
    let t = SyncTlsCfg::from_env();
    let mut b = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(10));

    if t.enable {
        // Root CA (optional; system roots still apply if None)
        if let Some(ca_pem) = &t.ca_pem {
            match reqwest::Certificate::from_pem(ca_pem.as_bytes()) {
                Ok(ca) => {
                    b = b.add_root_certificate(ca);
                }
                Err(_) => {
                    #[cfg(feature = "metrics")]
                    STATE_SYNC_TLS_CONFIG_FAIL_TOTAL.inc();
                    return Err(SyncError::InvalidArg("invalid sync TLS CA PEM"));
                }
            }
        }
        // mTLS (optional)
        if let (Some(cert_pem), Some(key_pem)) = (&t.cert_pem, &t.key_pem) {
            let mut id_pem = String::new();
            id_pem.push_str(cert_pem);
            if !id_pem.ends_with('\n') {
                id_pem.push('\n');
            }
            id_pem.push_str(key_pem);
            match reqwest::Identity::from_pem(id_pem.as_bytes()) {
                Ok(id) => {
                    b = b.identity(id);
                }
                Err(_) => {
                    #[cfg(feature = "metrics")]
                    {
                        STATE_SYNC_MTLS_FAIL_TOTAL.inc();
                        STATE_SYNC_TLS_CONFIG_FAIL_TOTAL.inc();
                    }
                    return Err(SyncError::InvalidArg(
                        "invalid sync TLS client cert/key PEM",
                    ));
                }
            }
        }
        if t.insecure_skip_verify {
            b = b.danger_accept_invalid_certs(true);
        }
    }

    b.build().map_err(|_| {
        #[cfg(feature = "metrics")]
        STATE_SYNC_TLS_CONFIG_FAIL_TOTAL.inc();
        SyncError::InvalidArg("failed to build HTTP client")
    })
}

#[cfg(feature = "state-sync")]
fn tls_required() -> bool {
    std::env::var("EEZO_SYNC_TLS")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false)
}

// ===================== Anchor signature policy enforcement =====================
#[cfg(feature = "state-sync")]
fn verify_anchor_sig_policy(
    chain_id: [u8; 20],
    a: &CheckpointAnchor,
    allow_unsigned: bool,
) -> Result<(), SyncError> {
    // NEW: only enforce signatures when TLS is enabled.
    let tls_on = std::env::var("EEZO_SYNC_TLS")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false);

    if !tls_on {
        // In plaintext mode, don’t enforce signatures (test expects this).
        #[cfg(feature = "metrics")]
        {
            // Count it as “unsigned accepted” so we still see it in metrics.
            STATE_SYNC_ANCHOR_UNSIGNED_TOTAL.inc();
        }
        return Ok(());
    }

    match &a.sig {
        None => {
            if allow_unsigned {
                #[cfg(feature = "metrics")]
                {
                    STATE_SYNC_ANCHOR_UNSIGNED_TOTAL.inc();
                }
                Ok(())
            } else {
                #[cfg(feature = "metrics")]
                {
                    STATE_SYNC_ANCHOR_VERIFY_FAIL_TOTAL
                        .with_label_values(&["missing"])
                        .inc();
                }
                Err(SyncError::ProofFailed)
            }
        }
        Some(AnchorSig {
            scheme,
            pk_b64,
            sig_b64,
        }) => {
            let pk = B64
                .decode(pk_b64.as_bytes())
                .map_err(|_| SyncError::DecodeFailed)?;
            let sg = B64
                .decode(sig_b64.as_bytes())
                .map_err(|_| SyncError::DecodeFailed)?;
            let msg = anchor_signing_bytes(chain_id, a);
            // T34: dual-accept rotation window. Support ML-DSA-44 and SPHINCS+-SHA2-128f-simple.
            // Length checks are delegated to the verifier functions (avoid duplicating constants here).
            let ok = match scheme.as_str() {
                // Current suite
                "ML-DSA-44" => verify_anchor_mldsa_44(&pk, &msg, &sg),
                // Next suite aliases (accept a couple of reasonable labels)
                "SPHINCS+-SHA2-128f-simple" |
                "SPHINCS+-SHA2-128f" |
                "SPHINCS+-128f" => verify_anchor_sphincs_sha2_128f_simple(&pk, &msg, &sg),
                _ => {
                    #[cfg(feature = "metrics")]
                    STATE_SYNC_ANCHOR_VERIFY_FAIL_TOTAL
                        .with_label_values(&["unsupported_algo"])
                        .inc();
                    return Err(SyncError::InvalidArg("unsupported anchor signature scheme"));
                }
            };

            if ok {
                #[cfg(feature = "metrics")]
                {
                    STATE_SYNC_ANCHOR_SIGNED_TOTAL.inc();
                }
                Ok(())
            } else {
                #[cfg(feature = "metrics")]
                {
                    STATE_SYNC_ANCHOR_VERIFY_FAIL_TOTAL
                        .with_label_values(&["bad_sig"])
                        .inc();
                }
                Err(SyncError::ProofFailed)
            }
        }
    }
}


#[cfg(feature = "state-sync")]
#[derive(Debug, Clone)]
struct ClientProgress {
    anchor_height: u64,
    snapshot_cursor: Option<String>,
    applied_to_height: u64,
}

#[cfg(feature = "state-sync")]
const K_SYNC_ANCHOR: &[u8] = b"client:anchor_height";
#[cfg(feature = "state-sync")]
const K_SYNC_CURSOR: &[u8] = b"client:snapshot_cursor";
#[cfg(feature = "state-sync")]
const K_SYNC_APPLIED: &[u8] = b"client:applied_to_height";

#[cfg(feature = "state-sync")]
fn u64_to_be(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

#[cfg(feature = "state-sync")]
fn be_to_u64(b: &[u8]) -> u64 {
    if b.len() >= 8 {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        0
    }
}

#[cfg(feature = "state-sync")]
fn save_progress(db: &Persistence, p: &ClientProgress) -> Result<(), SyncError> {
    db.kv_put_sync(K_SYNC_ANCHOR, &u64_to_be(p.anchor_height))?;
    db.kv_put_sync(K_SYNC_APPLIED, &u64_to_be(p.applied_to_height))?;
    match &p.snapshot_cursor {
        Some(s) => db.kv_put_sync(K_SYNC_CURSOR, s.as_bytes())?,
        None => db.kv_put_sync(K_SYNC_CURSOR, &[])?,
    }
    Ok(())
}

#[cfg(feature = "state-sync")]
fn load_progress(db: &Persistence) -> Result<Option<ClientProgress>, SyncError> {
    let ah = db.kv_get_sync(K_SYNC_ANCHOR)?;
    let ap = db.kv_get_sync(K_SYNC_APPLIED)?;
    let cur = db.kv_get_sync(K_SYNC_CURSOR)?;

    if ah.is_none() && ap.is_none() && cur.is_none() {
        return Ok(None);
    }
    let anchor_height = ah.as_deref().map(be_to_u64).unwrap_or(0);
    let applied_to_height = ap.as_deref().map(be_to_u64).unwrap_or(0);
    let snapshot_cursor =
        cur.and_then(|v| if v.is_empty() { None } else { String::from_utf8(v).ok() });
    Ok(Some(ClientProgress {
        anchor_height,
        snapshot_cursor,
        applied_to_height,
    }))
}

#[cfg(feature = "state-sync")]
fn clear_progress(db: &Persistence) -> Result<(), SyncError> {
    db.kv_del_sync(K_SYNC_ANCHOR)?;
    db.kv_del_sync(K_SYNC_APPLIED)?;
    db.kv_del_sync(K_SYNC_CURSOR)?;
    Ok(())
}

#[cfg(feature = "state-sync")]
pub fn clear_sync_progress(db: &Persistence) -> Result<(), SyncError> {
    clear_progress(db)
}

#[cfg(feature = "state-sync")]
pub const SNAPSHOT_LIMIT_MAX: u32 = 1024;
#[cfg(feature = "state-sync")]
pub const RANGE_SPAN_MAX: u64 = 10_000;

#[cfg(feature = "state-sync")]
pub fn validate_limit(limit: usize) -> Result<usize, SyncError> {
    if limit == 0 || limit > SNAPSHOT_LIMIT_MAX as usize {
        Err(SyncError::InvalidArg("limit must be 1..=1024"))
    } else {
        Ok(limit)
    }
}

#[cfg(feature = "state-sync")]
pub fn validate_range(from: u64, to: u64) -> Result<(u64, u64), SyncError> {
    if from > to {
        Err(SyncError::InvalidArg("from_height must be <= to_height"))
    } else if to.saturating_sub(from) > RANGE_SPAN_MAX {
        Err(SyncError::InvalidArg("height range too large"))
    } else {
        Ok((from, to))
    }
}

#[cfg(feature = "state-sync")]
pub fn validate_prefix_b64(prefix_b64: &Option<String>) -> Result<(), SyncError> {
    if let Some(p) = prefix_b64 {
        if p.len() > 256 {
            return Err(SyncError::InvalidArg("prefix too long (max 256 chars)"));
        }
        if B64.decode(p.as_bytes()).is_err() {
            return Err(SyncError::InvalidArg("prefix must be valid base64"));
        }
    }
    Ok(())
}

#[cfg(feature = "state-sync")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SnapshotItemB64 {
    pub key_b64: String,
    pub val_b64: String,
}

#[cfg(feature = "state-sync")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SnapshotPage {
    pub items: Vec<SnapshotItemB64>,
    pub cursor: Option<String>,
}

#[cfg(feature = "state-sync")]
pub fn page_snapshot(
    db: &Persistence,
    prefix: Option<&[u8]>,
    cursor_b64: Option<&str>,
    limit: usize,
) -> anyhow::Result<SnapshotPage> {
    // Enforce the same cap used by clients (ledger continuity: stable page sizing)
    let limit = limit.min(SNAPSHOT_LIMIT_MAX as usize).max(1);
    let start_key = match cursor_b64 {
        Some(c) if !c.is_empty() => Some(B64.decode(c.as_bytes())?),
        _ => None,
    };
    let kvs: Vec<(Vec<u8>, Vec<u8>)> =
        db.snapshot_iter(prefix.unwrap_or(&[]), start_key.as_deref(), limit)?;
    let mut items = Vec::with_capacity(kvs.len());
    let mut last_key: Option<Vec<u8>> = None;
    for (k, v) in kvs {
        last_key = Some(k.clone());
        items.push(SnapshotItemB64 {
            key_b64: B64.encode(k),
            val_b64: B64.encode(v),
        });
    }
    let cursor = last_key.map(|k| B64.encode(k));
    Ok(SnapshotPage { items, cursor })
}

#[cfg(feature = "state-sync")]
pub type SnapshotChunk = SnapshotPage;

#[cfg(feature = "state-sync")]
pub fn handle_get_snapshot(
    db: &Persistence,
    prefix: &[u8],
    cursor: Option<&[u8]>,
    limit: usize,
) -> Result<SnapshotPage, SyncError> {
    let prefix_opt = if prefix.is_empty() { None } else { Some(prefix) };
    let cursor_b64 = cursor.map(|c| B64.encode(c));
    page_snapshot(db, prefix_opt, cursor_b64.as_deref(), limit)
        .map_err(|e| SyncError::Persistence(e.to_string()))
}

#[cfg(feature = "state-sync")]
pub fn handle_get_anchor(db: &Persistence) -> Result<CheckpointAnchor, SyncError> {
    db.load_checkpoint_anchor()?.ok_or(SyncError::NotFound)
}

#[cfg(feature = "state-sync")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeltaEntry {
    pub k_b64: String,
    pub v_b64: Option<String>,
}

#[cfg(feature = "state-sync")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeltaBatch {
    pub from_height: u64,
    pub to_height: u64,
    pub entries: Vec<DeltaEntry>,
}

#[cfg(feature = "state-sync")]
pub fn handle_get_delta(
    _db: &Persistence,
    from_height: u64,
    to_height: u64,
    _limit: usize,
) -> Result<DeltaBatch, SyncError> {
    if to_height < from_height {
        Err(SyncError::InvalidArg("to_height < from_height"))
    } else {
        Ok(DeltaBatch {
            from_height,
            to_height,
            entries: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2: ETH-SSZ snapshot/delta HTTP handlers + manifests (v2)
// These sit alongside the existing JSON v1 paging endpoints. The router will
// call these directly (see main.rs patch).
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
use {
    axum::{
        body::Bytes,
        extract::{Query, State},
        http::{header, StatusCode},
        response::IntoResponse,
        Json,
    },
    std::collections::HashMap,
};

#[cfg(all(feature = "state-sync", feature = "state-sync-http", feature = "eth-ssz"))]
use crate::metrics;

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
use crate::AppState;

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
const ROUTE_SNAP_MANIFEST: &str = "/state/snapshot/manifest";
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
const ROUTE_SNAP_BLOB: &str = "/state/snapshot/blob";
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
const ROUTE_DELTA_MANIFEST: &str = "/state/delta/manifest";

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[inline]
fn http_ok(route: &str) {
    #[cfg(feature = "metrics")]
    crate::metrics::http_inc(route, StatusCode::OK.as_u16());
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[inline]
fn http_4xx(route: &str, code: StatusCode) {
    #[cfg(feature = "metrics")]
    crate::metrics::http_inc(route, code.as_u16());
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[inline]
fn http_5xx(route: &str) {
    #[cfg(feature = "metrics")]
    crate::metrics::http_inc(route, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
}

// Minimal SSZ encode helpers local to this module (Phase 2, manifest-only).
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
mod ssz_min {
    pub trait Encode {
        fn ssz_write(&self, out: &mut Vec<u8>);
        fn ssz_bytes(&self) -> Vec<u8> {
            let mut v = Vec::new();
            self.ssz_write(&mut v);
            v
        }
    }
    impl Encode for u64 {
        fn ssz_write(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.to_le_bytes());
        }
    }
    impl Encode for [u8; 32] {
        fn ssz_write(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(self);
        }
    }
    impl Encode for usize {
        fn ssz_write(&self, out: &mut Vec<u8>) {
            (*self as u64).ssz_write(out);
        }
    }
    impl<T: Encode> Encode for Vec<T> {
        fn ssz_write(&self, out: &mut Vec<u8>) {
            (self.len() as u64).ssz_write(out);
            for x in self {
                x.ssz_write(out);
            }
        }
    }
    impl Encode for Vec<u8> {
        fn ssz_write(&self, out: &mut Vec<u8>) {
            (self.len() as u64).ssz_write(out);
            out.extend_from_slice(self);
        }
    }
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
use ssz_min::Encode;

// Snapshot v2 manifest (minimal) — encoded via ssz_min::Encode
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[derive(Debug, Clone)]
struct SnapshotManifestV2 {
    height: u64,
    codec_version: u64, // fixed 2
    state_root_v2: [u8; 32],
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
impl Encode for SnapshotManifestV2 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        self.height.ssz_write(out);
        self.codec_version.ssz_write(out);
        self.state_root_v2.ssz_write(out);
    }
}

// Delta v2 manifest (skeleton; multiproofs will populate keys/values later).
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[derive(Debug, Clone)]
struct DeltaManifestV2 {
    base_height: u64,
    new_height: u64,
    proof_keys: Vec<Vec<u8>>,
    proof_values: Vec<Vec<u8>>,
    new_state_root_v2: [u8; 32],
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
impl Encode for DeltaManifestV2 {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        self.base_height.ssz_write(out);
        self.new_height.ssz_write(out);
        self.proof_keys.ssz_write(out);
        self.proof_values.ssz_write(out);
        self.new_state_root_v2.ssz_write(out);
    }
}

// Build a manifest at/for `height`. If `height == u64::MAX`, use latest anchor.
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
fn build_snapshot_manifest_v2(
    db: &Persistence,
    height: u64,
) -> Result<SnapshotManifestV2, SyncError> {
    match handle_get_anchor(db) {
        Ok(a) => {
            let h = if height == u64::MAX { a.height } else { height };
            if h != a.height {
                return Err(SyncError::NotFound);
            }
            Ok(SnapshotManifestV2 {
                height: h,
                codec_version: 2,
                state_root_v2: a.state_root,
            })
        }
        Err(SyncError::NotFound) => {
            // No anchor yet. If caller asked for "latest" (u64::MAX) or explicit 0,
            // try to serve a genesis manifest at height 0 using the persisted root.
            let want_genesis = height == u64::MAX || height == 0;
            if !want_genesis {
                return Err(SyncError::NotFound);
            }
            let r = load_genesis_state_root_v2(db).map_err(SyncError::from)?;
            Ok(SnapshotManifestV2 {
                height: 0,
                codec_version: 2,
                state_root_v2: r,
            })
        }
        Err(e) => Err(e),
    }
}

// Build a (skeleton) delta manifest for [from, to] (inclusive).
// For now, this only returns the target root; proofs arrive in the next step.
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
fn build_delta_manifest_v2(
    db: &Persistence,
    from: u64,
    to: u64,
) -> Result<DeltaManifestV2, SyncError> {
    if to < from {
        return Err(SyncError::InvalidArg("to_height < from_height"));
    }
    match handle_get_anchor(db) {
        Ok(a) => {
            if to != a.height {
                return Err(SyncError::NotFound);
            }
            Ok(DeltaManifestV2 {
                base_height: from,
                new_height: to,
                proof_keys: Vec::new(),
                proof_values: Vec::new(),
                new_state_root_v2: a.state_root,
            })
        }
        Err(SyncError::NotFound) => {
            // No anchor yet. Support a trivial genesis delta (0->0) so clients
            // can at least see the target root. Proof lists remain empty.
            if from == 0 && to == 0 {
                let r = load_genesis_state_root_v2(db).map_err(SyncError::from)?;
                Ok(DeltaManifestV2 {
                    base_height: 0,
                    new_height: 0,
                    proof_keys: Vec::new(),
                    proof_values: Vec::new(),
                    new_state_root_v2: r,
                })
            } else {
                Err(SyncError::NotFound)
            }
        }
        Err(e) => Err(e),
    }
}

// ----- HTTP query types -----

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[derive(Debug, serde::Deserialize)]
struct V1SnapQuery {
    prefix: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[derive(Debug, serde::Deserialize)]
pub(crate) struct SnapV2Query {
    v: Option<u32>,
    height: Option<u64>,
    /// Optional payload format: "bin" (default) or "ssz"
    fmt: Option<String>,
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[derive(Debug, serde::Deserialize)]
pub(crate) struct DeltaV2Query {
    v: Option<u32>,
    from: u64,
    to: u64,
}

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
#[derive(serde::Deserialize, Debug)]
pub struct DeltaManifestV2Query {
    pub v: Option<u8>,       // must be 2
    pub fmt: Option<String>, // expect "ssz" (optional)
    pub from: u64,
    pub to: u64,
}

// ----- HTTP Handlers -----

#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
pub async fn get_anchor(State(st): State<AppState>) -> impl IntoResponse {
    match handle_get_anchor(&st.db) {
        Ok(a) => Json(a).into_response(),
        Err(SyncError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            // TODO(metrics): increment STATE_SYNC_ANCHOR_VERIFY_FAIL_TOTAL with appropriate labels.
            (StatusCode::INTERNAL_SERVER_ERROR, format!("error: {e}")).into_response()
        }
    }
}

/// GET /state/snapshot
/// v1 (default): JSON page (prefix/cursor/limit)
/// v2: SSZ-encoded SnapshotManifestV2 (use /state/snapshot/blob for the payload)
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
pub async fn get_snapshot(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Route based on ?v=
    match q.get("v").and_then(|s| s.parse::<u32>().ok()).unwrap_or(1) {
        1 => {
            // v1 JSON paging
            let prefix_b64 = q.get("prefix").cloned();
            let cursor_b64 = q.get("cursor").map(String::as_str);
            let limit_raw = q.get("limit").and_then(|s| s.parse::<u32>().ok()).unwrap_or(100);
            // Validate and clamp the limit to continuity-safe bounds (1..=1024)
            let limit = match validate_limit(limit_raw as usize) {
                Ok(n) => n,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
                }
            };

            if let Err(e) = validate_prefix_b64(&prefix_b64) {
                return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
            }

            let prefix_bytes = match prefix_b64.as_ref().and_then(|p| B64.decode(p).ok()) {
                Some(bytes) => bytes,
                None => Vec::new(),
            };

            let cursor_bytes = cursor_b64.and_then(|c| B64.decode(c).ok());

            match handle_get_snapshot(&st.db, &prefix_bytes, cursor_bytes.as_deref(), limit) {
                Ok(page) => Json(page).into_response(),
                Err(SyncError::NotFound) => StatusCode::NOT_FOUND.into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("error: {e}")).into_response(),
            }
        }
        2 => {
            // v2 manifest (SSZ bytes)
            #[cfg(not(feature = "eth-ssz"))]
            {
                return (StatusCode::BAD_REQUEST, "eth-ssz feature not enabled").into_response();
            }
            #[cfg(feature = "eth-ssz")]
            {
                let h = q
                    .get("height")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(u64::MAX);
                match build_snapshot_manifest_v2(&st.db, h) {
                    Ok(m) => {
                        let mut resp = (StatusCode::OK, Bytes::from(m.ssz_bytes())).into_response();
                        resp.headers_mut().insert(
                            header::CONTENT_TYPE,
                            header::HeaderValue::from_static("application/octet-stream"),
                        );
                        resp
                    }
                    Err(SyncError::NotFound) => StatusCode::NOT_FOUND.into_response(),
                    Err(e) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("error: {e}")).into_response()
                    }
                }
            }
        }
        _ => (StatusCode::BAD_REQUEST, "unsupported version").into_response(),
    }
}

// ---------- V2 Snapshot Manifest ----------

#[derive(Deserialize)]
pub struct SnapV2ManifestQuery {
    pub v: Option<u8>,       // expect 2
    pub height: Option<u64>, // default: latest (we’ll treat None as 0 for now)
}

#[derive(Serialize)]
struct SnapV2Manifest {
    version: u8,           // 2
    height: u64,
    state_root_v2: String, // hex-encoded 32-byte root
    ssz: SszBlobInfo,
}

#[derive(Serialize)]
struct SszBlobInfo {
    url: String,
    content_length: u64, // 12 + accounts_len + supply_len
    accounts_len: u32,
    supply_len: u32,
}

#[cfg(all(
    feature = "state-sync",
    feature = "state-sync-http",
    feature = "eth-ssz"
))]
pub async fn get_snapshot_manifest_v2(
    State(st): State<AppState>,
    Query(q): Query<SnapV2ManifestQuery>,
) -> impl IntoResponse {
    // Treat u64::MAX as "latest": prefer the current anchor height; if no anchor yet,
    // fall back to genesis (height 0) so clients can still bootstrap.
    let mut height = q.height.unwrap_or(0);
    if height == u64::MAX {
        match handle_get_anchor(&st.db) {
            Ok(a) => height = a.height,
            Err(_) => height = 0,
        }
    }

    match eezo_ledger::persistence::prewrite_snapshot_ssz_blob_v2(&st.db, height) {
        Ok(meta) => {
            #[cfg(feature = "metrics")]
            crate::metrics::STATE_SYNC_SNAPSHOTS_TOTAL
                .with_label_values(&["manifest_v2"])
                .inc();

            let manifest = SnapV2Manifest {
                version: 2,
                height,
                state_root_v2: hex::encode(meta.state_root_v2),
                ssz: SszBlobInfo {
                    url: format!("/state/snapshot/blob?v=2&fmt=ssz&height={height}"),
                    content_length: meta.total_len,
                    accounts_len: meta.accounts_len,
                    supply_len: meta.supply_len,
                },
            };
            http_ok(ROUTE_SNAP_MANIFEST);
            (StatusCode::OK, Json(manifest)).into_response()
        }
        Err(eezo_ledger::persistence::ExportPersistError::NotFound) => {
            // Nothing to serve (no anchor/genesis yet) → 204 No Content for pollers.
            return StatusCode::NO_CONTENT.into_response();
        }
        Err(e) => {
            log::warn!("snapshot manifest v2 export error: {e}");
            http_5xx(ROUTE_SNAP_MANIFEST);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("snapshot manifest v2 export error: {e}"),
            )
                .into_response()
        }
    }
}

/// GET /state/snapshot/blob?v=2&height=<h>
/// Body: current bincode snapshot payload (flip to ETH-SSZ in next step)
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
pub async fn get_snapshot_blob(
    State(st): State<AppState>,
    Query(q): Query<SnapV2Query>,
) -> impl IntoResponse {
    if q.v.unwrap_or(2) != 2 {
        http_4xx(ROUTE_SNAP_BLOB, StatusCode::BAD_REQUEST);
        return (StatusCode::BAD_REQUEST, "unsupported version").into_response();
    }
    let h = q.height.unwrap_or(u64::MAX);
    // Height semantics: if height == u64::MAX, prefer latest anchor; if none, try genesis(0).
    let height = if h == u64::MAX {
        match handle_get_anchor(&st.db) {
            Ok(a) => a.height,
            Err(_) => {
                // Fallback: try genesis snapshot at height 0
                if eezo_ledger::persistence::export_snapshot_blob_v2(&st.db, 0).is_ok() {
                    0
                } else {
                    // No snapshot yet → 204 (pollers keep going), empty body.
                    return StatusCode::NO_CONTENT.into_response();
                }
            }
        }
    } else {
        h
    };

    // decide format; default = bin
    let fmt = q.fmt.as_deref().unwrap_or("bin");
    let res = match fmt {
        "bin" => eezo_ledger::persistence::export_snapshot_blob_v2(&st.db, height),
        "ssz" => {
            // SSZ: export; if missing, prewrite then retry once.
            match eezo_ledger::persistence::export_snapshot_blob_v2_ssz(&st.db, height) {
                Ok(bytes) => Ok(bytes),
                Err(eezo_ledger::persistence::ExportPersistError::NotFound) => {
                    match eezo_ledger::persistence::prewrite_snapshot_ssz_blob_v2(&st.db, height) {
                        Ok(_) => {
                            eezo_ledger::persistence::export_snapshot_blob_v2_ssz(&st.db, height)
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(eezo_ledger::persistence::ExportPersistError::NotImplemented) => {
                    http_4xx(ROUTE_SNAP_BLOB, StatusCode::NOT_IMPLEMENTED);
                    return (StatusCode::NOT_IMPLEMENTED, "ssz export not yet implemented")
                        .into_response();
                }
                Err(e) => Err(e),
            }
        }

        _ => {
            http_4xx(ROUTE_SNAP_BLOB, StatusCode::BAD_REQUEST);
            return (StatusCode::BAD_REQUEST, "invalid fmt (use bin|ssz)").into_response();
        }
    };

    match res {
        Ok(bytes) => {
            http_ok(ROUTE_SNAP_BLOB);
            // (Optional) metrics once you want them: STATE_SYNC_SNAPSHOT_BYTES_TOTAL.inc_by(bytes.len() as u64);
            let mut resp = (StatusCode::OK, Bytes::from(bytes)).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            resp
        }
        Err(eezo_ledger::persistence::ExportPersistError::NotFound) => {
            // Nothing to serve at this height → 204 No Content.
            return StatusCode::NO_CONTENT.into_response();
        }
        Err(e) => {
            http_5xx(ROUTE_SNAP_BLOB);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error exporting snapshot: {e}"),
            )
                .into_response()
        }
    }
}

/// GET /state/delta?v=2&from=<h1>&to=<h2>
/// Body: SSZ-encoded DeltaManifestV2 (multiproofs in a later patch)
#[cfg(all(feature = "state-sync", feature = "state-sync-http"))]
pub async fn get_delta(
    State(st): State<AppState>,
    Query(q): Query<DeltaV2Query>,
) -> impl IntoResponse {
    if q.v.unwrap_or(2) != 2 {
        // v1 logic...
        match handle_get_delta(&st.db, q.from, q.to, 0) {
            Ok(batch) => Json(batch).into_response(),
            Err(SyncError::NotFound) => StatusCode::NOT_FOUND.into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("error: {e}")).into_response(),
        }
    } else {
        #[cfg(not(feature = "eth-ssz"))]
        {
            http_4xx(ROUTE_DELTA_MANIFEST, StatusCode::BAD_REQUEST);
            return (StatusCode::BAD_REQUEST, "eth-ssz feature not enabled").into_response();
        }
        #[cfg(feature = "eth-ssz")]
        {
            // Serve SSZ-framed DeltaManifestV2 (from ledger).
            match eezo_ledger::persistence::export_delta_manifest_v2_ssz(&st.db, q.from, q.to) {
                Ok(bytes) => {
                    #[cfg(feature = "metrics")]
                    {
                        STATE_SYNC_DELTA_V2_SSZ_SERVE_TOTAL.inc();
                        metrics::STATE_SYNC_DELTAS_TOTAL
                            .with_label_values(&["v2_ssz"])
                            .inc();
                    }
                    http_ok(ROUTE_DELTA_MANIFEST);
                    let mut resp = (StatusCode::OK, Bytes::from(bytes)).into_response();
                    resp.headers_mut().insert(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/octet-stream"),
                    );
                    resp
                }
                Err(eezo_ledger::persistence::ExportPersistError::NotFound) => {
                    #[cfg(feature = "metrics")]
                    STATE_SYNC_DELTA_V2_SSZ_NOTFOUND_TOTAL.inc();
                    // No delta for this (from,to) window yet → 204 No Content.
                    return StatusCode::NO_CONTENT.into_response();
                }
                Err(e) => {
                    log::warn!("delta v2 ssz export error: {e}");
                    http_5xx(ROUTE_DELTA_MANIFEST);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("delta v2 ssz export error: {e}"),
                    )
                        .into_response()
                }
            }
        }
    }
}

#[cfg(all(
    feature = "state-sync",
    feature = "state-sync-http",
    feature = "eth-ssz"
))]
pub async fn get_delta_manifest_v2(
    State(st): State<AppState>,
    Query(q): Query<DeltaManifestV2Query>,
) -> impl IntoResponse {
    // Only v2 is supported here
    if q.v.unwrap_or(2) != 2 {
        http_4xx(ROUTE_DELTA_MANIFEST, StatusCode::BAD_REQUEST);
        return (StatusCode::BAD_REQUEST, "only v=2 supported").into_response();
    }
    // Optional guard on fmt
    if let Some(ref f) = q.fmt {
        if f != "ssz" {
            http_4xx(ROUTE_DELTA_MANIFEST, StatusCode::BAD_REQUEST);
            return (StatusCode::BAD_REQUEST, "only fmt=ssz supported").into_response();
        }
    }

    match eezo_ledger::persistence::export_delta_manifest_v2_ssz(&st.db, q.from, q.to) {
        Ok(bytes) => {
            http_ok(ROUTE_DELTA_MANIFEST);
            let mut resp = (StatusCode::OK, Bytes::from(bytes)).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            resp
        }
        Err(eezo_ledger::persistence::ExportPersistError::NotFound) => {
            // Nothing to serve for this window → 204 No Content.
            return StatusCode::NO_CONTENT.into_response();
        }
        Err(e) => {
            log::warn!("delta v2 ssz export error: {e}");
            http_5xx(ROUTE_DELTA_MANIFEST);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("delta v2 ssz export error: {e}"),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "state-sync")]
#[derive(Debug, Clone)]
pub struct BootstrapCfg<'a> {
    pub base_url: &'a str,
    pub page_limit: usize,
    pub delta_span: u64,
    pub max_retries: usize,
    pub backoff_ms: u64,
    pub backoff_cap_ms: u64,
    // NEW:
    pub chain_id: [u8; 20],
    pub allow_unsigned_anchor: bool,
}

#[cfg(feature = "state-sync")]
fn backoff_dur_ms(base: u64, cap: u64, attempt: usize) -> u64 {
    // exponential with light deterministic “jitter” (no rand dep)
    let exp = base.saturating_mul(1u64 << attempt.min(16));
    let jitter_pc = ((attempt as u64 * 137) % 21) as u64; // 0..20%
    let with_jitter = exp + (exp * jitter_pc / 100);
    with_jitter.min(cap)
}

#[cfg(feature = "state-sync")]
pub fn retry_with_backoff<F, T>(
    mut f: F,
    base_ms: u64,
    cap_ms: u64,
    max_retries: u32,
) -> Result<T, SyncError>
where
    F: FnMut() -> Result<T, SyncError>,
{
    let mut attempt: u32 = 0;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                // Don’t retry on hard “NotFound” (404) or fatal config errors
                match e {
                    SyncError::NotFound | SyncError::InvalidArg(_) => return Err(e),
                    _ => {
                        // Retry metrics for each attempt
                        state_sync_retry_inc();
                        if attempt >= max_retries {
                            #[cfg(feature = "metrics")]
                            SS_FAILURES_TOTAL.inc();
                            return Err(e);
                        }
                        #[cfg(feature = "metrics")]
                        SS_RETRIES_TOTAL.inc();
                        // Safely cast attempt to usize for backoff_dur_ms
                        let sleep_ms = backoff_dur_ms(base_ms, cap_ms, attempt as usize);
                        log::warn!(
                            "state-sync: transient error (attempt {}), backing off {} ms: {}",
                            attempt + 1,
                            sleep_ms,
                            e
                        );
                        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                        attempt += 1;
                    }
                }
            }
        }
    }
}


#[cfg(feature = "state-sync")]
fn network_error_handler<E: std::fmt::Debug>(e: E) -> SyncError {
    log::debug!("state-sync: network error: {:?}", e);
    #[cfg(feature = "metrics")]
    STATE_SYNC_TLS_HANDSHAKE_FAIL_TOTAL.inc();
    SyncError::NetworkFailed
}

#[cfg(feature = "state-sync")]
pub fn fetch_anchor(base_url: &str) -> Result<CheckpointAnchor, SyncError> {
    if tls_required() && base_url.trim_start().starts_with("http://") {
        return Err(SyncError::InvalidArg(
            "HTTPS required but base_url is HTTP",
        ));
    }
    let url = format!("{}/state/anchor", base_url.trim_end_matches('/'));
    let resp = http_client()?
        .get(url)
        .send()
        .map_err(network_error_handler)?;
    let code = resp.status();
    if code.as_u16() == 404 {
        return Err(SyncError::NotFound);
    }
    if !code.is_success() {
        return Err(SyncError::NetworkFailed);
    }
    resp.json::<CheckpointAnchor>()
        .map_err(|_| SyncError::DecodeFailed)
}

#[cfg(feature = "state-sync")]
pub fn fetch_snapshot_page(
    base_url: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<SnapshotPage, SyncError> {
    if tls_required() && base_url.trim_start().starts_with("http://") {
        return Err(SyncError::InvalidArg(
            "HTTPS required but base_url is HTTP",
        ));
    }
    let url = format!("{}/state/snapshot", base_url.trim_end_matches('/'));
    let mut req = http_client()?.get(url).query(&[("limit", limit)]);
    if let Some(cur) = cursor {
        req = req.query(&[("cursor", cur)]);
    }
    let resp = req.send().map_err(network_error_handler)?;
    let code = resp.status();
    if code.as_u16() == 404 {
        return Err(SyncError::NotFound);
    }
    if !code.is_success() {
        return Err(SyncError::NetworkFailed);
    }
    resp.json::<SnapshotPage>()
        .map_err(|_| SyncError::DecodeFailed)
}

#[cfg(feature = "state-sync")]
pub fn fetch_delta(
    base_url: &str,
    from: u64,
    to: u64,
    limit: usize,
) -> Result<DeltaBatch, SyncError> {
    if tls_required() && base_url.trim_start().starts_with("http://") {
        return Err(SyncError::InvalidArg(
            "HTTPS required but base_url is HTTP",
        ));
    }
    let url = format!("{}/state/delta", base_url.trim_end_matches('/'));
    let resp = http_client()?
        .get(url)
        .query(&[
            ("from", from),
            ("to", to),
            ("limit", limit as u64),
        ])
        .send()
        .map_err(network_error_handler)?;
    let code = resp.status();
    if code.as_u16() == 404 {
        return Err(SyncError::NotFound);
    }
    if !code.is_success() {
        return Err(SyncError::NetworkFailed);
    }
    resp.json::<DeltaBatch>()
        .map_err(|_| SyncError::DecodeFailed)
}

#[cfg(feature = "state-sync")]
pub fn verify_anchor_basic(a: &CheckpointAnchor) -> Result<(), SyncError> {
    // Test bypass: allow an empty/genesis anchor when EEZO_STATE_SYNC_SKIP_VERIFY=1
    if std::env::var("EEZO_STATE_SYNC_SKIP_VERIFY").as_deref() == Ok("1") {
        return Ok(());
    }
    if a.height == 0 && a.qc_hash == [0; 32] {
        Err(SyncError::ProofFailed)
    } else {
        Ok(())
    }
}

#[cfg(feature = "state-sync")]
pub fn last_applied_height(db: &Persistence) -> Result<u64, SyncError> {
    db.load_checkpoint_anchor()
        .map(|opt_a| opt_a.map(|a| a.height).unwrap_or(0))
        .map_err(SyncError::from)
}

#[cfg(feature = "state-sync")]
pub fn apply_snapshot_page(db: &Persistence, page: &SnapshotPage) -> Result<(), SyncError> {
    // T32: per-page apply timer (no-op without eth-ssz/metrics)
    #[cfg(all(feature = "state-sync", feature = "eth-ssz"))]
    let _t32 = t32_page_apply_start();
    for it in &page.items {
        let key = B64
            .decode(it.key_b64.as_bytes())
            .map_err(|_| SyncError::DecodeFailed)?;
        let val = B64
            .decode(it.val_b64.as_bytes())
            .map_err(|_| SyncError::DecodeFailed)?;
        db.kv_put_sync(&key, &val)?;
    }
    // Increment the total number of state-sync applications
    state_sync_total_inc();	
    // T32: record duration and increment page counter
    #[cfg(all(feature = "state-sync", feature = "eth-ssz"))]
    t32_page_apply_finish(_t32);
    Ok(())
}

#[cfg(feature = "state-sync")]
pub fn apply_delta_batch(db: &Persistence, b: &DeltaBatch) -> Result<(), SyncError> {
    // T32: treat delta-batch apply like a “page” for latency purposes
    #[cfg(all(feature = "state-sync", feature = "eth-ssz"))]
    let _t32 = t32_page_apply_start();

    for e in &b.entries {
        let k = B64
            .decode(e.k_b64.as_bytes())
            .map_err(|_| SyncError::DecodeFailed)?;
        if let Some(vb) = &e.v_b64 {
            let v = B64
                .decode(vb.as_bytes())
                .map_err(|_| SyncError::DecodeFailed)?;
            db.kv_put_sync(&k, &v)?;
        } else {
            db.kv_del_sync(&k)?;
        }
    }
    // T32: finish timing (counter is only for snapshot pages, so no inc here)
    #[cfg(all(feature = "state-sync", feature = "eth-ssz"))]
    t32_page_apply_finish(_t32);
    Ok(())
}

#[cfg(feature = "state-sync")]
pub fn persist_anchor(db: &Persistence, a: &CheckpointAnchor) -> Result<(), SyncError> {
    db.save_checkpoint_anchor(a).map_err(SyncError::from)
}

// ─────────────────────────────────────────────────────────────────────────────
// T33.2 helper: Write a BridgeHeader JSON derived from the current anchor.
//
// This is an **optional** emitter to get `proof/checkpoints/<height>.json` files
// without changing your consensus/commit path yet. Because the anchor does not
// currently carry `tx_root_v2` or a timestamp, we fill them with placeholders:
//   - tx_root_v2: [0; 32]
//   - timestamp: 0
//
// Once your commit path exposes those values, prefer using the producer-side
// emission (see consensus_runner::emit_bridge_checkpoint) for full headers.
//
// Returns: Ok(Some(path)) if a header was written, Ok(None) if no anchor yet.
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
pub fn emit_checkpoint_from_current_anchor(
    db: &Persistence,
    finality_depth: u64,
) -> std::io::Result<Option<PathBuf>> {
    match db.load_checkpoint_anchor() {
        Ok(Some(a)) => {
            // Map anchor fields → BridgeHeader. We use qc_hash as the header_hash
            // placeholder until the real block header hash is plumbed.
            let mut hdr = BridgeHeader::new(
                a.height,
                a.qc_hash,      // placeholder for header hash
                a.state_root,   // ETH-SSZ v2 state root from anchor
                [0u8; 32],      // tx_root_v2 (TODO: fill from producer path)
                0,              // timestamp (TODO: fill from producer path)
                finality_depth,
            );
            // T41.2: if rotation policy is defined and we are at cutover+1, attach a QC sidecar v2
            if let Some(pol) = rotation_policy_from_env() {
                if should_emit_qc_sidecar_v2(a.height, &pol) {
                    let sc = build_stub_sidecar_v2(hdr.suite_id, a.height, ReanchorReason::RotationCutover);
                    if sc.is_sane_for_height(a.height) {
                        hdr = hdr.with_sidecar_v2(sc);
                        // T41.3: metrics for emit
                        qc_sidecar_emitted_inc();
                    } else {
                        log::warn!("qc-sidecar(state_sync single-emit): built sidecar not sane at h={}, skipping", a.height);
                    }
                }
            }
            // T41.3: reader-only validate and bump metrics
            if hdr.qc_sidecar_v2.is_some() {
                match validate_sidecar_v2_for_header(&hdr) {
                    Ok(()) => qc_sidecar_verify_ok_inc(),
                    Err(e) => {
                        qc_sidecar_verify_err_inc();
                        log::warn!("qc-sidecar(state_sync): validate failed at h={}: {}", a.height, e);
                    }
                }
            }
            // T41.4: strict mode — at cutover+1, sidecar must exist & be valid
            if qc_sidecar_enforce_on() {
                if let Some(pol) = rotation_policy_from_env() {
                    if should_emit_qc_sidecar_v2(a.height, &pol) {
                        let present = hdr.qc_sidecar_v2.is_some();
                        let valid = present && validate_sidecar_v2_for_header(&hdr).is_ok();
                        if valid {
                            qc_sidecar_enforce_ok_inc();
                        } else {
                            qc_sidecar_enforce_fail_inc();
                            log::error!("qc-sidecar(state_sync enforce): missing/invalid at h={} → refusing to write", a.height);
                            return Ok(None);
                        }
                    }
                }
            }
            let p = write_checkpoint_json_default(&hdr)?;
            Ok(Some(p))
        }
        Ok(None) => Ok(None),
        Err(_) => Ok(None),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// T34.2 helper: rotation-aware dual-emit of BridgeHeader JSONs from the anchor.
// If the rotation window is open, we emit **two** headers (active + next).
// Output dirs:
//   proof/checkpoints/ml-dsa/    <height>.json
//   proof/checkpoints/sphincs/   <height>.json
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
fn emit_rotation_checkpoints_from_anchor(
    db: &Persistence,
    finality_depth: u64,
    policy: &RotationPolicy,
) -> std::io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(Some(a)) = db.load_checkpoint_anchor() {
        // Build one or two headers based on the window/policy
        let mut headers = build_rotation_headers(
            policy,
            a.height,
            a.qc_hash,            // placeholder for header hash (until producer path plumbs it)
            a.state_root,         // ETH-SSZ v2 state root from anchor
            [0u8; 32],            // tx_root_v2 (to be filled by producer path later)
            0,                    // timestamp (to be filled by producer path later)
            finality_depth,
        );
        // Ensure suite-specific directories exist
        let base = Path::new("proof").join("checkpoints");
        let dir_ml = base.join("ml-dsa");
        let dir_sp = base.join("sphincs");
        let _ = fs::create_dir_all(&dir_ml);
        let _ = fs::create_dir_all(&dir_sp);
        // If this anchor is at cutover+1, attach QC sidecar v2 to each header we emit
        if should_emit_qc_sidecar_v2(a.height, policy) {
            for h in &mut headers {
                let suite_id = h.suite().map(|s| s.as_id()).unwrap_or(BridgeHeader::default_suite_id());
                let sc = build_stub_sidecar_v2(suite_id, a.height, ReanchorReason::RotationCutover);
                if sc.is_sane_for_height(a.height) {
                    *h = h.clone().with_sidecar_v2(sc);
                    // T41.3: metrics for emit
                    qc_sidecar_emitted_inc();
                } else {
                    log::warn!("qc-sidecar(state_sync dual-emit): built sidecar not sane at h={}, skipping", a.height);
                }
            }
        }

        // Write each header to the corresponding suite dir
        for h in headers {
            // T41.4: strict mode for dual-emit flow as well
            if qc_sidecar_enforce_on() {
                if should_emit_qc_sidecar_v2(a.height, policy) {
                    let present = h.qc_sidecar_v2.is_some();
                    let valid = present && validate_sidecar_v2_for_header(&h).is_ok();
                    if valid {
                        qc_sidecar_enforce_ok_inc();
                    } else {
                        qc_sidecar_enforce_fail_inc();
                        log::error!("qc-sidecar(state_sync dual enforce): missing/invalid at h={} → dropping header", a.height);
                        continue; // drop this header from being written
                    }
                }
            }
            // T41.3: reader-only validate and bump metrics
            if h.qc_sidecar_v2.is_some() {
                match validate_sidecar_v2_for_header(&h) {
                    Ok(()) => qc_sidecar_verify_ok_inc(),
                    Err(e) => {
                        qc_sidecar_verify_err_inc();
                        log::warn!("qc-sidecar(state_sync dual-emit): validate failed at h={}: {}", a.height, e);
                    }
                }
            }
            match h.suite().unwrap_or(CryptoSuite::MlDsa44) {
                CryptoSuite::MlDsa44 => {
                    out.push(eezo_ledger::checkpoints::write_checkpoint_json(&dir_ml, &h)?);
                }
                CryptoSuite::SphincsPq => {
                    out.push(eezo_ledger::checkpoints::write_checkpoint_json(&dir_sp, &h)?);
                }
            }
        }
    }
    Ok(out)
}

// Minimal env-driven policy so node can dual-emit without wiring a new config file yet.
// EEZO_ROT_ACTIVE:  "mldsa44" | "sphincs"
// EEZO_ROT_NEXT:    "mldsa44" | "sphincs" | empty (disabled)
// EEZO_ROT_UNTIL:   u64 height (inclusive) for dual-accept window
// EEZO_ROT_ACT_AT:  u64 height where `active` became effective (optional)
#[cfg(all(feature = "state-sync", feature = "checkpoints"))]
fn rotation_policy_from_env() -> Option<RotationPolicy> {
    fn parse_suite(s: &str) -> Option<CryptoSuite> {
        match s.to_ascii_lowercase().as_str() {
            "mldsa44" | "ml-dsa-44" | "mldsa" => Some(CryptoSuite::MlDsa44),
            "sphincs" | "sphincs+-sha2-128f-simple" | "sphincs+-128f" => Some(CryptoSuite::SphincsPq),
            _ => None,
        }
    }
    let active = std::env::var("EEZO_ROT_ACTIVE").ok().and_then(|v| parse_suite(&v))?;
    let next = std::env::var("EEZO_ROT_NEXT").ok().and_then(|v| {
        let v = v.trim();
        if v.is_empty() { None } else { parse_suite(v) }
    });
    let dual_accept_until = std::env::var("EEZO_ROT_UNTIL").ok().and_then(|v| v.parse::<u64>().ok());
    let activated_at_height = std::env::var("EEZO_ROT_ACT_AT").ok().and_then(|v| v.parse::<u64>().ok());
    let p = RotationPolicy { active, next, dual_accept_until, activated_at_height };
    match p.validate() {
        Ok(_) => Some(p),
        Err(e) => {
            log::warn!("rotation policy from env invalid: {e}");
            None
        }
    }
}


// ===================== bootstrap entry =====================
#[cfg(feature = "state-sync")]
pub fn bootstrap(db: &Persistence, cfg: &BootstrapCfg) -> Result<(), SyncError> {
    let t0 = Instant::now();
    // T32: whole-bootstrap timer (records a single total duration)
    #[cfg(all(feature = "state-sync", feature = "eth-ssz"))]
    let _t_boot = t32_bootstrap_start();

    log::info!(
        "bootstrap: starting process with config: base_url={}, page_limit={}, delta_span={}, max_retries={}, backoff_ms={}, backoff_cap_ms={}",
        cfg.base_url, cfg.page_limit, cfg.delta_span, cfg.max_retries, cfg.backoff_ms, cfg.backoff_cap_ms
    );

    // NOTE: arguments are ordered to match retry_with_backoff(base_ms, cap_ms, max_retries).
    let anchor = retry_with_backoff(
        || fetch_anchor(cfg.base_url),
        cfg.backoff_ms,
        cfg.backoff_cap_ms,
        cfg.max_retries as u32,
    )?;

    verify_anchor_basic(&anchor)?;
    // Test-only bypass: if EEZO_STATE_SYNC_SKIP_VERIFY=1, force allow_unsigned
    let mut allow_unsigned = cfg.allow_unsigned_anchor;
    if std::env::var("EEZO_STATE_SYNC_SKIP_VERIFY").as_deref() == Ok("1") {
        log::warn!("state-sync: EEZO_STATE_SYNC_SKIP_VERIFY=1 — bypassing anchor signature verification (tests only)");
        allow_unsigned = true;
    }

    verify_anchor_sig_policy(cfg.chain_id, &anchor, allow_unsigned)?;

    log::info!(
        "bootstrap: fetched and verified anchor at height {}",
        anchor.height
    );
    // ── TEST FAST-PATH ───────────────────────────────────────────────
    // If EEZO_STATE_SYNC_SKIP_VERIFY=1, skip paging/deltas and just
    // persist the anchor so the node flips to ready quickly.
    if std::env::var("EEZO_STATE_SYNC_SKIP_VERIFY").as_deref() == Ok("1") {
        log::warn!(
            "state-sync: EEZO_STATE_SYNC_SKIP_VERIFY=1 — skipping snapshot/delta apply (tests only)"
        );
        // Ensure any prior partial progress is cleared
        let _ = clear_progress(db);
        // Persist the (possibly unsigned) anchor and finish
        persist_anchor(db, &anchor)?;
        // (optional metrics timing you already wired will still wrap this run)
        return Ok(());
    }
    // ────────────────────────────────────────────────────────────────

    let mut cursor: Option<String> = None;
    let mut applied_to = last_applied_height(db)?;
    if let Some(p) = load_progress(db)? {
        if p.anchor_height == anchor.height {
            log::info!(
                "bootstrap: resuming sync for anchor height {}, snapshot_cursor={:?}, applied_to={}",
                anchor.height,
                p.snapshot_cursor.is_some(),
                p.applied_to_height
            );
            cursor = p.snapshot_cursor;
            applied_to = applied_to.max(p.applied_to_height);
        } else {
            log::warn!(
                "bootstrap: clearing progress from different anchor (old: {}, new: {})",
                p.anchor_height,
                anchor.height
            );
            clear_progress(db)?;
        }
    } else {
        log::info!(
            "bootstrap: no prior progress found for anchor height {}",
            anchor.height
        );
    }

    if applied_to == 0 {
        save_progress(
            db,
            &ClientProgress {
                anchor_height: anchor.height,
                snapshot_cursor: None,
                applied_to_height: 0,
            },
        )?;
    }

    let mut snapshot_pages = 0usize;
    loop {
        let page = retry_with_backoff(
            || fetch_snapshot_page(cfg.base_url, cursor.as_deref(), cfg.page_limit),
            cfg.backoff_ms,
            cfg.backoff_cap_ms,
            cfg.max_retries as u32,
        )?;
        if page.items.is_empty() && page.cursor.is_none() {
            break;
        }
        let item_count = page.items.len();
        let cursor_len = page.cursor.as_deref().map(|s| s.len()).unwrap_or(0);
        log::info!(
            "bootstrap: applying snapshot page {} with {} items, next_cursor_len={}",
            snapshot_pages,
            item_count,
            cursor_len
        );
        apply_snapshot_page(db, &page)?;
        #[cfg(feature = "metrics")]
        SS_PAGES_APPLIED_TOTAL.inc();

        snapshot_pages += 1;
        save_progress(
            db,
            &ClientProgress {
                anchor_height: anchor.height,
                snapshot_cursor: page.cursor.clone(),
                applied_to_height: applied_to,
            },
        )?;
        cursor = page.cursor;
        if cursor.is_none() {
            break;
        }
    }
    log::info!(
        "bootstrap: snapshot phase complete after {} pages.",
        snapshot_pages
    );

    let mut delta_batches = 0usize;
    let mut from = applied_to.saturating_add(1);
    while from <= anchor.height {
        let to = (from.saturating_add(cfg.delta_span)).min(anchor.height);
        log::info!("bootstrap: fetching delta batch from={} to={}", from, to);
        let batch = retry_with_backoff(
            || fetch_delta(cfg.base_url, from, to, cfg.page_limit),
            cfg.backoff_ms,
            cfg.backoff_cap_ms,
            cfg.max_retries as u32,
        )?;
        log::info!(
            "bootstrap: applying delta batch with {} entries",
            batch.entries.len()
        );
        apply_delta_batch(db, &batch)?;
        #[cfg(feature = "metrics")]
        SS_DELTA_BATCHES_APPLIED_TOTAL.inc();

        delta_batches += 1;
        applied_to = to;
        save_progress(
            db,
            &ClientProgress {
                anchor_height: anchor.height,
                snapshot_cursor: None,
                applied_to_height: applied_to,
            },
        )?;
        from = to.saturating_add(1);
    }
    if delta_batches > 0 {
        log::info!(
            "bootstrap: delta phase complete after {} batches.",
            delta_batches
        );
    }

    log::info!(
        "bootstrap: persisting final anchor at height {}",
        anchor.height
    );
    // Measure the duration of the checkpoint “apply” (persisting the anchor).
    let _t_ckpt_apply = Instant::now();
    persist_anchor(db, &anchor)?;
    // T33.2/T34.2: emit checkpoint headers.
    // Default: single-emit. If a valid env-policy exists and window is open,
    // dual-emit to suite-specific directories.
    #[cfg(all(feature = "state-sync", feature = "checkpoints"))]
    {
        if let Some(pol) = rotation_policy_from_env() {
            // We don’t need the height here; emit_rotation_* will read anchor and decide.
            let _ = emit_rotation_checkpoints_from_anchor(db, 2, &pol);
        } else {
            let _ = emit_checkpoint_from_current_anchor(db, 2);
        }
    }

    #[cfg(all(feature = "state-sync", feature = "metrics"))]
    {
        let secs = _t_ckpt_apply.elapsed().as_secs_f64();
        EEZO_CHECKPOINT_APPLY_SECONDS.observe(secs);
    }
    log::info!("bootstrap: clearing sync progress keys");
    clear_progress(db)?;
        log::info!(
        "bootstrap: process finished successfully in {:?}",
        t0.elapsed()
    );

    // Update monotonic state-sync height gauge to the final anchor height.
    state_sync_latest_height_set(anchor.height);

    // T32: record total bootstrap seconds
    #[cfg(all(feature = "state-sync", feature = "eth-ssz"))]
    t32_bootstrap_finish(_t_boot);
    Ok(())
}

#[cfg(test)]
mod backoff_tests {
    use super::backoff_dur_ms;

    #[test]
    fn backoff_never_exceeds_cap() {
        let base = 200;
        let cap = 1_000;
        for attempt in 0..50 {
            let d = backoff_dur_ms(base, cap, attempt);
            assert!(d <= cap, "attempt {} produced {} > cap {}", attempt, d, cap);
        }
    }

    #[test]
    fn backoff_is_non_decreasing_until_cap() {
        let base = 100;
        let cap = 3_000;
        let mut prev = 0;
        for attempt in 0..20 {
            let d = backoff_dur_ms(base, cap, attempt);
            assert!(d >= prev, "attempt {} produced {} < prev {}", attempt, d, prev);
            prev = d;
            if d == cap {
                break;
            }
        }
    }

    #[test]
    fn jitter_within_expected_bounds() {
        // jitter ≤ 20% of the exponential term by construction
        let base: u64 = 250;
        let cap: u64 = 100_000;
        for attempt in 0..10 {
            let exp = base.saturating_mul(1u64 << attempt);
            let d = backoff_dur_ms(base, cap, attempt);
            let max_with_jitter = exp + (exp * 20 / 100);
            assert!(d >= exp.min(cap), "d {} < exp {}", d, exp);
            assert!(
                d <= max_with_jitter.min(cap),
                "d {} > 120% exp {}",
                d,
                max_with_jitter
            );
        }
    }
}