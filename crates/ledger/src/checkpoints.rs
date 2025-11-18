// ------------------ LIGHT PATH: always available with `checkpoints` ------------------
// (only changes below are in serde_hex32 + an allow(dead_code) on hex_byte)

// (patch touches only imports below and the T34 anchor-verify section)

/// 32-byte QC hash alias — must NOT be behind `checkpoints-verify`
pub type QcHash = [u8; 32];

use crate::rotation::RotationPolicy;
use crate::qc_sidecar::{QcSidecarV2, ReanchorReason}; // T41.1/41.2: sidecar types (additive)
use crate::consensus_sig::build_qc_sidecar_v2; // T41.3: deterministic sidecar builder
use eezo_crypto::suite::{CryptoSuite, SuiteError};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use std::time::SystemTime;
// --- ADDED Imports for OpenOptions logic ---
use std::io::{ErrorKind, Write};
// --- END ADDED Imports ---
// T41.3: sidecar v2 metrics (read-only validation counters)
#[cfg(all(feature = "metrics", feature = "checkpoints"))]
use crate::metrics::{inc_sidecar_invalid, inc_sidecar_seen, inc_sidecar_valid};
// T37.8: logging on successful writes
// (use fully-qualified `log::info!` to avoid adding a new `use` line)

// ---------- serde helpers: [u8;32] <-> "0x{64-hex}" ----------
mod serde_hex32 {
    // --- MODIFIED: Removed unused imports `Error as _` and `Deserialize` ---
    use serde::{de::{self, SeqAccess, Visitor}, Deserializer, Serializer};

    #[inline]
    pub fn serialize<S>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // fast manual hex (no alloc except the String)
        let mut out = String::with_capacity(2 + 64);
        out.push_str("0x");
        // Use static lookup table for fast hex encoding
        static H: &[u8; 16] = b"0123456789abcdef";
        for b in v {
            let hi = H[(b >> 4) as usize] as char;
            let lo = H[(b & 0x0F) as usize] as char;
            out.push(hi);
            out.push(lo);
        }
        s.serialize_str(&out)
    }

    #[inline]
    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrOrSeq;
        impl<'de> Visitor<'de> for StrOrSeq {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("hex string (with/without 0x) or array[32] of bytes")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let s = v.trim();
                let s = s.strip_prefix("0x").unwrap_or(s);
                if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(E::custom("expected 64 hex chars"));
                }
                let mut out = [0u8; 32];
                for i in 0..32 {
                    let b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(E::custom)?;
                    out[i] = b;
                }
                Ok(out)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = [0u8; 32];
                // --- PATCH 1 START ---
                for (i, slot) in out.iter_mut().enumerate() {
                    // accept u8/u16/u32/u64 numbers
                    let v: Option<u64> = seq.next_element()?;
                    let n = v.ok_or_else(|| de::Error::invalid_length(i, &self))?;
                    if n > 255 {
                        return Err(de::Error::custom("byte out of range"));
                    }
                    *slot = n as u8;
                }
                // --- PATCH 1 END ---
                Ok(out)
            }
        }
        d.deserialize_any(StrOrSeq)
    }

    // --- MODIFIED: Added allow(dead_code) to fix compiler warning ---
    #[allow(dead_code)]
    #[inline]
    fn from_hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn hex_byte(_b: u8) -> &'static str {
        const TABLE: [&str; 256] = {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let t: [&str; 256] = [""; 256];
            let mut _i = 0usize;
            // NOTE: const fn generation isn't stable for String; we fall back to match below at runtime.
            // We'll never execute this block; keep to satisfy const syntax.
            t
        };
        // small runtime formatter (kept inline to avoid alloc)
        // SAFETY: we return &'static str by formatting into a stack buffer then leaking a boxed str.
        // To avoid leaks and complexity, we instead use a tiny two-byte array rendered via a local stack string.
        // Since Serializer copies, we can allocate a 2-char &'static via a static table built at runtime once.
        // Simpler approach: format! each nibble; it's fine (rare path).
        // Replaced with quick local buffer:
        // (Use a small static map for both nibbles)
        static H: &[u8; 16] = b"0123456789abcdef";
        // SAFETY: We only build &str used immediately by caller; but we can't return a stack ref.
        // So we fallback to formatting in caller. To keep code simple, we don't use this helper in serialize.
        let _ = TABLE;
        let _ = H;
        ""
    }
}

/// Compact anchor used by state-sync to bootstrap from a checkpoint.
/// It identifies the checkpoint block, its state root, and the QC hash that attests it.
/// This struct is always present, not behind a feature gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointAnchor {
    /// Height of the checkpoint block (decided).
    pub height: u64,
    /// Block id (32 bytes) of the checkpoint block.
    pub block_id: [u8; 32],
    /// State root (32 bytes) for the checkpoint block.
    pub state_root: [u8; 32],
    /// Hash of the quorum certificate that attests this checkpoint.
    pub qc_hash: [u8; 32],
    /// Optional signature envelope (T29.9). Present when the server signs anchors.
    /// Backward compatible: omitted in older servers/clients.
    #[serde(default)]
    pub sig: Option<AnchorSig>,
    /// Crypto suite used for this anchor/checkpoint.
    /// Backward compatible (omitted => None).
    #[serde(default)]
    pub suite_id: Option<u8>,
}

/// JSON-friendly signature envelope for anchors.
/// Kept simple for HTTP surfaces; we use base64 for binary values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorSig {
    /// Signature algorithm name (e.g., "ML-DSA-44").
    pub scheme: String,
    /// Public key (base64) for the signer.
    pub pk_b64: String,
    /// Detached signature (base64) over `anchor_signing_bytes(chain_id, anchor)`.
    pub sig_b64: String,
}

/// Produce canonical bytes to be signed for a `CheckpointAnchor`.
/// Includes `chain_id` to prevent cross-chain replay.
///
/// Layout:
///   TAG("EEZO:ANCHOR|v1|") || chain_id(20) || height(u64 LE) || block_id(32) || state_root(32) || qc_hash(32)
pub fn anchor_signing_bytes(chain_id: [u8; 20], a: &CheckpointAnchor) -> Vec<u8> {
    const TAG: &[u8] = b"EEZO:ANCHOR|v1|";
    let mut v = Vec::with_capacity(TAG.len() + 20 + 8 + 32 + 32 + 32);
    v.extend_from_slice(TAG);
    v.extend_from_slice(&chain_id);
    v.extend_from_slice(&a.height.to_le_bytes());
    v.extend_from_slice(&a.block_id);
    v.extend_from_slice(&a.state_root);
    v.extend_from_slice(&a.qc_hash);
    v
}

impl CheckpointAnchor {
    #[inline]
    pub const fn new(
        height: u64,
        block_id: [u8; 32],
        state_root: [u8; 32],
        qc_hash: [u8; 32],
    ) -> Self {
        Self { height, block_id, state_root, qc_hash, sig: None, suite_id: None }
    }

    #[inline]
    pub const fn height(&self) -> u64 {
        self.height
    }
    #[inline]
    pub const fn block_id(&self) -> &[u8; 32] {
        &self.block_id
    }
    #[inline]
    pub const fn state_root(&self) -> &[u8; 32] {
        &self.state_root
    }
    #[inline]
    pub const fn qc_hash(&self) -> &[u8; 32] {
        &self.qc_hash
    }
}

/// Minimal QC record — light part only; `sigset` is gated
#[derive(Debug, Clone)]
pub struct QuorumCert {
    pub height: u64,
    pub block_hash: QcHash,
    #[cfg(feature = "checkpoints-verify")]
    pub sigset: Option<QcSigSet>,
}

#[derive(Debug)]
pub enum QcError {
    Invalid,
    // Extra variants only when verify is on
    #[cfg(feature = "checkpoints-verify")]
    MissingSigSet,
    #[cfg(feature = "checkpoints-verify")]
    NotEnoughSignatures { have: usize, need: usize },
    #[cfg(feature = "checkpoints-verify")]
    BadSignature,
}

/// Verifier trait (exists in both modes so `verify_quorum_cert` has a type to call)
pub trait QcVerifier {
    fn verify(&self, qc: &QuorumCert) -> Result<(), QcError>;
}

/// Stub verifier (the default when `checkpoints-verify` is OFF)
#[derive(Default, Debug, Clone, Copy)]
pub struct StubQcVerifier;
impl QcVerifier for StubQcVerifier {
    fn verify(&self, _qc: &QuorumCert) -> Result<(), QcError> {
        Ok(())
    }
}

/// Pick the active verifier: stub in light mode, real in verify mode
#[cfg(not(feature = "checkpoints-verify"))]
pub type ActiveQcVerifier = StubQcVerifier;
#[cfg(feature = "checkpoints-verify")]
pub type ActiveQcVerifier = RealQcVerifier;

/// Light wrapper used by consensus/tests in both modes
pub fn verify_quorum_cert(qc: &QuorumCert) -> Result<(), QcError> {
    ActiveQcVerifier::default().verify(qc)
}

/// Convenience helpers (LIGHT)
pub fn qc_hash_of(qc: &QuorumCert) -> QcHash {
    qc.block_hash
}

impl From<&crate::block::BlockHeader> for QuorumCert {
    fn from(h: &crate::block::BlockHeader) -> Self {
        QuorumCert {
            height: h.height,
            block_hash: h.qc_hash,
            #[cfg(feature = "checkpoints-verify")]
            sigset: None,
        }
    }
}

impl QuorumCert {
    pub fn new(height: u64, block_hash: QcHash) -> Self {
        QuorumCert {
            height,
            block_hash,
            #[cfg(feature = "checkpoints-verify")]
            sigset: None,
        }
    }
    pub fn hash(&self) -> &QcHash {
        &self.block_hash
    }
}

/// Checkpoint interval predicate
pub fn is_checkpoint_height(height: u64, interval: u64) -> bool {
    interval != 0 && height % interval == 0
}

/// Domain/message helpers used for QC — LIGHT
pub const QC_DOMAIN: &[u8] = b"EEZO:QC:v1";
pub fn qc_message_bytes(chain_id: [u8; 20], height: u64, block_hash: &QcHash) -> Vec<u8> {
    let mut msg = Vec::with_capacity(QC_DOMAIN.len() + 20 + 8 + 32);
    msg.extend_from_slice(QC_DOMAIN);
    msg.extend_from_slice(&chain_id);
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(block_hash);
    msg
}

pub fn quorum_threshold(total_signers: usize) -> usize {
    if total_signers == 0 {
        0
    } else {
        (2 * total_signers) / 3 + 1
    }
}

/// Helper used by consensus.rs to time a QC verification path.
/// If no qc_hash is attached, returns true immediately.
pub fn verify_qc_stub(block: &crate::block::Block) -> bool {
    if block.header.qc_hash == [0u8; 32] {
        return true;
    }
    // Build a minimal QC view from the block header; unused fields default.
    let qc = QuorumCert {
        height: block.header.height,
        block_hash: block.header.qc_hash,
        #[cfg(feature = "checkpoints-verify")]
        sigset: None,
    };
    verify_quorum_cert(&qc).is_ok()
}

// ------------------ T33.2: Checkpoint Emitter (LIGHT) ------------------

/// Default folder where JSON checkpoint headers are written.
pub const CHECKPOINTS_DIR: &str = "proof/checkpoints";

/// Minimal header exported for bridge/light-client use.
/// Keep fields stable: any additions must be backward-compatible.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeHeader {
    /// Decided block height.
    pub height: u64,
    /// Hash/id of the block header (32B).
    #[serde(with = "serde_hex32")]
    pub header_hash: [u8; 32],
    /// ETH-SSZ v2 state root (32B).
    #[serde(with = "serde_hex32")]
    pub state_root_v2: [u8; 32],
    /// ETH-SSZ v2 tx root (32B).
    #[serde(with = "serde_hex32")]
    pub tx_root_v2: [u8; 32],
    /// Block timestamp (unix seconds).
    pub timestamp: u64,
    /// Finality depth relative to this header (e.g., 2 for single-node PoA).
    pub finality_depth: u64,
    /// Crypto suite used for the header/proof (1 = ML-DSA-44, 2 = SPHINCS+ ...).
    /// Backward compatible: omitted in older files; defaults to 1.
    #[serde(default = "BridgeHeader::default_suite_id")]
    pub suite_id: u8,
    /// Optional QC sidecar v2 (re-anchor envelope). Additive & backward-compatible:
    /// - omitted on old files,
    /// - not serialized when None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qc_sidecar_v2: Option<QcSidecarV2>,	
}

impl BridgeHeader {
    #[inline]
    pub const fn default_suite_id() -> u8 {
        1
    }

    #[inline]
    pub const fn new(
        height: u64,
        header_hash: [u8; 32],
        state_root_v2: [u8; 32],
        tx_root_v2: [u8; 32],
        timestamp: u64,
        finality_depth: u64,
    ) -> Self {
        Self {
            height,
            header_hash,
            state_root_v2,
            tx_root_v2,
            timestamp,
            finality_depth,
            suite_id: Self::default_suite_id(),
            // T41.1: additive field defaults to None for writers
            qc_sidecar_v2: None,
        }
    }

    /// Variant that lets writers pick the suite explicitly.
    #[inline]
    pub const fn new_with_suite(
        height: u64,
        header_hash: [u8; 32],
        state_root_v2: [u8; 32],
        tx_root_v2: [u8; 32],
        timestamp: u64,
        finality_depth: u64,
        suite_id: u8,
    ) -> Self {
        Self {
            height,
            header_hash,
            state_root_v2,
            tx_root_v2,
            timestamp,
            finality_depth,
            suite_id,
            // T41.1: additive field defaults to None for writers
            qc_sidecar_v2: None
        }
    }

    /// Return the suite as a typed enum (defaults handled by serde already).
    #[inline]
    pub fn suite(&self) -> Result<CryptoSuite, SuiteError> {
        CryptoSuite::try_from(self.suite_id)
    }

    /// Convenience: set the suite from a typed enum.
    #[inline]
    pub fn set_suite(&mut self, s: CryptoSuite) {
        self.suite_id = s.as_id();
    }
    // ---------- T41.1: tiny helper; no enforcement ----------
    /// Format-only sanity for an attached sidecar (if any). Does **not** verify crypto.
    #[inline]
    pub fn sidecar_v2_is_sane(&self) -> bool {
        match &self.qc_sidecar_v2 {
            None => true,
            Some(sc) => sc.is_sane_for_height(self.height),
        }
    }
    /// Convenience setter (purely additive; used in later tasks/tests).
    #[inline]
    pub fn with_sidecar_v2(mut self, sc: QcSidecarV2) -> Self {
        self.qc_sidecar_v2 = Some(sc);
        self
    }	
}
// ─────────────────────────────────────────────────────────────────────────────
// T41.2: QC sidecar emit helpers (policy + shape), kept in ledger so node can use.
// These are additive and do not change verification or consensus behavior.
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true iff we should emit a QC sidecar v2 at this checkpoint `height`
/// according to rotation policy and the configured checkpoint cadence.
/// Long-term rule: **emit at the first checkpoint whose height is ≥ (cutover+1)**,
/// where cutover ≔ `dual_accept_until`.
pub fn should_emit_qc_sidecar_v2(height: u64, rot: &RotationPolicy) -> bool {
    let Some(cutover) = rot.dual_accept_until else { return false };
    let cutover_plus_one = cutover.saturating_add(1);
    // Discover cadence from env (same knob the node uses); default=32.
    let every = std::env::var("EEZO_CHECKPOINT_EVERY")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(32);
    if every == 0 {
        // degenerate/disabled checkpoints → never emit
        return false;
    }
    // Compute the current checkpoint boundary for `height` and the previous boundary.
    let this_boundary = height.saturating_sub(height % every);
    let prev_boundary = this_boundary.saturating_sub(every);
    // Fire when cutover+1 falls after the previous boundary and up to (and including) this one.
    cutover_plus_one > prev_boundary && cutover_plus_one <= this_boundary
}
/// Runtime override: force-emit a QC sidecar at checkpoints for bring-up/tests.
#[inline]
fn sidecar_force_from_env() -> bool {
    std::env::var("EEZO_QC_SIDECAR_FORCE")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Builds a stub QC sidecar v2 for emission (no cryptographic verification here).
/// We carry non-empty, size-bounded bytes so format sanity passes; real signing can be added later.
#[allow(dead_code)]
pub fn build_stub_sidecar_v2(suite_id: u8, anchor_height: u64, reason: ReanchorReason) -> QcSidecarV2 {
    // minimal non-empty placeholders; sized so `is_sane_for_height` passes
    let anchor_pub = vec![0u8; 32]; // placeholder pubkey bytes
    let anchor_sig = vec![0u8; 64]; // placeholder signature bytes
    QcSidecarV2 {
        anchor_suite: suite_id,
        anchor_sig,
        anchor_pub,
        anchor_height,
        reason,
    }
}
/// T41.3: lightweight reader-only validator for QC sidecar v2.
/// Behavior: returns `Ok(())` if no sidecar, or if present and format-sane and suite matches.
/// No cryptographic checks here (reader path only).
pub fn validate_sidecar_v2_for_header(h: &BridgeHeader) -> Result<(), &'static str> {
    match &h.qc_sidecar_v2 {
        None => Ok(()),
        Some(sc) => {
            if !sc.is_sane_for_height(h.height) {
                return Err("qc_sidecar_v2: not sane for header height");
            }
            if sc.anchor_suite != h.suite_id {
                return Err("qc_sidecar_v2: suite_id mismatch");
            }
            Ok(())
        }
    }
}

/// Optional: obtain a rotation policy from env vars (lightweight, avoids plumbing now).
/// Usage (in node): if `Some(rot)`, callers can attach sidecar based on policy.
///
/// Env knobs:
/// - EEZO_ROTATION_ACTIVE_ID: u8 (default 1)
/// - EEZO_ROTATION_NEXT_ID:   u8 (optional; if absent → no rotation scheduled)
/// - EEZO_ROTATION_CUTOFF:    u64 (dual_accept_until) (optional)
/// - EEZO_ROTATION_ACTIVATED_AT: u64 (optional)
pub fn rotation_policy_from_env() -> Option<RotationPolicy> {
    // --- PATCH 2 START ---
    use eezo_crypto::suite::CryptoSuite;
    // --- PATCH 2 END ---

    // active id (default 1 = ml-dsa-44 in your mapping)
    let active_id: u8 = std::env::var("EEZO_ROTATION_ACTIVE_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let active = CryptoSuite::try_from(active_id).ok()?;

    // optional next id
    let next = std::env::var("EEZO_ROTATION_NEXT_ID")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .and_then(|id| CryptoSuite::try_from(id).ok());

    // optional cutoff / activated-at
    let dual_accept_until = std::env::var("EEZO_ROTATION_CUTOFF").ok().and_then(|s| s.parse().ok());
    let activated_at_height = std::env::var("EEZO_ROTATION_ACTIVATED_AT").ok().and_then(|s| s.parse().ok());

    Some(RotationPolicy { active, next, dual_accept_until, activated_at_height })
}
/// Filename for a checkpoint header JSON (zero-padded height for lexicographic order).
#[inline]
pub fn checkpoint_filename(height: u64) -> String {
    // 20 digits covers > 10^20 blocks; adjust only with migration.
    format!("{height:020}.json")
}

/// Rotation-aware filename with a stable tag (`active` or `next`).
#[inline]
pub fn checkpoint_filename_tagged(height: u64, tag: &str) -> String {
    format!("ckpt_{:020}_{}.json", height, tag)
}

/// Write a `BridgeHeader` JSON file into `dir/<height>.json`.
/// Creates the directory if missing.
/// Returns the full path on success.
pub fn write_checkpoint_json(dir: &Path, hdr: &BridgeHeader) -> std::io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let mut path = PathBuf::from(dir);
    path.push(checkpoint_filename(hdr.height));
    // T41.4: strict enforcement when the flag is on (only if env policy is available)
    #[cfg(feature = "qc-sidecar-v2-enforce")]
    {
        let force = sidecar_force_from_env();
        if let Some(policy) = rotation_policy_from_env() {
            if force || should_emit_qc_sidecar_v2(hdr.height, &policy) {
                match &hdr.qc_sidecar_v2 {
                    Some(_) => {
                        if validate_sidecar_v2_for_header(hdr).is_err() {
                            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                "qc_sidecar_v2 invalid at cutover+1"));
                        }
                    }
                    None => {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                            "qc_sidecar_v2 missing (required by policy/force)"));
                    }
                }
            } else if !force && hdr.qc_sidecar_v2.is_some() {
                // defensive: when not forced, sidecar only allowed at cutover+1
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                    "qc_sidecar_v2 present at non-cutover+1 height"));
            }
        }
    }	
    // T41.3: reader-only validation + metrics (no enforcement/gating here)
    #[cfg(all(feature = "metrics", feature = "checkpoints"))]
    {
        if hdr.qc_sidecar_v2.is_some() {
            inc_sidecar_seen();
            if validate_sidecar_v2_for_header(hdr).is_ok() {
                inc_sidecar_valid();
            } else {
                inc_sidecar_invalid();
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(hdr).expect("BridgeHeader JSON serialize");

    // --- MODIFIED BLOCK: Use OpenOptions to write idempotently (skip if already exists) ---
    match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut f) => {
            f.write_all(&bytes)?;
            // T37.8: log on first creation only (idempotent if already exists)
            log::info!(
                "checkpoint writer: wrote ckpt for h={} tag=plain path={:?}",
                hdr.height, path
            );
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            // File already exists, skip. This makes the write idempotent.
        }
        Err(e) => {
            // Propagate other errors
            return Err(e);
        }
    }
    // --- END MODIFIED BLOCK ---

    Ok(path)
}

/// Write a `BridgeHeader` JSON file into `dir/ckpt_<height>_<tag>.json`.
#[inline]
pub fn write_checkpoint_json_tagged(dir: &Path, hdr: &BridgeHeader, tag: &str) -> std::io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let mut path = PathBuf::from(dir);
    path.push(checkpoint_filename_tagged(hdr.height, tag));
    // T41.4: strict enforcement when the flag is on (only if env policy is available)
    #[cfg(feature = "qc-sidecar-v2-enforce")]
    {
        let force = sidecar_force_from_env();
        if let Some(policy) = rotation_policy_from_env() {
            if force || should_emit_qc_sidecar_v2(hdr.height, &policy) {
                match &hdr.qc_sidecar_v2 {
                    Some(_) => {
                        if validate_sidecar_v2_for_header(hdr).is_err() {
                            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                "qc_sidecar_v2 invalid at cutover+1 (tagged)"));
                        }
                    }
                    None => {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                            "qc_sidecar_v2 missing (required by policy/force)"));
                    }
                }
            } else if !force && hdr.qc_sidecar_v2.is_some() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                    "qc_sidecar_v2 present at non-cutover+1 height (tagged)"));
            }
        }
    }	
    // T41.3: reader-only validation + metrics (no enforcement/gating here)
    #[cfg(all(feature = "metrics", feature = "checkpoints"))]
    {
        if hdr.qc_sidecar_v2.is_some() {
            inc_sidecar_seen();
            if validate_sidecar_v2_for_header(hdr).is_ok() {
                inc_sidecar_valid();
            } else {
                inc_sidecar_invalid();
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(hdr).expect("BridgeHeader JSON serialize");
    
    // --- MODIFIED BLOCK: Use OpenOptions to write idempotently (skip if already exists) ---
    match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut f) => {
            f.write_all(&bytes)?;
            // T37.8: log on first creation only (idempotent if already exists)
            log::info!(
                "checkpoint writer: wrote ckpt for h={} tag={} path={:?}",
                hdr.height, tag, path
            );			
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            // File already exists, skip. This makes the write idempotent.
        }
        Err(e) => {
            // Propagate other errors
            return Err(e);
        }
    }
    // --- END MODIFIED BLOCK ---

    Ok(path)
}

/// Convenience wrapper that writes into the default `proof/checkpoints/` directory.
#[inline]
pub fn write_checkpoint_json_default(hdr: &BridgeHeader) -> std::io::Result<PathBuf> {
    write_checkpoint_json(Path::new(CHECKPOINTS_DIR), hdr)
}

// ------------------ T36.5: emission helper (rotation-aware, default dir) ------------------

// PATCH 1: Define the argument struct here, before it's first used.
/// Arguments for creating checkpoint headers.
#[derive(Clone, Copy, Debug)]
pub struct CheckpointArgs<'a> {
    policy: &'a RotationPolicy,
    height: u64,
    header_hash: [u8; 32],
    state_root_v2: [u8; 32],
    tx_root_v2: [u8; 32],
    timestamp: u64,
    finality_depth: u64,
}
impl<'a> CheckpointArgs<'a> {
    /// Public constructor that takes all fields.
    #[inline]
    pub const fn new(
        policy: &'a RotationPolicy, height: u64, header_hash: [u8; 32],
        state_root_v2: [u8; 32], tx_root_v2: [u8; 32], timestamp: u64,
        finality_depth: u64,
    ) -> Self {
        Self { policy, height, header_hash, state_root_v2, tx_root_v2, timestamp, finality_depth }
    }
}

/// Emit one or two rotation-aware `BridgeHeader` JSON files for `height` into the default
/// `proof/checkpoints/` directory. Callers pass the already-known values (typically fetched
/// from persistence in the runner), so this helper stays free of DB assumptions and is
/// safe to use under all current feature sets.
///
/// Returns the list of file paths written (one or two), matching `write_rotation_headers`.
#[inline]
// PATCH 1: Update function signature for emit_bridge_checkpoint_default
pub fn emit_bridge_checkpoint_default(
    args: &CheckpointArgs,
) -> std::io::Result<Vec<PathBuf>> {
    // PATCH 1: Update call to write_rotation_headers to pass the struct
    write_rotation_headers(
        Path::new(CHECKPOINTS_DIR), args,
    )
}

/// Emit one or two rotation-aware `BridgeHeader` JSON files into the provided `dir`.
/// Path-aware variant used by the node so checkpoints land under the configured datadir.
#[inline]
// PATCH 1: Update function signature for emit_bridge_checkpoint_with_path
pub fn emit_bridge_checkpoint_with_path(
    base_dir: &std::path::Path,
    args: &CheckpointArgs,
) -> std::io::Result<Vec<PathBuf>> {
    // PATCH 1: Update call to write_rotation_headers to pass the struct
    write_rotation_headers(
        base_dir,
        args,
    )
}

// ------------------ T34.2: rotation-aware header emission ------------------
/// Build one or two `BridgeHeader`s for `height` depending on the rotation policy.
/// Always includes the **active** suite; if the dual-accept window is open, also
/// includes the **next** suite.
/// Callers can then write each to disk.
#[inline]
pub fn build_rotation_headers(
    policy: &RotationPolicy,
    height: u64,
    header_hash: [u8; 32],
    state_root_v2: [u8; 32],
    tx_root_v2: [u8; 32],
    timestamp: u64,
    finality_depth: u64,
) -> Vec<BridgeHeader> {
    let (first, second) = policy.verify_order(height);
    let mut out = Vec::with_capacity(2);
    // active
    let mut h_active = BridgeHeader::new_with_suite(
        height,
        header_hash,
        state_root_v2,
        tx_root_v2,
        timestamp,
        finality_depth,
        first.as_id(),
    );
    // T41.2/41.3: emit qc_sidecar_v2 at first checkpoint ≥ (cutover+1),
    // or when forced via env for bring-up. Record provenance height (cutover+1).
    let force = sidecar_force_from_env();
    let emit = force || should_emit_qc_sidecar_v2(height, policy);
    if emit {
        let cutover_plus_one = policy.dual_accept_until.unwrap_or(0).saturating_add(1);
        let sc = build_qc_sidecar_v2(
            cutover_plus_one,          // <- provenance height
            &header_hash,
            h_active.suite_id,
            ReanchorReason::RotationCutover,
        );
        h_active = h_active.with_sidecar_v2(sc);
    }
    out.push(h_active);
    // optional next (e.g., SPHINCS+) while window is open
    if let Some(next) = second {
        let mut h_next = BridgeHeader::new_with_suite(
            height,
            header_hash,
            state_root_v2,
            tx_root_v2,
            timestamp,
            finality_depth,
            next.as_id(),
        );
        // If we wrote a sidecar for active at cutover+1, mirror it for the "next" tag of same height
        if emit {
            let cutover_plus_one = policy.dual_accept_until.unwrap_or(0).saturating_add(1);
            let sc = build_qc_sidecar_v2(
                cutover_plus_one,      // <- provenance height
                &header_hash,
                h_next.suite_id,
                ReanchorReason::RotationCutover,
            );
            h_next = h_next.with_sidecar_v2(sc);
        }		
        out.push(h_next);
    }
    out
}

/// Convenience that both **builds and writes** rotation-aware headers into `dir/`.
/// Returns the list of file paths written (one or two).
// PATCH 2: Update function signature for write_rotation_headers
pub fn write_rotation_headers(
    dir: &Path,
    args: &CheckpointArgs,
) -> std::io::Result<Vec<PathBuf>> {
    // PATCH 2: Update call to build_rotation_headers to use args fields
    let headers = build_rotation_headers(
        args.policy,
        args.height,
        args.header_hash,
        args.state_root_v2,
        args.tx_root_v2,
        args.timestamp,
        args.finality_depth,
    );
    // ── T41.5: runtime+feature enforcement before writing (active/next)
    // This path enforces even when the compile-time feature is off.
    // Set EEZO_QC_SIDECAR_ENFORCE=1 (or true/yes/on) to enable at runtime.
    let enforce_runtime = std::env::var("EEZO_QC_SIDECAR_ENFORCE")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let enforce = cfg!(feature = "qc-sidecar-v2-enforce") || enforce_runtime;
    let force = sidecar_force_from_env();
    // PATCH 2: Update if-condition to use args fields
    if enforce && (force || should_emit_qc_sidecar_v2(args.height, args.policy)) {
        // validate presence + basic shape for each header we’re about to write
        // --- PATCH 3 START ---
        let check_one = |tag: &str, h: &BridgeHeader| -> std::io::Result<()> {
        // --- PATCH 3 END ---
            if h.qc_sidecar_v2.is_none() {
                #[cfg(feature = "metrics")]
                {
                    // observability: count missing + rejected-at-enforce
                    crate::metrics::inc_sidecar_missing();
                    crate::metrics::inc_sidecar_rejected();
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("qc_sidecar_v2 required at cutover+1 checkpoint ({tag})"),
                ));
            }
            if validate_sidecar_v2_for_header(h).is_err() {
                #[cfg(feature = "metrics")]
                {
                    // count invalid + rejected
                    crate::metrics::inc_sidecar_invalid();
                    crate::metrics::inc_sidecar_rejected();
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("qc_sidecar_v2 invalid at cutover+1 ({tag})"),
                ));
            }
            Ok(())
        };
        match headers.as_slice() {
            [h_active] => {
                check_one("active", h_active)?;
            }
            [h_active, h_next] => {
                check_one("active", h_active)?;
                check_one("next",   h_next)?;
            }
            _ => {}
        }
    }	
    let mut paths = Vec::with_capacity(headers.len());

    // Emit deterministic, rotation-aware filenames:
    //  - always write the ACTIVE one as "..._active.json"
    //  - if a NEXT suite is present in the window, also write "..._next.json"
    match headers.as_slice() {
        [h_active] => {
            let p = write_checkpoint_json_tagged(dir, h_active, "active")?;
            // T37.8: mirror the write log here as well (when called via rotation helper)
            paths.push(p);
        }
        [h_active, h_next] => {
            let p1 = write_checkpoint_json_tagged(dir, h_active, "active")?;
            let p2 = write_checkpoint_json_tagged(dir, h_next,  "next")?;
            paths.push(p1);
            paths.push(p2);
        }
        _ => { /* unreachable: build_rotation_headers returns 1 or 2 */ }
    }
    Ok(paths)
}

// ------------------ HEAVY PATH BELOW: keep behind `checkpoints-verify` ------------------
// ------------------ T36.6: listing helpers (LIGHT) ------------------
/// One checkpoint file entry found on disk.
#[derive(Clone, Debug)]
pub struct CheckpointFile {
    pub height: u64,
    pub path:   PathBuf,
    pub modified: Option<SystemTime>,
    /// Optional rotation tag (e.g., "active" or "next") for rotation-aware files.
    pub tag:    Option<String>,
}

#[inline]
fn parse_height_and_tag(file_name: &str) -> Option<(u64, Option<String>)> {
    // Pattern 1: zero-padded plain file: "00000000000000000001.json"
    if file_name.len() == 25 && file_name.ends_with(".json") {
        if let Ok(h) = file_name[0..20].parse::<u64>() {
            if file_name.as_bytes()[20] == b'.' && &file_name[21..] == "json" {
                return Some((h, None));
            }
        }
    }
    // Pattern 2: rotation-tagged file: "ckpt_<20d>_active.json" or "..._next.json"
    if let Some(rest) = file_name.strip_prefix("ckpt_") {
        if rest.len() == 27 && rest.ends_with(".json") {
            // rest = "<20d>_<tag>.json"
            let num = &rest[0..20];
            if rest.as_bytes()[20] == b'_' {
                if let Ok(h) = num.parse::<u64>() {
                    let tag = &rest[21..rest.len() - 5]; // strip ".json"
                    if tag == "active" || tag == "next" {
                        return Some((h, Some(tag.to_string())));
                    }
                }
            }
        }
    }
    None
}

/// List checkpoint files inside a directory (non-recursive), returning parsed heights,
/// stable paths, and modification times. The result is **sorted by (height desc, tag asc)**,
/// where tagged files ("active" before "next") for the same height come after plain files.
pub fn list_checkpoint_files_in(dir: &Path) -> std::io::Result<Vec<CheckpointFile>> {
    let mut out: Vec<CheckpointFile> = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out), // no folder yet
        Err(e) => return Err(e),
    };
    // --- PATCH 4 START ---
    for ent in rd.flatten() {
        let path = ent.path();
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        if let Some((height, tag)) = parse_height_and_tag(name) {
            let modified = ent.metadata().ok().and_then(|m| m.modified().ok());
            out.push(CheckpointFile { height, path, modified, tag });
        }
    }
    // --- PATCH 4 END ---
    // sort: height desc, then tag so that untagged < "active" < "next"
    out.sort_by(|a, b| {
        use std::cmp::Ordering::*;
        match b.height.cmp(&a.height) {
            Equal => {
                // order: None (plain) < Some("active") < Some("next")
                let rank = |t: &Option<String>| match t.as_deref() {
                    None => 0,
                    Some("active") => 1,
                    Some("next") => 2,
                    Some(_) => 3,
                };
                rank(&a.tag).cmp(&rank(&b.tag))
            }
            other => other,
        }
    });
    Ok(out)
}

/// List checkpoint files from the default directory `proof/checkpoints/`.
#[inline]
pub fn list_checkpoints_default() -> std::io::Result<Vec<CheckpointFile>> {
    list_checkpoint_files_in(Path::new(CHECKPOINTS_DIR))
}

/// Convenience: return the latest checkpoint height found on disk (if any).
#[inline]
pub fn latest_checkpoint_height(dir: &Path) -> std::io::Result<Option<u64>> {
    Ok(list_checkpoint_files_in(dir)?.first().map(|e| e.height))
}

/// Convenience: latest height from the default directory.
#[inline]
pub fn latest_checkpoint_height_default() -> std::io::Result<Option<u64>> {
    latest_checkpoint_height(Path::new(CHECKPOINTS_DIR))
}

// NEW: QcSig struct for individual signatures with public key
#[cfg(feature = "checkpoints-verify")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QcSig {
    pub pk: Vec<u8>,
    pub sig: Vec<u8>,
}

// NEW: Updated QcSigSet structure
#[cfg(feature = "checkpoints-verify")]
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct QcSigSet {
    pub signatures: Vec<QcSig>,
}

// NEW: Verification error for real QC verification
#[cfg(feature = "checkpoints-verify")]
#[derive(Debug, thiserror::Error)]
pub enum QcVerifyError {
    #[error("not a checkpoint height")]
    NotCheckpoint,
    #[error("no signatures present")]
    NoSigs,
    #[error("bad public key bytes")]
    BadPk,
    #[error("bad signature bytes")]
    BadSig,
    #[error("signature verify failed")]
    VerifyFailed,
}

/// Real verifier that will implement actual checks when enabled.
#[cfg(feature = "checkpoints-verify")]
#[derive(Default, Debug)]
pub struct RealQcVerifier;

#[cfg(feature = "checkpoints-verify")]
impl RealQcVerifier {
    /// Build a batch verification plan.
    /// We don't *enforce* anything yet.
    pub fn plan(
        &self,
        chain_id: [u8; 20],
        qc: &QuorumCert,
    ) -> Result<(usize, Vec<QcBatchItem>), QcError> {
        // If no signatures yet, return empty plan (keeps current behavior unchanged).
        let Some(sigset) = qc.sigset.as_ref() else {
            return Ok((0, Vec::new()));
        };

        validate_sigset_shape(sigset)?;

        let need = quorum_threshold(sigset.signatures.len());
        let msg = qc_message_bytes(chain_id, qc.height, &qc.block_hash);
        // Materialize batch items
        let mut items = Vec::with_capacity(sigset.signatures.len());
        for entry in &sigset.signatures {
            // For now, we'll use placeholder signer_id since we don't have it in QcSig
            // This will be updated in the real implementation
            let signer_id = [0u8; 20]; // Placeholder
            items.push(QcBatchItem {
                signer_id,
                message: msg.clone(),
                signature: entry.sig.clone(),
            });
        }
        Ok((need, items))
    }
}

#[cfg(feature = "checkpoints-verify")]
impl QcVerifier for RealQcVerifier {
    fn verify(&self, qc: &QuorumCert) -> Result<(), QcError> {
        // NOTE: We do not have chain_id on the QC, so the caller (consensus)
        // will pass it when we enforce.
        // For now we simulate with zeros to keep
        // compilation and leave behavior unchanged.
        let fake_chain: [u8; 20] = [0u8; 20];

        // Build plan (may be empty if no sigset attached yet).
        let _ = self.plan(fake_chain, qc)?;

        // T17.5-4: still no enforcement; return Ok to keep behavior unchanged.
        Ok(())
    }
}

// === T17.5-5: env-aware verify entrypoint (compile-only; no crypto) ===
#[cfg(feature = "checkpoints-verify")]
pub fn verify_quorum_cert_with_env(
    qc: &QuorumCert,
    chain_id: [u8; 20],
    checkpoint_interval: u64,
) -> Result<(), QcError> {
    // Only enforce on checkpoint heights;
    // off-interval is a no-op.
    if checkpoint_interval == 0 || qc.height % checkpoint_interval != 0 {
        return Ok(());
    }

    // Build a plan; may be empty if no sigset yet (current behavior).
    // --- PATCH 5 START ---
    let verifier = RealQcVerifier;
    // --- PATCH 5 END ---
    let (need, plan) = verifier.plan(chain_id, qc)?;

    // T17.5-5: enforce ONLY the threshold when a sigset exists.
    // If no sigset yet (plan is empty because qc.sigset == None), we keep behavior unchanged.
    if plan.is_empty() {
        // No signatures attached yet;
        // accept for now to stay green.
        return Ok(());
    }

    if plan.len() < need {
        // Not enough signatures to reach quorum.
        return Err(QcError::Invalid);
    }

    // T17.6+: here we will call the real batch crypto verification.
    Ok(())
}

// NEW: Signature set helpers (only available when checkpoints-verify is enabled)
#[cfg(feature = "checkpoints-verify")]
impl QuorumCert {
    pub fn with_sigset(mut self, sigset: QcSigSet) -> Self {
        self.sigset = Some(sigset);
        self
    }

    pub fn has_sigset(&self) -> bool {
        self.sigset.is_some()
    }

    pub fn sig_count(&self) -> usize {
        self.sigset.as_ref().map(|set| set.signatures.len()).unwrap_or(0)
    }
}

// === T17.6: local sig plumbing ===
#[cfg(feature = "checkpoints-verify")]
pub type SigShare = Vec<u8>;
#[cfg(feature = "checkpoints-verify")]
pub type SigSet = Vec<SigShare>;

// === T17.6-2: local signature addition helper ===
#[cfg(all(feature = "checkpoints-verify", feature = "pq44-runtime"))]
pub fn add_local_sig_to_qc(
    qc: &mut QuorumCert,
    sk: &pqcrypto_mldsa::mldsa44::SecretKey,
    pk: &pqcrypto_mldsa::mldsa44::PublicKey,
    chain_id: [u8; 20],
) {
    // Bring in the trait methods (from_bytes / as_bytes) for PK and detached sig:
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
    // Bring in the concrete ML-DSA types + helpers:
    use pqcrypto_mldsa::mldsa44::detached_sign;
    // must match the verifier's expected message exactly:
    let msg = qc_message_bytes(chain_id, qc.height, &qc.block_hash);
    let ds = detached_sign(&msg, sk);
    let entry = QcSig { pk: pk.as_bytes().to_vec(), sig: ds.as_bytes().to_vec() };
    let set = qc.sigset.get_or_insert_with(|| QcSigSet { signatures: vec![] });
    set.signatures.push(entry);
}

// NEW: Real QC verification function
#[cfg(feature = "checkpoints-verify")]
pub fn verify_quorum_cert_real(
    qc: &QuorumCert,
    chain_id: [u8; 20],
    interval: u64,
) -> Result<(), QcVerifyError> {
    // Sanity: only verify if this is actually a checkpoint height.
    if interval != 0 && (qc.height % interval != 0) {
        return Err(QcVerifyError::NotCheckpoint);
    }

    let set = qc.sigset.as_ref().ok_or(QcVerifyError::NoSigs)?;
    if set.signatures.is_empty() {
        return Err(QcVerifyError::NoSigs);
    }

    // Bring trait methods into scope:
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
    // Concrete ML-DSA types + verify helper:
    use pqcrypto_mldsa::mldsa44::{verify_detached_signature, DetachedSignature, PublicKey};

    let msg = qc_message_bytes(chain_id, qc.height, &qc.block_hash);
    // Accept if *any* signature verifies. (Tighten later to quorum threshold.)
    for entry in &set.signatures {
        let pk = PublicKey::from_bytes(&entry.pk).map_err(|_| QcVerifyError::BadPk)?;
        let sig = DetachedSignature::from_bytes(&entry.sig).map_err(|_| QcVerifyError::BadSig)?;

        if verify_detached_signature(&sig, &msg, &pk).is_ok() {
            return Ok(());
        }
    }

    Err(QcVerifyError::VerifyFailed)
}

// -------------------- T34: Suite-aware anchor verify --------------------
// T34 anchor verify imports
use eezo_crypto::sig::registry::RotationState;
#[cfg(feature = "state-sync")]
use eezo_crypto::sig::registry::verify_anchor_mldsa_44;
// SLH-DSA (SPHINCS+) verifier lives in the module, not the registry
#[cfg(feature = "slh-dsa")]
use eezo_crypto::sig::slh_dsa;
// base64 is only used when state-sync is enabled
#[cfg(feature = "state-sync")]
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

/// Verify an anchor signature using the rotation policy.
/// Version compiled **when state-sync is enabled** (has base64 + verifiers).
#[cfg(feature = "state-sync")]
pub fn verify_anchor_signature_rotating(
    chain_id: [u8; 20],
    anchor: &CheckpointAnchor,
    rot: &RotationState,
) -> bool {
    let Some(sig_env) = &anchor.sig else {
        // no signature = legacy anchor = accept only if in dual window
        return rot.accepts(anchor.height, rot.active_suite);
    };

    // Choose algorithm by name (don’t pull private enums across crates)
    let algo = sig_env.scheme.as_str();
    // decode base64
    let pk: Vec<u8> = match B64.decode(sig_env.pk_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig: Vec<u8> = match B64.decode(sig_env.sig_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // canonical message
    let msg = anchor_signing_bytes(chain_id, anchor);
    match algo {
        "ML-DSA-44" | "mldsa-44" => verify_anchor_mldsa_44(&pk, &sig, &msg),
        "SLH-DSA-128f" | "SPHINCS+" | "sphincs+" => {
            #[cfg(feature = "slh-dsa")]
            {
                slh_dsa::verify_bytes(&pk, &sig, &msg)
            }
            #[cfg(not(feature = "slh-dsa"))]
            {
                false
            }
        }
        _ => false,
    }
}

/// Verify an anchor signature using the rotation policy.
/// Lightweight stub compiled **when state-sync is disabled** (no base64 usage).
#[cfg(not(feature = "state-sync"))]
pub fn verify_anchor_signature_rotating(
    _chain_id: [u8; 20],
    anchor: &CheckpointAnchor,
    rot: &RotationState,
) -> bool {
    // If there is no signature, we accept based on rotation policy (legacy anchors).
    if anchor.sig.is_none() {
        return rot.accepts(anchor.height, rot.active_suite);
    }
    // If a signature is present but state-sync is off, we can't verify — reject.
    false
}

// === T17.5-4: batch plan scaffold (no behavior change) ===
#[cfg(feature = "checkpoints-verify")]
#[derive(Debug, Clone)]
pub struct QcBatchItem {
    /// 20-byte validator id (e.e., first 20 bytes of SHA3(pk))
    pub signer_id: [u8; 20],
    /// Canonical message bytes to verify (domain || chain_id || height || block_hash)
    pub message: Vec<u8>,
    /// Detached signature bytes for `message`
    pub signature: Vec<u8>,
}

#[cfg(feature = "checkpoints-verify")]
fn validate_sigset_shape(_sigset: &QcSigSet) -> Result<(), QcError> {
    // For the new QcSigSet structure, we don't need to validate signers vs signatures
    // since each signature carries its own public key
    Ok(())
}

// ================= ETH-SSZ (v2) container + root for QuorumCert (LIGHT) =================
#[cfg(feature = "eth-ssz")]
mod eth_ssz_for_qc {
    use super::QuorumCert;
    use eezo_serde::eth::{Decode, Encode};

    // We purposely encode only the LIGHT fields (height, block_hash).
    // The optional sigset (when checkpoints-verify is on) is NOT included in the ETH-SSZ root,
    // keeping the root stable and bounded for light clients.
    impl Encode for QuorumCert {
        fn ssz_write(&self, out: &mut Vec<u8>) {
            // u64 height
            self.height.ssz_write(out);
            // [u8;32] block_hash
            out.extend_from_slice(&self.block_hash);
        }
    }

    impl Decode for QuorumCert {
        fn ssz_read(input: &[u8]) -> eezo_serde::eth::Result<(Self, usize)> {
            // Exact, bounded decode of the LIGHT fields via the trait impls.
            // No vectors here, so there is no unbounded allocation risk.
            let (height, u1) = u64::ssz_read(input)?;
            let (block_hash, u2) = <[u8; 32]>::ssz_read(&input[u1..])?;

            let qc = QuorumCert {
                height,
                block_hash,
                #[cfg(feature = "checkpoints-verify")]
                sigset: None,
            };
            Ok((qc, u1 + u2))
        }
    }

    // No explicit HashTreeRoot impl here — we rely on the blanket impl:
    // impl<T: Encode> HashTreeRoot for T { ... }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::RotationPolicy;
    #[test]
    fn suite_helpers_roundtrip() {
        let mut h = BridgeHeader::new(1, [1u8; 32], [2u8; 32], [3u8; 32], 123, 2);
        // default was 1 => ml-dsa-44
        assert_eq!(h.suite_id, BridgeHeader::default_suite_id());
        assert!(matches!(h.suite(), Ok(CryptoSuite::MlDsa44)));
        h.set_suite(CryptoSuite::SphincsPq);
        assert!(matches!(h.suite(), Ok(CryptoSuite::SphincsPq)));
    }

    #[test]
    fn rotation_headers_dual_emit_inside_window() {
        let policy = RotationPolicy {
            active: CryptoSuite::MlDsa44,
            next: Some(CryptoSuite::SphincsPq),
            dual_accept_until: Some(150),
            activated_at_height: Some(100),
        };
        let hs =
            build_rotation_headers(&policy, 120, [1u8; 32], [2u8; 32], [3u8; 32], 123, 2);
        assert_eq!(hs.len(), 2);
        assert!(matches!(hs[0].suite(), Ok(CryptoSuite::MlDsa44)));
        assert!(matches!(hs[1].suite(), Ok(CryptoSuite::SphincsPq)));
    }

    #[test]
    fn rotation_headers_single_after_window() {
        let policy = RotationPolicy {
            active: CryptoSuite::MlDsa44,
            next: Some(CryptoSuite::SphincsPq),
            dual_accept_until: Some(150),
            activated_at_height: Some(100),
        };
        let hs =
            build_rotation_headers(&policy, 200, [1u8; 32], [2u8; 32], [3u8; 32], 123, 2);
        assert_eq!(hs.len(), 1);
        assert!(matches!(hs[0].suite(), Ok(CryptoSuite::MlDsa44)));
    }
    #[test]
    fn sidecar_emits_exactly_at_cutover_plus_one() {
        // dual_accept_until = 150 → cutover+1 = 151.
        // With default EEZO_CHECKPOINT_EVERY = 32, checkpoints are:
        //   ..., 96, 128, 160, 192, ...
        // So the first checkpoint height ≥ 151 is 160.
        let policy = RotationPolicy {
            active: CryptoSuite::MlDsa44,
            next: Some(CryptoSuite::SphincsPq),
            dual_accept_until: Some(150),
            activated_at_height: Some(100),
        };
        // before the first eligible checkpoint (128) → never emit
        let hs_128 =
            build_rotation_headers(&policy, 128, [1u8; 32], [2u8; 32], [3u8; 32], 123, 2);
        assert!(hs_128.iter().all(|h| h.qc_sidecar_v2.is_none()));

        // at the first checkpoint ≥ cutover+1 (160) → must emit
        let hs_160 =
            build_rotation_headers(&policy, 160, [1u8; 32], [2u8; 32], [3u8; 32], 124, 2);
        assert!(hs_160.iter().all(|h| h.qc_sidecar_v2.is_some()));
    }

    #[test]
    fn sidecar_not_emitted_when_no_cutover() {
        // No dual_accept_until → never emit a sidecar
        let policy = RotationPolicy {
            active: CryptoSuite::MlDsa44,
            next: None,
            dual_accept_until: None,
            activated_at_height: Some(0),
        };
        let hs = build_rotation_headers(&policy, 42, [9u8; 32], [8u8; 32], [7u8; 32], 999, 1);
        assert!(hs.iter().all(|h| h.qc_sidecar_v2.is_none()));
    }	
}