//! Persistence layer for the ledger, handling storage of blocks, headers, transactions, and state snapshots.
#[cfg(feature = "persistence")]
use crate::accounts::{Accounts, StateError as AccountsStateError};
#[cfg(feature = "persistence")]
use crate::block::{Block, BlockHeader};
#[cfg(feature = "persistence")]
use crate::bridge::BridgeState;
#[cfg(all(feature = "persistence", feature = "metrics"))]
use crate::metrics;
#[cfg(feature = "persistence")]
use crate::supply::{StateError as SupplyStateError, Supply};
#[cfg(feature = "persistence")]
use bincode::{deserialize, serialize};
#[cfg(feature = "persistence")]
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
#[cfg(feature = "persistence")]
use sha3::Digest;
#[cfg(feature = "persistence")]
use std::time::Instant;
#[cfg(feature = "persistence")]
use thiserror::Error;
// === State-sync additions ===
#[cfg(all(feature = "persistence", feature = "state-sync"))]
use crate::checkpoints::{AnchorSig, CheckpointAnchor};
#[cfg(all(feature = "persistence", feature = "state-sync"))]
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
#[cfg(all(feature = "persistence", feature = "state-sync"))]
use std::cmp::Ordering;

// Suite IDs (for legacy anchor decode default)
#[cfg(all(feature = "persistence", feature = "state-sync"))]
use eezo_crypto::suite::CryptoSuite;
// --- constants
#[cfg(feature = "persistence")]
const CF_BLOCKS: &str = "blocks";
#[cfg(feature = "persistence")]
const CF_HEADERS: &str = "headers";
#[cfg(feature = "persistence")]
const CF_TX_INDEX: &str = "tx_index";
#[cfg(feature = "persistence")]
const CF_METADATA: &str = "metadata";
#[cfg(feature = "persistence")]
pub const CF_SNAPSHOTS: &str = "snapshots";

#[cfg(feature = "persistence")]
const META_TIP: &[u8] = b"tip";
#[cfg(feature = "persistence")]
const META_GENESIS: &[u8] = b"genesis";
// ── T32.1: continuity markers (stored in CF_METADATA) ────────────────────────
#[cfg(feature = "persistence")]
const META_LAST_HEADER: &[u8] = b"continuity:last_header";
#[cfg(feature = "persistence")]
const META_LAST_SNAPSHOT_V2: &[u8] = b"continuity:last_snapshot_v2";

// === State-sync: anchor key ===
#[cfg(all(feature = "persistence", feature = "state-sync"))]
const KEY_LAST_CHECKPOINT_ANCHOR: &[u8] = b"meta:last_checkpoint_anchor:v1";
// --- ETH-SSZ Light header anchor storage (v2) ---
#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
use crate::light::LightHeader;
#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
use eezo_serde::eth::{Decode as EthDecode, Encode as EthEncode};
// Key under CF_METADATA for the v2 light anchor (ETH-SSZ)
#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
const KEY_LIGHT_ANCHOR_V2: &[u8] = b"meta:light_anchor:v2";
#[cfg(feature = "persistence")]
#[derive(Debug, Error)]
pub enum PersistError {
    #[error("rocksdb error: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("codec error: {0}")]
    Codec(#[from] Box<bincode::ErrorKind>),
    #[error("accounts state error: {0}")]
    Accounts(#[from] AccountsStateError),
    #[error("supply state error: {0}")]
    Supply(#[from] SupplyStateError),
    #[error("not found")]
    NotFound,
    #[error("internal: {0}")]
    Internal(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(feature = "persistence")]
pub type Result<T> = std::result::Result<T, PersistError>;
#[cfg(feature = "persistence")]
pub struct Persistence {
    db: DB,
}

#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
#[inline]
fn default_codec_v1() -> u8 {
    1
}

#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
#[inline]
fn default_zero32() -> [u8; 32] {
    [0u8; 32]
}

#[cfg(feature = "persistence")]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct StateSnapshot {
    pub height: u64,
    pub accounts: Accounts,
    pub supply: Supply,
    pub state_root: [u8; 32],
    /// Bridge module persistent state (Alpha). Optional for back-compat.
    /// When absent (older snapshots), the node should treat it as empty/default.
    #[serde(default)] // IMPORTANT: do not skip for bincode; write the Option tag (0/1)
    pub bridge: Option<BridgeState>,

    /// Snapshot codec version: 1 = SSZ-lite (v1), 2 = ETH-SSZ (v2).
    /// Only present when the `eth-ssz` feature is enabled; older snapshots deserialize with default=1.
    #[cfg(feature = "eth-ssz")]
    #[serde(default = "default_codec_v1")]
    pub codec_version: u8,

    /// ETH-SSZ state root (v2).
    /// Default = all-zero for legacy snapshots.
    #[cfg(feature = "eth-ssz")]
    #[serde(default = "default_zero32")]
    pub state_root_v2: [u8; 32],
}

#[cfg(feature = "persistence")]
#[allow(dead_code)]
fn opts(enable_compression: bool, _cache_size_mb: usize) -> Options {
    let mut o = Options::default();
    o.create_if_missing(true);
    o.create_missing_column_families(true);
    if enable_compression {
        o.set_compression_type(rocksdb::DBCompressionType::Lz4);
    }
    o
}

#[cfg(feature = "persistence")]
pub fn open_db(cfg: &crate::config::PersistenceCfg) -> Result<Persistence> {
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    if cfg.enable_compression {
        db_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    }

    let cfs = vec![
        ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
        ColumnFamilyDescriptor::new(CF_HEADERS, Options::default()),
        ColumnFamilyDescriptor::new(CF_TX_INDEX, Options::default()),
        ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
        ColumnFamilyDescriptor::new(CF_SNAPSHOTS, Options::default()),
    ];
    let _start = Instant::now();
    let db = DB::open_cf_descriptors(&db_opts, &cfg.db_path, cfs)?;
    #[cfg(feature = "metrics")]
    {
        let ms = _start.elapsed().as_millis() as u64;
        metrics::RECOVERY_DUR_MS.inc_by(ms);
    }

    Ok(Persistence { db })
}

#[cfg(feature = "persistence")]
fn k_height(h: u64) -> [u8; 8] {
    h.to_be_bytes()
}

#[cfg(feature = "persistence")]
fn k_tx_hash(hash32: [u8; 32]) -> [u8; 32] {
    hash32
}

#[cfg(feature = "persistence")]
fn tx_hash(tx: &crate::SignedTx) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let bytes = crate::block::encode_signed_tx(tx);
    let mut hasher = Sha3_256::new();
    hasher.update(&bytes);
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out[..32]);
    h
}

// === State-sync: fixed encoding helpers ===
#[cfg(all(feature = "persistence", feature = "state-sync"))]
fn encode_anchor(a: &CheckpointAnchor) -> [u8; 105] {
    let mut out = [0u8; 105];
    out[0] = 1; // version
    out[1..9].copy_from_slice(&a.height.to_le_bytes());
    out[9..41].copy_from_slice(&a.block_id);
    out[41..73].copy_from_slice(&a.state_root);
    out[73..105].copy_from_slice(&a.qc_hash);
    out
}

#[cfg(all(feature = "persistence", feature = "state-sync"))]
fn decode_anchor(buf: &[u8]) -> Option<CheckpointAnchor> {
    if buf.len() != 105 || buf[0] != 1 {
        return None;
    }
    let mut height_bytes = [0u8; 8];
    height_bytes.copy_from_slice(&buf[1..9]);
    let mut block_id = [0u8; 32];
    block_id.copy_from_slice(&buf[9..41]);
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&buf[41..73]);
    let mut qc_hash = [0u8; 32];
    qc_hash.copy_from_slice(&buf[73..105]);
    Some(CheckpointAnchor {
        height: u64::from_le_bytes(height_bytes),
        block_id,
        state_root,
        qc_hash,
        suite_id: Some(CryptoSuite::MlDsa44.as_id()),
        // V1 legacy value has no signature
        sig: None,
    })
}

// === T29.9: Backward-compatible variable-length (V1 or V2) encoding ===
// V1 (legacy): [ ver=1 | height(8) | block_id(32) | state_root(32) | qc_hash(32) ]  => 105 bytes
// V2 (signed): [ ver=2 | height(8) | block_id(32) | state_root(32) | qc_hash(32)
//                | algo_id(1) | pk_len(2 LE) | sig_len(2 LE) | pk[..] | sig[..] ]
// For now we reserve algo_id=1 for ML-DSA-44 and enforce strict lengths (pk=1312, sig=2420).
#[cfg(all(feature = "persistence", feature = "state-sync"))]
const ALGO_ID_MLDSA44: u8 = 1;
#[cfg(all(feature = "persistence", feature = "state-sync"))]
#[allow(dead_code)]
const ANCHOR_V1_LEN: usize = 1 + 8 + 32 + 32 + 32;
#[cfg(all(feature = "persistence", feature = "state-sync"))]
const V2_FIXED_HDR: usize = 1 + 8 + 32 + 32 + 32 + 1 + 2 + 2;
#[cfg(all(feature = "persistence", feature = "state-sync"))]
fn encode_anchor_any(a: &CheckpointAnchor) -> Vec<u8> {
    match &a.sig {
        None => encode_anchor(a).to_vec(),
        Some(sig) => {
            // Validate scheme & base64 once before writing
            if sig.scheme.as_str() != "ML-DSA-44" {
                // Fall back to legacy encoding if unknown scheme (keeps system usable).
                // Alternatively: panic to force operator fix; choose policy here.
                return encode_anchor(a).to_vec();
            }
            let pk = match B64.decode(sig.pk_b64.as_bytes()) {
                Ok(v) => v,
                Err(_) => return encode_anchor(a).to_vec(),
            };
            let sg = match B64.decode(sig.sig_b64.as_bytes()) {
                Ok(v) => v,
                Err(_) => return encode_anchor(a).to_vec(),
            };
            // Strict length checks for ML-DSA-44
            if pk.len() != 1312 || sg.len() != 2420 {
                return encode_anchor(a).to_vec();
            }
            let mut out = Vec::with_capacity(V2_FIXED_HDR + pk.len() + sg.len());
            out.push(2); // version
            out.extend_from_slice(&a.height.to_le_bytes());
            out.extend_from_slice(&a.block_id);
            out.extend_from_slice(&a.state_root);
            out.extend_from_slice(&a.qc_hash);
            out.push(ALGO_ID_MLDSA44);
            out.extend_from_slice(&(pk.len() as u16).to_le_bytes());
            out.extend_from_slice(&(sg.len() as u16).to_le_bytes());
            out.extend_from_slice(&pk);
            out.extend_from_slice(&sg);
            out
        }
    }
}

#[cfg(all(feature = "persistence", feature = "state-sync"))]
fn decode_anchor_any(buf: &[u8]) -> Option<CheckpointAnchor> {
    let ver = *buf.first()?;
    match ver {
        1 => decode_anchor(buf),
        2 => {
            if buf.len() < V2_FIXED_HDR {
                return None;
            }
            let mut off = 1;
            let mut take = |n: usize| {
                let s = &buf[off..off + n];
                off += n;
                s
            };
            let height = u64::from_le_bytes(take(8).try_into().ok()?);
            let block_id = <[u8; 32]>::try_from(take(32)).ok()?;
            let state_root = <[u8; 32]>::try_from(take(32)).ok()?;
            let qc_hash = <[u8; 32]>::try_from(take(32)).ok()?;
            let algo = take(1)[0];
            let pk_len = u16::from_le_bytes(take(2).try_into().ok()?) as usize;
            let sg_len = u16::from_le_bytes(take(2).try_into().ok()?) as usize;
            if buf.len() < off + pk_len + sg_len {
                return None;
            }
            let pk = &buf[off..off + pk_len];
            off += pk_len;
            let sg = &buf[off..off + sg_len];
            // Strictly accept only ML-DSA-44 for now
            if algo != ALGO_ID_MLDSA44 || pk_len != 1312 || sg_len != 2420 {
                return None;
            }
            let sig = AnchorSig {
                scheme: "ML-DSA-44".to_string(),
                pk_b64: B64.encode(pk),
                sig_b64: B64.encode(sg),
            };
            Some(CheckpointAnchor {
                height,
                block_id,
                suite_id: Some(CryptoSuite::MlDsa44.as_id()),
                state_root,
                qc_hash,
                sig: Some(sig),
            })
        }
        _ => None,
    }
}

// === Internal, production-safe KV for system features (e.g., state-sync progress) ===
// This helper function goes *outside* the impl block.
const NS_SYNC: &[u8] = b"\xFFsync:";

// Helper to prefix a raw user key with the reserved namespace.
fn ns_key_sync(key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(NS_SYNC.len() + key.len());
    k.extend_from_slice(NS_SYNC);
    k.extend_from_slice(key);
    k
}

#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
#[derive(Clone, Debug)]
pub struct LightAnchor {
    pub header: LightHeader,
    /// 1 = SSZ-lite (v1), 2 = ETH-SSZ (v2)
    pub codec_version: u32,
}

#[cfg(feature = "persistence")]
impl Persistence {
    pub fn open_default(path: &std::path::Path) -> Result<Self> {
        let cfg = crate::config::PersistenceCfg {
            db_path: path.to_path_buf(),
            snapshot_interval: 1000,
            enable_compression: true,
            cache_size_mb: 128,
        };
        open_db(&cfg)
    }

    pub fn set_genesis(&self, height: u64) -> Result<()> {
        let cf_meta = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        let mut wb = WriteBatch::default();
        wb.put_cf(cf_meta, META_GENESIS, k_height(height));
        wb.put_cf(cf_meta, META_TIP, k_height(height));
        self.db.write(wb)?;
        Ok(())
    }

    pub fn get_genesis(&self) -> Result<u64> {
        let cf_meta = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        if let Some(v) = self.db.get_cf(cf_meta, META_GENESIS)? {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&v);
            Ok(u64::from_be_bytes(buf))
        } else {
            Err(PersistError::NotFound)
        }
    }

    pub fn set_tip(&self, height: u64) -> Result<()> {
        let cf_meta = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        self.db.put_cf(cf_meta, META_TIP, k_height(height))?;
        Ok(())
    }

    pub fn get_tip(&self) -> Result<u64> {
        let cf_meta = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        if let Some(v) = self.db.get_cf(cf_meta, META_TIP)? {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&v);
            Ok(u64::from_be_bytes(buf))
        } else {
            Err(PersistError::NotFound)
        }
    }

    // ── T32.1: continuity helpers ───────────────────────────────────────────
    pub fn continuity_last_header(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        if let Some(v) = self.db.get_cf(cf, META_LAST_HEADER)? {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&v);
            Ok(u64::from_be_bytes(buf))
        } else {
            Err(PersistError::NotFound)
        }
    }

    pub fn continuity_last_snapshot_v2(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        if let Some(v) = self.db.get_cf(cf, META_LAST_SNAPSHOT_V2)? {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&v);
            Ok(u64::from_be_bytes(buf))
        } else {
            Err(PersistError::NotFound)
        }
    }

    pub fn set_chain_id(&self, id20: &[u8; 20]) -> Result<()> {
        self.kv_put_sync(b"meta:chain_id", id20)
    }

    pub fn put_block(&self, height: u64, block: &Block) -> Result<()> {
        let cf_hdrs = self.db.cf_handle(CF_HEADERS)
            .ok_or_else(|| PersistError::Internal("cf:headers missing".into()))?;
        let cf_blks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| PersistError::Internal("cf:blocks missing".into()))?;
        let cf_txix = self.db.cf_handle(CF_TX_INDEX)
            .ok_or_else(|| PersistError::Internal("cf:tx_index missing".into()))?;

        let _start = Instant::now();
        let hdr = BlockHeader {
            height: block.header.height,
            prev_hash: block.header.prev_hash,
            tx_root: block.header.tx_root,
            #[cfg(feature = "eth-ssz")]
            tx_root_v2: block.header.tx_root_v2,
            fee_total: block.header.fee_total,
            tx_count: block.header.tx_count,
            timestamp_ms: block.header.timestamp_ms,
            #[cfg(feature = "checkpoints")]
            qc_hash: block.header.qc_hash,
        };
        let hdr_bytes = serialize(&hdr)?;
        let blk_bytes = serialize(block)?;

        let mut wb = WriteBatch::default();
        wb.put_cf(cf_hdrs, k_height(height), &hdr_bytes);
        wb.put_cf(cf_blks, k_height(height), &blk_bytes);
        for (idx, tx) in block.txs.iter().enumerate() {
            let key = k_tx_hash(tx_hash(tx));
            let val = serialize(&(height, idx as u32))?;
            wb.put_cf(cf_txix, key, val);
        }

        self.db.write(wb)?;
        #[cfg(feature = "metrics")]
        {
            let ms = _start.elapsed().as_millis() as u64;
            metrics::PERSIST_WRITE_DUR_MS.inc_by(ms);
        }
        Ok(())
    }

    pub fn get_header(&self, height: u64) -> Result<BlockHeader> {
        let cf_hdrs = self.db.cf_handle(CF_HEADERS)
            .ok_or_else(|| PersistError::Internal("cf:headers missing".into()))?;
        let _start = Instant::now();
        let bytes = self
            .db
            .get_cf(cf_hdrs, k_height(height))?
            .ok_or(PersistError::NotFound)?;
        let hdr: BlockHeader = deserialize(&bytes)?;
        #[cfg(feature = "metrics")]
        {
            let ms = _start.elapsed().as_millis() as u64;
            metrics::PERSIST_READ_DUR_MS.inc_by(ms);
        }
        Ok(hdr)
    }

    pub fn get_block(&self, height: u64) -> Result<Block> {
        let cf_blks = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| PersistError::Internal("cf:blocks missing".into()))?;
        let _start = Instant::now();
        let bytes = self
            .db
            .get_cf(cf_blks, k_height(height))?
            .ok_or(PersistError::NotFound)?;
        let blk: Block = deserialize(&bytes)?;
        #[cfg(feature = "metrics")]
        {
            let ms = _start.elapsed().as_millis() as u64;
            metrics::PERSIST_READ_DUR_MS.inc_by(ms);
        }
        Ok(blk)
    }
    /// Persist only the block header at `height`.
    pub fn put_header(&self, height: u64, header: &BlockHeader) -> Result<()> {
        let _start = Instant::now();
        let key = k_height(height);
        let hdr_bytes = serialize(header)?;

        let cf_headers = self
            .db
            .cf_handle(CF_HEADERS)
            .ok_or_else(|| PersistError::Internal("cf:headers missing".into()))?;

        self.db.put_cf(cf_headers, key, &hdr_bytes)?;

        #[cfg(feature = "metrics")]
        {
            let ms = _start.elapsed().as_millis() as u64;
            metrics::PERSIST_WRITE_DUR_MS.inc_by(ms); // Reuse existing metric if applicable, or add a specific one
        }
        Ok(())
    }	
	
	// ──────────────────────────────────────────────────────────────────────
	// T33.2 helpers: fetch roots/timestamps needed for bridge checkpoints
	//
	// These are convenience getters only; they DO NOT compute roots.
	// They read what you already persisted in headers/snapshots/blocks
	// so the commit path (or your checkpoint emitter) can build a header JSON.
	
	/// Return the ETH-SSZ **tx_root_v2** stored in the header at `height`.
	/// Requires the `eth-ssz` feature; otherwise returns NotFound.
	#[cfg(feature = "eth-ssz")]
	pub fn get_tx_root_v2(&self, height: u64) -> Result<[u8; 32]> {
		let hdr = self.get_header(height)?;
		Ok(hdr.tx_root_v2)
	}
	
	/// Return the ETH-SSZ **state_root_v2** for `height`.
	/// If the v2 field is zero in the snapshot, fall back to the legacy root.
	/// Resolve the state root to feed checkpoints:
	/// 1) Try exact snapshot at `height`
	/// 2) Else use the latest snapshot **≤ height**  
	/// 3) If the v2 field is zero (legacy), fall back to legacy root
	#[cfg(feature = "eth-ssz")]
	pub fn get_state_root_v2(&self, height: u64) -> Result<[u8; 32]> {
		let _snap = self;
        // try the snapshot at this height first
        match self.load_state_snapshot(height)? {
            Some(s) => {
                if s.state_root_v2 != [0u8; 32] {
                    Ok(s.state_root_v2)
                } else {
                    Ok(s.state_root)
                }
            }
            None => {
                // no exact snapshot: fall back to the latest snapshot at or below height
                if let Some(s) = self.get_latest_snapshot_at_or_below(height)? {
                    if s.state_root_v2 != [0u8; 32] {
                        Ok(s.state_root_v2)
                    } else {
                        Ok(s.state_root)
                    }
                } else {
                    Err(PersistError::NotFound)
                }
            }
        }			
	}
	
	/// Return the block **timestamp (seconds)** recorded in the block at `height`.
	/// (Your Block stores `timestamp_ms`; we convert to seconds here.)
	pub fn get_block_timestamp_secs(&self, height: u64) -> Result<u64> {
		let blk = self.get_block(height)?;
		Ok(blk.header.timestamp_ms / 1000)
	}
    /// Return the block timestamp (seconds) recorded in the *header* at `height`.
    /// (Reads header CF, converts ms to secs).
    pub fn get_header_timestamp_secs(&self, height: u64) -> Result<u64> {
        let hdr = self.get_header(height)?; // Reads CF_HEADERS
        Ok(hdr.timestamp_ms / 1000)
    }	

    pub fn lookup_tx(&self, hash32: [u8; 32]) -> Result<(u64, u32)> {
        let cf_txix = self.db.cf_handle(CF_TX_INDEX)
            .ok_or_else(|| PersistError::Internal("cf:tx_index missing".into()))?;
        if let Some(v) = self.db.get_cf(cf_txix, k_tx_hash(hash32))? {
            let (h, idx): (u64, u32) = deserialize(&v)?;
            Ok((h, idx))
        } else {
            Err(PersistError::NotFound)
        }
    }

    pub fn put_state_snapshot(&self, snap: &StateSnapshot) -> Result<()> {
        // Write v2 marker only when ETH-SSZ is enabled;
        // baseline stays v1.
        #[cfg(feature = "eth-ssz")]
        let snap = {
            let mut s = snap.clone();
            s.codec_version = 2;
            s
        };
        let bytes = bincode::serialize(&snap)?;
        #[cfg(feature = "metrics")]
        crate::metrics::STATE_SIZE_BYTES.set(bytes.len() as i64);
        // Be defensive about CF existence instead of unwrap (avoid panic).
        let Some(cf) = self.db.cf_handle(CF_SNAPSHOTS) else {
            // don’t ever panic here — persist layer must be panic-free
            return Err(PersistError::Internal("cf:snapshots missing".into()));
        };
        self.db.put_cf(cf, snap.height.to_be_bytes(), bytes)?;
        #[cfg(feature = "metrics")]
        crate::metrics::SNAPSHOT_COUNT_TOTAL.inc();
        // T32.1: continuity — best-effort dual-write SSZ blob & manifest and stamp meta.
        // If ETH-SSZ is compiled, export will also persist (blob, manifest) idempotently.
        #[cfg(feature = "eth-ssz")]
        {
            // ================== FIXED BLOCK with catch_unwind ==================
            // Call the helper that writes the SSZ blob & manifest using the in-memory snapshot.
            // We wrap it in catch_unwind so that any panic inside the SSZ encoder is logged
            // and does not bring down the node.
			log::info!(
			    "Snapshot height {} accounts count = {}, supply = {:?}",
			    snap.height,
			    snap.accounts.iter().count(),
			    snap.supply
			);
            let dual_write_res = std::panic::catch_unwind(|| {
                export_api::prewrite_snapshot_ssz_blob_v2_with_snapshot(self, &snap)
            });
            match dual_write_res {
                // Completed without panicking and returned Ok
                Ok(Ok(())) => { /* good */ }
                // Completed without panicking but returned an error
                Ok(Err(e)) => {
                    log::warn!(
                        "state-sync: SSZ v2 dual-write failed at h={}: {:?}",
                        snap.height, e
                    );
                }
                // Panicked: log as critical bug but do not crash
                Err(panic_payload) => {
                    log::error!(
                        "state-sync: SSZ v2 dual-write PANICKED at h={}. This is a bug in the serialization logic. Payload: {:?}",
                        snap.height,
                        panic_payload
                    );
                }
            }

            // =======================================================================

            // Mark continuity "last snapshot v2" in CF_METADATA
            if let Some(cf_meta) = self.db.cf_handle(CF_METADATA) {
                if let Err(e) = self
                    .db
                    .put_cf(cf_meta, META_LAST_SNAPSHOT_V2, snap.height.to_be_bytes())
                {
                    // don’t panic; continuity marker is best-effort
                    log::warn!(
                        "state-sync: failed to stamp META_LAST_SNAPSHOT_V2 at h={}: {}",
                        snap.height,
                        e
                    );
                }
            } else {
                log::warn!("state-sync: CF_METADATA missing; cannot stamp META_LAST_SNAPSHOT_V2");
            }
        }

        Ok(())
    }

    pub fn get_latest_snapshot_at_or_below(
        &self,
        target_height: u64,
    ) -> Result<Option<StateSnapshot>> {
        // Safely get the snapshots column family; if it is missing, treat as no snapshots.
        let cf = match self.db.cf_handle(CF_SNAPSHOTS) {
			 Some(cf) => cf,
			 None => return Ok(None),
		};
		let mut iter = self.db.iterator_cf(
		    cf,
			rocksdb::IteratorMode::From(&target_height.to_be_bytes(), rocksdb::Direction::Reverse),
		);
		if let Some(Ok((_k, v))) = iter.next() {
			let snap: StateSnapshot = bincode::deserialize(&v)?;
			Ok(Some(snap))
		} else {
			Ok(None)
		}
 
    }

pub fn load_state_snapshot(&self, height: u64) -> Result<Option<StateSnapshot>> {
    // Safely get the snapshots column family; if it is missing, treat as no snapshots.
    let cf_handle = match self.db.cf_handle(CF_SNAPSHOTS) {
        Some(cf) => cf,
        None => return Ok(None), // align with Option return
    };
    let key = height.to_be_bytes();
    match self.db.get_cf(cf_handle, &key) {
        Ok(Some(bytes)) => {
            let snap: StateSnapshot = bincode::deserialize(&bytes)?;
            Ok(Some(snap))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(PersistError::from(e)),
    }
}

    // ---------------------------------------------------------------------
    // Snapshot presence helpers (additive, no behavior change elsewhere)
    // ---------------------------------------------------------------------
    /// Returns true iff an exact snapshot exists at `height`.
    /// This is a thin convenience wrapper around `load_state_snapshot`.
    pub fn has_snapshot(&self, height: u64) -> Result<bool> {
        Ok(self.load_state_snapshot(height)?.is_some())
    }

    /// Return just the height of the latest snapshot **at or below** `target_height`.
    /// This mirrors `get_latest_snapshot_at_or_below` but avoids deserializing the
    /// whole snapshot when callers only need the height.
    pub fn latest_snapshot_height_at_or_below(&self, target_height: u64) -> Result<Option<u64>> {
        let cf = match self.db.cf_handle(CF_SNAPSHOTS) {
            Some(cf) => cf,
            None => return Ok(None),
        };
        let mut iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&target_height.to_be_bytes(), rocksdb::Direction::Reverse),
        );
        if let Some(Ok((k, _v))) = iter.next() {
            if k.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&k);
                return Ok(Some(u64::from_be_bytes(buf)));
            }
        }
        Ok(None)
    }

    pub fn recover_state(&self, target_height: u64) -> Result<(Accounts, Supply)> {
        let snap = self.get_latest_snapshot_at_or_below(target_height)?;
        if let Some(s) = snap {
            let mut accs = s.accounts.clone();
            let mut supply = s.supply.clone();
            for h in (s.height + 1)..=target_height {
                let block = self.get_block(h)?;
                accs.apply_block(&block)?;
                supply.apply_block(&block)?;
                #[cfg(feature = "metrics")]
                crate::metrics::REPLAY_BLOCKS_TOTAL.inc();
            }
            Ok((accs, supply))
        } else {
            Err(PersistError::NotFound)
        }
    }
    // (helper removed; callers now use a safe lookup)

    /// Atomically persist header + block at `height` (and index txs).
    pub fn put_header_and_block(
        &self,
        height: u64,
        header: &BlockHeader,
        block: &Block,
    ) -> Result<()> {
        // (optional) metrics timer
        let _start = Instant::now();
        // Keys & payloads
        let key = height.to_be_bytes();
        let hdr_bytes = bincode::serialize(header)?;
        let blk_bytes = bincode::serialize(block)?;

        // Look up CF handles from the DB (we don’t store them as fields)
        let cf_headers = self
            .db
            .cf_handle(CF_HEADERS)
            .ok_or_else(|| PersistError::NotFound)?;
        let cf_blocks = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| PersistError::NotFound)?;
        let cf_tx_index = self
            .db
            .cf_handle(CF_TX_INDEX)
            .ok_or_else(|| PersistError::NotFound)?;
        // Atomic batch for header + block (+ tx index entries + continuity meta)
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(cf_headers, &key, &hdr_bytes);
        batch.put_cf(cf_blocks, &key, &blk_bytes);

        // Build/refresh the tx index for this block (hash = sha3-256(bincode(tx)))
        let mut hasher = sha3::Sha3_256::new();
        for tx in &block.txs {
            let tx_bytes = bincode::serialize(tx)?;
            hasher.update(&tx_bytes);
            let tx_hash: [u8; 32] = hasher.finalize_reset().into();
            batch.put_cf(cf_tx_index, &tx_hash, &key);
        }

        // T32.1: also stamp continuity "last header" (CF_METADATA) in the same batch
        let cf_meta = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::NotFound)?;
        batch.put_cf(cf_meta, META_LAST_HEADER, &key);

        // Commit
        self.db.write(batch)?;
        // (optional) metrics here using _start if you wire them
        Ok(())
    }

    // === State-sync: checkpoint anchor helpers ===
    /// Persist the last decided checkpoint anchor (idempotent overwrite).
    #[cfg(feature = "state-sync")]
    pub fn save_checkpoint_anchor(&self, anchor: &CheckpointAnchor) -> Result<()> {
        // Use V2 when signature is present;
        // otherwise V1.
        let data = encode_anchor_any(anchor);
        self.db
            .put(KEY_LAST_CHECKPOINT_ANCHOR, &data)
            .map_err(PersistError::from)?;
        // T32: checkpoints written counter
        #[cfg(feature = "metrics")]
        crate::metrics::EEZO_CHECKPOINTS_WRITTEN_TOTAL.inc();
        Ok(())
    }

    /// Load the last decided checkpoint anchor if present.
    #[cfg(feature = "state-sync")]
    pub fn load_checkpoint_anchor(&self) -> Result<Option<CheckpointAnchor>> {
        match self.db.get(KEY_LAST_CHECKPOINT_ANCHOR) {
            Ok(Some(v)) => Ok(decode_anchor_any(&v)),
            Ok(None) => Ok(None),
            Err(e) => Err(PersistError::from(e)),
        }
    }

    /// Iterate a *snapshot* (prefix range) of the state DB in key order.
    ///
    /// - `prefix`: logical namespace to scan (e.g. b"acct:" or b"storage:").
    /// - `cursor`: resume-after key (raw), or `None` to start at `prefix`.
    /// - `limit`: max items to return.
    ///
    /// Returns a Vec of (key, value) pairs. Keys always start with `prefix`.
    #[cfg(feature = "state-sync")]
    pub fn snapshot_iter(
        &self,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        use rocksdb::{Direction, IteratorMode};
        if limit == 0 {
            return Ok(Vec::new());
        }
        // Start from the cursor (exclusive) or from the prefix itself.
        let start_key = match cursor {
            Some(c) => {
                // Start from cursor and skip it if equal.
                c.to_vec()
            }
            None => prefix.to_vec(),
        };
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut iter = self
            .db
            .iterator(IteratorMode::From(&start_key, Direction::Forward));
        while let Some(Ok((k, v))) = iter.next() {
            let kref: &[u8] = &k;
            // Respect the cursor "exclusive" semantics.
            if let Some(c) = cursor {
                match kref.cmp(c) {
                    Ordering::Less | Ordering::Equal => continue,
                    Ordering::Greater => { /* ok */ }
                }
            }
            if !kref.starts_with(prefix) {
                break;
                // prefix range ended
            }
            out.push((k.to_vec(), v.to_vec()));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    // === Production-Safe KV store for internal use (e.g., state-sync) ===

    // Core impl (one place).
    // Returns your project PersistError.
    pub fn kv_put_sync(&self, key: &[u8], val: &[u8]) -> Result<()> {
        let k = ns_key_sync(key);
        self.db.put(k, val).map_err(PersistError::from)
    }

    pub fn kv_get_sync(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let k = ns_key_sync(key);
        self.db.get(k).map_err(PersistError::from)
    }

    pub fn kv_del_sync(&self, key: &[u8]) -> Result<()> {
        let k = ns_key_sync(key);
        self.db.delete(k).map_err(PersistError::from)
    }

    // ---- Optional compatibility aliases (thin wrappers) ----
    pub fn kv_put_internal(&self, key: &[u8], val: &[u8]) -> Result<()> {
        self.kv_put_sync(key, val)
    }
    pub fn kv_get_internal(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.kv_get_sync(key)
    }
    pub fn kv_del_internal(&self, key: &[u8]) -> Result<()> {
        self.kv_del_sync(key)
    }

    // DEV-ONLY: write a raw key/value into the default
    // column family.
    /// This is for local testing of snapshot paging.
    #[cfg(debug_assertions)]
    pub fn dev_put_raw(&self, key: &[u8], val: &[u8]) -> std::result::Result<(), rocksdb::Error> {
        // Adjust if your wrapper type differs;
        // the idea is to hit the same RocksDB the snapshot uses.
        // If you already have a lower-level handle, use it; otherwise call through your existing write path.
        self.db.put(key, val)?;
        // <-- if your inner field isn't `db`, rename accordingly
        Ok(())
    }
}

#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
impl Persistence {
    /// Persist the ETH-SSZ light anchor (v2).
    /// Overwrites previous value.
    pub fn put_light_anchor(&self, a: &LightAnchor) -> Result<()> {
        // Serialize: codec_version (u32 LE) + ETH-SSZ bytes of LightHeader
        let mut buf = Vec::with_capacity(4 + 128);
        buf.extend_from_slice(&a.codec_version.to_le_bytes());
        let hdr_bytes = a.header.ssz_bytes();
        buf.extend_from_slice(&hdr_bytes);

        let cf_meta = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        self.db.put_cf(cf_meta, KEY_LIGHT_ANCHOR_V2, &buf)?;
        Ok(())
    }

    /// Load the ETH-SSZ light anchor (v2) if present.
    pub fn get_light_anchor(&self) -> Result<Option<LightAnchor>> {
        let cf_meta = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| PersistError::Internal("cf:metadata missing".into()))?;
        let Some(bytes) = self.db.get_cf(cf_meta, KEY_LIGHT_ANCHOR_V2)? else {
            return Ok(None);
        };
        if bytes.len() < 4 {
            return Err(PersistError::Codec(Box::new(
                bincode::ErrorKind::Custom("anchor: short".into()),
            )));
        }
        let mut ver = [0u8; 4];
        ver.copy_from_slice(&bytes[0..4]);
        let codec_version = u32::from_le_bytes(ver);
        // Decode LightHeader from the remaining bytes using ETH-SSZ
        let (hdr, _consumed) = LightHeader::ssz_read(&bytes[4..]).map_err(|_| {
            PersistError::Codec(Box::new(bincode::ErrorKind::Custom(
                "anchor decode".into(),
            )))
        })?;
        Ok(Some(LightAnchor {
            header: hdr,
            codec_version,
        }))
    }
}

// ---------- Public export used by node for Phase-2 HTTP ----------
// Current behavior: return the *existing* bincode snapshot payload for height H.
// Next step: we will flip what we persist/return here to a real ETH-SSZ container.
#[cfg(feature = "persistence")]
pub mod export_api {
    use super::*;
    // pulls in the existing top-level PersistError

    #[derive(thiserror::Error, Debug)]
    pub enum ExportPersistError {
        #[error("not found")]
        NotFound,
        #[error("not implemented")]
        NotImplemented,
        #[error("io: {0}")]
        Io(#[from] std::io::Error),
        #[error("codec: {0}")]
        Codec(String),
        #[error("internal: {0}")]
        Internal(String),
    }

    // For content hashing when persisting blobs/manifests.
    use bincode::{deserialize, serialize};
    use sha3::{Digest, Sha3_256};

    // Allow `?` on functions that return PersistError (KV ops) to bubble into ExportPersistError.
    impl From<PersistError> for ExportPersistError {
        fn from(e: PersistError) -> Self {
            match e {
                PersistError::NotFound => ExportPersistError::NotFound,
                // You can split these further if you prefer a more precise mapping
                PersistError::Io(ioe) => ExportPersistError::Io(ioe),
                PersistError::Codec(s) => ExportPersistError::Codec(format!("{s:?}")),
                _ => ExportPersistError::Internal(e.to_string()),
            }
        }
    }

    // ---- Helpers for SSZ2 safety ------------------------------------------------
    #[cfg(feature = "eth-ssz")]
    #[inline]
    fn ensure_codec_v2(snap: &StateSnapshot) -> std::result::Result<(), ExportPersistError> {
        if snap.codec_version != 2 {
            return Err(ExportPersistError::Codec(
                "expected codec_version=2".into(),
            ));
        }
        Ok(())
    }

    #[inline]
    fn parse_ssz2_header(buf: &[u8]) -> std::result::Result<(u32, u32), ExportPersistError> {
        if buf.len() < 12 {
            return Err(ExportPersistError::Codec("ssz2: short header".into()));
        }
        if &buf[0..4] != b"SSZ2" {
            return Err(ExportPersistError::Codec("ssz2: bad magic".into()));
        }
        let acc_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let sup_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let total = 12u64 + acc_len as u64 + sup_len as u64;
        if total != buf.len() as u64 {
            return Err(ExportPersistError::Codec("ssz2: bad lengths".into()));
        }
        Ok((acc_len, sup_len))
    }

    // ---------- SSZ blob framing ----------
    // We add a tiny, explicit frame so clients can split Accounts/Supply deterministically:
    // "SSZ2" (4 bytes) | acc_len: u32 LE | sup_len: u32 LE | acc_bytes | sup_bytes
    fn encode_snapshot_ssz_blob_v2(acc_bytes: &[u8], sup_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + 4 + acc_bytes.len() + sup_bytes.len());
        out.extend_from_slice(b"SSZ2");
        out.extend_from_slice(&(acc_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(sup_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(acc_bytes);
        out.extend_from_slice(sup_bytes);
        out
    }

    #[inline]
    fn k_snap_v2_ssz(height: u64) -> [u8; 32] {
        // fixed-size key: "snap/v2/ssz/" + u64_be + zero padding to 32
        // (Feel free to replace with your existing key scheme; just keep it consistent.)
        let mut k = [0u8; 32];
        k[..12].copy_from_slice(b"snap/v2/ssz/");
        k[12..20].copy_from_slice(&height.to_be_bytes());
        k
    }

    // ---------- Durable keys for manifests & delta ----------
    #[inline]
    fn k_snap_manifest_v2(height: u64) -> [u8; 32] {
        // "snap/v2/mani" (12 bytes; no trailing slash) + u64_be + pad
        let mut k = [0u8; 32];
        // keep prefix lengths consistent with other keys
        debug_assert_eq!(b"snap/v2/mani".len(), 12);
        k[..12].copy_from_slice(b"snap/v2/mani");
		k[12..20].copy_from_slice(&height.to_be_bytes());
		k
    }

    #[inline]
    fn k_delta_manifest_v2(from: u64, to: u64) -> [u8; 32] {
        // "dlt/v2/mani/" + from(u64_be) + to(u64_be)  => 12 + 8 + 8 = 28, pad to 32
        let mut k = [0u8; 32];
        k[..12].copy_from_slice(b"dlt/v2/mani/");
        k[12..20].copy_from_slice(&from.to_be_bytes());
        k[20..28].copy_from_slice(&to.to_be_bytes());
        k
    }

    #[inline]
    fn k_delta_proof_v2(from: u64, to: u64) -> [u8; 32] {
        // "dlt/v2/proof" + from + to
        let mut k = [0u8; 32];
        k[..12].copy_from_slice(b"dlt/v2/proof");
        k[12..20].copy_from_slice(&from.to_be_bytes());
        k[20..28].copy_from_slice(&to.to_be_bytes());
        k
    }

    // ---------- Durable manifest records (bincode) ----------
    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
    pub struct SnapshotManifestRecord {
        pub height: u64,
        pub state_root_v2: [u8; 32],
        pub blob_len: u64,
        pub blob_sha256: [u8; 32],
    }

    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
    pub struct DeltaManifestRecord {
        pub from: u64,
        pub to: u64,
        pub new_state_root_v2: [u8; 32],
        pub proof_len: u64,
        pub proof_sha256: [u8; 32],
        pub kcnt: u32,
    }

    // ---------- Put/Get helpers with verification ----------
    fn sha256_32(b: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b);
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out[..32]);
        r
    }

    pub fn put_snapshot_blob_v2(db: &Persistence, height: u64, blob: &[u8]) -> Result<[u8; 32]> {
        let key = k_snap_v2_ssz(height);
        db.kv_put_sync(&key, blob)?;
        Ok(sha256_32(blob))
    }

    pub fn put_snapshot_manifest_v2(
        db: &Persistence,
        rec: &SnapshotManifestRecord,
    ) -> Result<()> {
        let key = k_snap_manifest_v2(rec.height);
        let bytes = serialize(rec).map_err(|e| PersistError::Internal(e.to_string()))?;
        db.kv_put_sync(&key, &bytes)
    }

    pub fn get_snapshot_manifest_v2(
        db: &Persistence,
        height: u64,
    ) -> std::result::Result<SnapshotManifestRecord, ExportPersistError> {
        let key = k_snap_manifest_v2(height);
        let bytes = db.kv_get_sync(&key)?.ok_or(ExportPersistError::NotFound)?;
        let rec: SnapshotManifestRecord =
            deserialize(&bytes).map_err(|e| ExportPersistError::Codec(e.to_string()))?;
        Ok(rec)
    }

    pub fn get_snapshot_blob_v2_verified(
        db: &Persistence,
        height: u64,
    ) -> std::result::Result<Vec<u8>, ExportPersistError> {
        let mani = get_snapshot_manifest_v2(db, height)?;
        let key_blob = k_snap_v2_ssz(height);
        let blob = db.kv_get_sync(&key_blob)?.ok_or(ExportPersistError::NotFound)?;
        if blob.len() as u64 != mani.blob_len {
            return Err(ExportPersistError::Internal(
                "snapshot blob: len mismatch".into(),
            ));
        }
        if sha256_32(&blob) != mani.blob_sha256 {
            return Err(ExportPersistError::Internal(
                "snapshot blob: hash mismatch".into(),
            ));
        }
        Ok(blob)
    }

    pub fn put_delta_proof_blob_v2(
        db: &Persistence,
        from: u64,
        to: u64,
        proof: &[u8],
    ) -> Result<[u8; 32]> {
        let key = k_delta_proof_v2(from, to);
        db.kv_put_sync(&key, proof)?;
        Ok(sha256_32(proof))
    }

    pub fn put_delta_manifest_v2(db: &Persistence, rec: &DeltaManifestRecord) -> Result<()> {
        let key = k_delta_manifest_v2(rec.from, rec.to);
        let bytes = serialize(rec).map_err(|e| PersistError::Internal(e.to_string()))?;
        db.kv_put_sync(&key, &bytes)
    }

    pub fn get_delta_manifest_v2(
        db: &Persistence,
        from: u64,
        to: u64,
    ) -> std::result::Result<DeltaManifestRecord, ExportPersistError> {
        let key = k_delta_manifest_v2(from, to);
        let bytes = db.kv_get_sync(&key)?.ok_or(ExportPersistError::NotFound)?;
        let rec: DeltaManifestRecord =
            deserialize(&bytes).map_err(|e| ExportPersistError::Codec(e.to_string()))?;
        Ok(rec)
    }

    #[cfg(feature = "eth-ssz")]
    pub fn prewrite_snapshot_ssz_blob_v2_with_snapshot(
        db: &Persistence,
        snap: &StateSnapshot,
    ) -> Result<()> {
        // Snapshots used for SSZ2 must be v2-coded
        ensure_codec_v2(snap).map_err(|e| PersistError::Internal(e.to_string()))?;

        // Encode deterministically (never panic)
        let acc_bytes = snap.accounts.to_ssz_bytes();
        let sup_bytes = snap.supply.to_ssz_bytes();

        // Build SSZ2 blob and persist it (returns hash)
        let blob = encode_snapshot_ssz_blob_v2(&acc_bytes, &sup_bytes);
        let blob_hash = put_snapshot_blob_v2(db, snap.height, &blob)
            .map_err(|e| PersistError::Internal(e.to_string()))?;

        // Also persist a manifest now so verified reads work immediately
        let state_root_v2 = if snap.state_root_v2 != [0u8; 32] {
            snap.state_root_v2
        } else {
            snap.state_root
        };
        let mani = SnapshotManifestRecord {
            height: snap.height,
            state_root_v2,
            blob_len: blob.len() as u64,
            blob_sha256: blob_hash,
        };
        put_snapshot_manifest_v2(db, &mani)?;
        Ok(())
    }

    #[cfg(not(feature = "eth-ssz"))]
    pub fn prewrite_snapshot_ssz_blob_v2_with_snapshot(
        _db: &Persistence,
        _snap: &StateSnapshot,
    ) -> Result<()> {
        // No-op when SSZ v2 is not compiled in.
        Ok(())
    }

    /// Export the snapshot blob for `height` as raw bytes (current bincode).
    /// If `height` is not present, return `NotFound`.
    pub fn export_snapshot_blob_v2(
        db: &Persistence,
        height: u64,
    ) -> std::result::Result<Vec<u8>, ExportPersistError> {
        // Legacy bincode snapshot (for fmt=bin).
        // Keep existing behavior.
        let Some(cf_handle) = db.db.cf_handle(CF_SNAPSHOTS) else {
            return Err(ExportPersistError::NotFound);
        };
        let key = height.to_be_bytes();
        match db.db.get_cf(cf_handle, &key) {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(ExportPersistError::NotFound),
            Err(e) => Err(ExportPersistError::Internal(e.to_string())),
        }
    }

    /// Export the snapshot blob for `height` as ETH-SSZ bytes.
    /// After dual-write is implemented, this should read `<height>.ssz` (FS) or
    /// the corresponding KV key and return those bytes.
    /// For now, stub it.
    pub fn export_snapshot_blob_v2_ssz(
        db: &Persistence,
        height: u64,
    ) -> std::result::Result<Vec<u8>, ExportPersistError> {
        // 1) Try durable, verified read (manifest + blob)
        if let Ok(bytes) = get_snapshot_blob_v2_verified(db, height) {
            let _ = parse_ssz2_header(&bytes)?;
            // sanity
            return Ok(bytes);
        }

        // 2) Reconstruct SSZ blob from the persisted snapshot at `height`
        let snap_opt = db.load_state_snapshot(height)?;
        let snap = snap_opt.ok_or(ExportPersistError::NotFound)?;

        // If compiled with v2, only serve SSZ2 for codec v2 snapshots
        #[cfg(feature = "eth-ssz")]
        ensure_codec_v2(&snap)?;
        // Accounts/Supply -> SSZ bytes (fallible, never panic)
		let acc_ssz = snap.accounts.to_ssz_bytes();
		let sup_ssz = snap.supply.to_ssz_bytes();
        let blob = encode_snapshot_ssz_blob_v2(&acc_ssz, &sup_ssz);

        // 3) Persist blob + manifest atomically (best-effort: write blob first, then manifest)
        let blob_hash = put_snapshot_blob_v2(db, height, &blob)
            .map_err(|e| ExportPersistError::Internal(e.to_string()))?;
        // Choose v2 root when available
        let state_root_v2 = {
            #[cfg(feature = "eth-ssz")]
            {
                if snap.state_root_v2 != [0u8; 32] {
                    snap.state_root_v2
                } else {
                    snap.state_root
                }
            }
            #[cfg(not(feature = "eth-ssz"))]
            {
                snap.state_root
            }
        };
        let rec = SnapshotManifestRecord {
            height,
            state_root_v2,
            blob_len: blob.len() as u64,
            blob_sha256: blob_hash,
        };
        put_snapshot_manifest_v2(db, &rec)
            .map_err(|e| ExportPersistError::Internal(e.to_string()))?;
        Ok(blob)
    }

    // ---------- DeltaManifestV2 (SSZ framing) ----------
    // Frame (all LE where noted):
    //   magic:    "SSZ2D" (5 bytes)
    //   from:     u64 LE
    //   to:       u64 LE
    //   new_root: [u8;32]
    //   kcnt:     u32 LE            // number of proof
    //   keys
    //   plen:     u32 LE            // total proof bytes length
    //   keys:     kcnt * 32 bytes   // concatenated [32]-byte keys
    //   proof:    plen bytes        // proof byte blob (format TBD; opaque for now)
    //
    // For now we send kcnt=0, plen=0 (no keys/no proof).
    // Clients can parse today
    // and start verifying once proofs land, without changing the HTTP API.
    fn encode_delta_manifest_v2_ssz(
        from: u64,
        to: u64,
        new_root: [u8; 32],
        proof_keys: &[[u8; 32]],
        proof_bytes: &[u8],
    ) -> Vec<u8> {
        let kcnt = proof_keys.len() as u32;
        let plen = proof_bytes.len() as u32;
        let mut out =
            Vec::with_capacity(5 + 8 + 8 + 32 + 4 + 4 + kcnt as usize * 32 + plen as usize);
        out.extend_from_slice(b"SSZ2D");
        out.extend_from_slice(&from.to_le_bytes());
        out.extend_from_slice(&to.to_le_bytes());
        out.extend_from_slice(&new_root);
        out.extend_from_slice(&kcnt.to_le_bytes());
        out.extend_from_slice(&plen.to_le_bytes());
        for k in proof_keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(proof_bytes);
        out
    }

    // Producer for SSZ delta manifests (empty proof for now).
    pub fn export_delta_manifest_v2_ssz(
        db: &Persistence,
        from: u64,
        to: u64,
    ) -> std::result::Result<Vec<u8>, ExportPersistError> {
        // 0) Try durable manifest first
        if let Ok(mani) = get_delta_manifest_v2(db, from, to) {
            let proof_bytes = db
                .kv_get_sync(&k_delta_proof_v2(from, to))?
                .unwrap_or_default();
            // sanity: lengths + hashes (if proof present)
            if mani.proof_len == proof_bytes.len() as u64
                && (mani.proof_len == 0 || sha256_32(&proof_bytes) == mani.proof_sha256)
            {
                return Ok(encode_delta_manifest_v2_ssz(
                    mani.from,
                    mani.to,
                    mani.new_state_root_v2,
                    &[], // keys opaque for now
                    &proof_bytes,
                ));
            }
            // fall through to rebuild if mismatch
        }

        // Today we only support trivial range where new_root is the root at `to`.
        // When you support multi-block ranges, compute the post-state root for `to`.
        let snap_opt = db.load_state_snapshot(to)?;
        let snap = snap_opt.ok_or(ExportPersistError::NotFound)?;
        // Prefer v2 root when available, else fall back
        let new_root = {
            #[cfg(feature = "eth-ssz")]
            {
                if snap.state_root_v2 != [0u8; 32] {
                    snap.state_root_v2
                } else {
                    snap.state_root
                }
            }
            #[cfg(not(feature = "eth-ssz"))]
            {
                snap.state_root
            }
        };
        // Until multiproof builder is ready, ship empty proof, but persist a manifest
        // with lengths/hashes so the server never serves partial blobs.
        let proof_bytes: Vec<u8> = Vec::new();
        let proof_hash = sha256_32(&proof_bytes);
        // Persist proof blob (empty) then manifest
        let _ = put_delta_proof_blob_v2(db, from, to, &proof_bytes)
            .map_err(|e| ExportPersistError::Internal(e.to_string()))?;
        let mani = DeltaManifestRecord {
            from,
            to,
            new_state_root_v2: new_root,
            proof_len: proof_bytes.len() as u64,
            proof_sha256: proof_hash,
            kcnt: 0,
        };
        put_delta_manifest_v2(db, &mani)
            .map_err(|e| ExportPersistError::Internal(e.to_string()))?;
        Ok(encode_delta_manifest_v2_ssz(
            from,
            to,
            new_root,
            &[], // keys opaque for now
            &proof_bytes,
        ))
    }

    // -------- Genesis helpers (optional) ----------
    /// Try to load the genesis state root (v2) from
    /// persistence.
    /// We assume the node wrote it at genesis under a well-known key.
    pub fn load_genesis_state_root_v2(db: &Persistence) -> Result<[u8; 32]> {
        // Adjust the key to match your KV layout if needed
        const K: &[u8] = b"genesis/state_root_v2";
        let opt = db.kv_get_sync(K)?; // -> Result<Option<Vec<u8>>>
        let bytes = opt.ok_or(PersistError::NotFound)?;
        if bytes.len() != 32 {
            return Err(PersistError::Internal(
                "bad genesis state_root_v2 length".into(),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Persist the genesis state root (v2). Idempotent: overwrites if present.
    pub fn save_genesis_state_root_v2(db: &Persistence, root: [u8; 32]) -> Result<()> {
        const K: &[u8] = b"genesis/state_root_v2";
        db.kv_put_sync(K, &root)?;
        Ok(())
    }

    #[cfg(feature = "eth-ssz")]
    #[derive(Debug)]
    pub struct SnapshotBlobMeta {
        pub state_root_v2: [u8; 32],
        pub accounts_len: u32,
        pub supply_len: u32,
        pub total_len: u64,
    }

    // When eth-ssz is OFF, expose a dummy type so the symbol can still be referenced in generic code.
    #[cfg(not(feature = "eth-ssz"))]
    #[derive(Debug)]
    pub struct SnapshotBlobMeta;
    /// Pre-compute metadata for the SSZ snapshot blob v2 without writing it out.
    /// This is used by state-sync HTTP to build a JSON manifest.
    #[cfg(feature = "eth-ssz")]
    pub fn prewrite_snapshot_ssz_blob_v2(
        db: &Persistence,
        height: u64,
    ) -> std::result::Result<SnapshotBlobMeta, ExportPersistError> {
        // Resolve state_root_v2 at the requested height
        let state_root_v2 = if height == 0 {
            // Genesis root (map PersistError -> ExportPersistError::NotFound if missing)
            load_genesis_state_root_v2(db).map_err(|_| ExportPersistError::NotFound)?
        } else {
            // Load the persisted snapshot at `height` and pick the v2 root if present
            let snap = db
                .load_state_snapshot(height)?
                .ok_or(ExportPersistError::NotFound)?;
            #[cfg(feature = "eth-ssz")]
            let root = if snap.state_root_v2 != [0u8; 32] {
                snap.state_root_v2
            } else {
                snap.state_root
            };
            #[cfg(not(feature = "eth-ssz"))]
            let root = snap.state_root;
            root
        };

        // We also need length metadata.
        // Read the snapshot to derive SSZ lengths.
        let snap = db
            .load_state_snapshot(height)?
            .ok_or(ExportPersistError::NotFound)?;

        let acc_ssz = snap.accounts.to_ssz_bytes();
        let sup_ssz = snap.supply.to_ssz_bytes();
        let accounts_len = acc_ssz.len() as u32;
        let supply_len = sup_ssz.len() as u32;
        // SSZ2 header is 12 bytes: "SSZ2"(4) + acc_len(u32 LE) + sup_len(u32 LE)
        let total_len = 12u64 + accounts_len as u64 + supply_len as u64;
        Ok(SnapshotBlobMeta {
            state_root_v2,
            accounts_len,
            supply_len,
            total_len,
        })
    }

    // Stub when eth-ssz is OFF: keeps builds green under narrow feature sets.
    #[cfg(not(feature = "eth-ssz"))]
    pub fn prewrite_snapshot_ssz_blob_v2(
        _db: &Persistence,
        _height: u64,
    ) -> std::result::Result<SnapshotBlobMeta, ExportPersistError> {
        Err(ExportPersistError::NotImplemented)
    }
}

// Re-export for the node crate.
#[cfg(feature = "persistence")]
pub use export_api::{
    export_delta_manifest_v2_ssz, export_snapshot_blob_v2, export_snapshot_blob_v2_ssz,
    load_genesis_state_root_v2, save_genesis_state_root_v2, ExportPersistError,
};
// Only expose the prewrite helper when SSZ v2 is actually compiled in
#[cfg(all(feature = "persistence", feature = "eth-ssz"))]
pub use export_api::prewrite_snapshot_ssz_blob_v2;
// ============================ T29.9: tests ============================
#[cfg(all(
    test,
    feature = "persistence",
    feature = "state-sync",
    feature = "testing"
))]
mod tests {
    use super::*;
    use crate::checkpoints::{AnchorSig, CheckpointAnchor};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    // helpers to build deterministic anchors
    fn dummy_anchor(height: u64) -> CheckpointAnchor {
        let mut block_id = [0u8; 32];
        let mut state_root = [0u8; 32];
        let mut qc_hash = [0u8; 32];
        block_id[0] = 1;
        block_id[31] = 2;
        state_root[0] = 3;
        state_root[31] = 4;
        qc_hash[0] = 5;
        qc_hash[31] = 6;
        CheckpointAnchor {
            height,
            suite_id: Some(CryptoSuite::MlDsa44.as_id()),
            block_id,
            state_root,
            qc_hash,
            sig: None,
        }
    }

    #[test]
    fn v1_roundtrip_legacy_unsigned() {
        let a = dummy_anchor(42);
        let v1 = super::encode_anchor(&a); // fixed V1 writer
        assert!(!v1.is_empty(), "encode_anchor must produce bytes");
        // decode via both paths
        let d1 = super::decode_anchor(&v1).expect("decode v1 (legacy)");
        let d2 = super::decode_anchor_any(&v1).expect("decode v1 (any)");
        assert_eq!(d1, a);
        assert_eq!(d2, a);
        assert!(d2.sig.is_none());
    }

    #[test]
    fn v2_roundtrip_signed() {
        let mut a = dummy_anchor(100);
        // build strict-length ML-DSA-44 pk/sig (contents arbitrary for persistence test)
        let pk = vec![0xAB; 1312];
        let sg = vec![0xCD; 2420];
        let sig = AnchorSig {
            scheme: "ML-DSA-44".to_string(),
            pk_b64: B64.encode(&pk),
            sig_b64: B64.encode(&sg),
        };
        a.sig = Some(sig);
        let v = super::encode_anchor_any(&a); // selector should emit V2
                                              // version byte must be 2
        assert_eq!(v.first().copied(), Some(2u8));
        let d = super::decode_anchor_any(&v).expect("decode v2 (any)");
        assert_eq!(d.height, a.height);
        assert_eq!(d.block_id, a.block_id);
        assert_eq!(d.state_root, a.state_root);
        assert_eq!(d.qc_hash, a.qc_hash);
        let dsig = d.sig.expect("sig present");
        assert_eq!(dsig.scheme, "ML-DSA-44");
        assert_eq!(
            B64.decode(dsig.pk_b64.as_bytes()).unwrap().len(),
            1312
        );
        assert_eq!(
            B64.decode(dsig.sig_b64.as_bytes()).unwrap().len(),
            2420
        );
    }

    #[test]
    fn v2_strict_lengths_enforced() {
        let mut a = dummy_anchor(7);
        // wrong sizes must fall back to V1 writer (encode_anchor_any returns v1 bytes)
        let pk = vec![0; 10]; // bad
        let sg = vec![0; 20];
        // bad
        a.sig = Some(AnchorSig {
            scheme: "ML-DSA-44".to_string(),
            pk_b64: B64.encode(&pk),
            sig_b64: B64.encode(&sg),
        });
        let out = super::encode_anchor_any(&a);
        assert_eq!(
            out.first().copied(),
            Some(1u8),
            "invalid sizes must not write v2"
        );
        // decode yields legacy unsigned
        let d = super::decode_anchor_any(&out).expect("decode fallback v1");
        assert!(d.sig.is_none());
    }
}

#[cfg(all(
    test,
    feature = "persistence",
    feature = "eth-ssz",
    feature = "testing"
))]
mod light_anchor_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn light_anchor_put_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let db = Persistence::open_default(tmp.path()).unwrap();

        // minimal LightHeader (fields must match your light.rs)
        let hdr = LightHeader {
            height: 10,
            parent_root: [1u8; 32],
            tx_root_v2: [2u8; 32],
            #[cfg(feature = "checkpoints")]
            qc_root: [3u8; 32],
            timestamp_ms: 1234,
        };
        let a = LightAnchor {
            header: hdr,
            codec_version: 2,
        };
        db.put_light_anchor(&a).unwrap();

        let r = db.get_light_anchor().unwrap().expect("present");
        assert_eq!(r.codec_version, 2);
        assert_eq!(r.header.height, 10);
        assert_eq!(r.header.parent_root, [1u8; 32]);
        assert_eq!(r.header.tx_root_v2, [2u8; 32]);
        #[cfg(feature = "checkpoints")]
        assert_eq!(r.header.qc_root, [3u8; 32]);
        assert_eq!(r.header.timestamp_ms, 1234);
    }
}
