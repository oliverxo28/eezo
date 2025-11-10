use crate::{
    persistence::PersistError, Account, Accounts, Address, Block, BlockHeader, Persistence,
    StateSnapshot, Supply,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
// For persisting a genesis anchor so /state/anchor works immediately.
// Gate on state-sync so non-state-sync builds are unaffected.
#[cfg(feature = "state-sync")]
use crate::checkpoints::CheckpointAnchor;
// default the genesis anchor to ML-DSA-44; if you later thread RotationPolicy in,
// replace this with the active suite from policy.
#[cfg(feature = "state-sync")]
use eezo_crypto::suite::CryptoSuite;

#[cfg(all(feature = "metrics", feature = "state-sync"))]
use crate::metrics::EEZO_CHECKPOINT_APPLY_SECONDS;
#[cfg(all(feature = "metrics", feature = "state-sync"))]
use std::time::Instant;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusParams {
    pub max_txs_per_block: u64,
    pub block_bytes_budget: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub address: Address,
    pub stake: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: [u8; 20],
    pub initial_validators: Vec<ValidatorEntry>,
    pub initial_accounts: Vec<(Address, u128)>, // (address, balance)
    pub initial_supply: Supply,
    pub consensus_params: ConsensusParams,
    // --- T34: crypto-suite rotation policy (optional; keeps old JSONs valid) ---
    // If absent in genesis JSON, these come out as None and the node will
    // fall back to ENV (if set) or hardcoded defaults.
    #[serde(default)]
    pub active_suite_id: Option<u8>,
    #[serde(default)]
    pub next_suite_id: Option<u8>,
    #[serde(default)]
    pub dual_accept_until: Option<u64>,	
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub config: GenesisConfig,
    pub block: Block,
    pub state_root: [u8; 32],
}

// helper: lower-hex encode 20 bytes without adding a new dependency
fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn to_le_bytes_u128(x: u128) -> [u8; 16] {
    x.to_le_bytes()
}
#[allow(dead_code)]
fn to_le_bytes_u64(x: u64) -> [u8; 8] {
    x.to_le_bytes()
}

impl Accounts {
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Collect via public iterator (keeps `inner` private)
        let mut pairs: Vec<(&Address, &Account)> = self.iter().collect();

        // Deterministic order by raw address bytes
        pairs.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

        // Encode: addr[20] || balance[u128 LE] || nonce[u64 LE]
        for (addr, acc) in pairs {
            out.extend_from_slice(addr.as_bytes());
            out.extend_from_slice(&acc.balance.to_le_bytes());
            out.extend_from_slice(&acc.nonce.to_le_bytes());
        }
        out
    }
}

impl Supply {
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&to_le_bytes_u128(self.native_mint_total));
        out.extend_from_slice(&to_le_bytes_u128(self.bridge_mint_total));
        out.extend_from_slice(&to_le_bytes_u128(self.burn_total));
        out
    }
}

pub fn build_genesis_block(cfg: GenesisConfig) -> GenesisBlock {
    // 1) Materialize initial accounts and supply from config
    let mut accounts = Accounts::default();
    for (addr, bal) in &cfg.initial_accounts {
        accounts.credit(*addr, *bal);
    }
    let supply = cfg.initial_supply.clone();

    // 2) Compute genesis state root (panic-free).
    //    If eth-ssz is enabled, prefer the fallible SSZ encoders and log+fallback on error.
    //    Otherwise, use the stable v1 bytes.
    let mut hasher = Sha3_256::new();
    #[cfg(feature = "eth-ssz")]
    let (acc_ssz, sup_ssz) = {
        let acc = accounts.to_ssz_bytes_safe().unwrap_or_else(|e| {
            log::warn!(
                "genesis: accounts SSZ encode failed: {e}; falling back to v1 bytes"
            );
            accounts.to_ssz_bytes()
        });
        let sup = supply.to_ssz_bytes_safe().unwrap_or_else(|e| {
            log::warn!(
                "genesis: supply SSZ encode failed: {e}; falling back to v1 bytes"
            );
            supply.to_ssz_bytes()
        });
        (acc, sup)
    };
    #[cfg(not(feature = "eth-ssz"))]
    let (acc_ssz, sup_ssz) = (accounts.to_ssz_bytes(), supply.to_ssz_bytes());
    hasher.update(&acc_ssz);
    hasher.update(&sup_ssz);
    let state_root: [u8; 32] = hasher.finalize().into();

    // 3) Minimal header for genesis
    let header = BlockHeader {
        prev_hash: [0u8; 32],
        height: 0,
        tx_root: [0u8; 32], // Empty merkle root
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32], // or compute via crate::eth_ssz::txs_root_v2 if txs available
        fee_total: 0,
        timestamp_ms: 0, // or a fixed constant to keep it deterministic
        tx_count: 0,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    };

    let block = Block {
        header,
        txs: Vec::new(),
    };

    GenesisBlock {
        config: cfg,
        block,
        state_root,
    }
}

pub fn ensure_genesis(p: &Persistence, cfg: &GenesisConfig) -> Result<(), PersistError> {
    // If we already have a genesis header, assume genesis is done.
    if p.get_header(0).is_ok() {
        // --- Genesis migration: backfill genesis/state_root_v2 if missing ---
        #[cfg(feature = "eth-ssz")]
        {
            use crate::persistence::{load_genesis_state_root_v2, save_genesis_state_root_v2};
            // Try to read; if missing, backfill from the stored genesis snapshot.
            if let Err(crate::persistence::PersistError::NotFound) = load_genesis_state_root_v2(p) {
                // Load the stored genesis snapshot (height 0) from persistence.
                let snap0 = p.get_latest_snapshot_at_or_below(0).map_err(|e| {
                    crate::persistence::PersistError::Internal(format!("load snap0: {e}"))
                })?;

                if let Some(s0) = snap0 {
                    // Prefer `state_root_v2` if present; otherwise fall back to `state_root`.
                    let root_v2: [u8; 32] = {
                        #[cfg(feature = "eth-ssz")]
                        {
                            if s0.state_root_v2 != [0u8; 32] {
                                s0.state_root_v2
                            } else {
                                s0.state_root
                            }
                        }
                        #[cfg(not(feature = "eth-ssz"))]
                        {
                            s0.state_root
                        }
                    };
                    save_genesis_state_root_v2(p, root_v2)?;
                    log::info!("genesis migration: wrote missing genesis/state_root_v2");
                } else {
                    // If no snapshot is found, you can skip or log a warning.
                    log::warn!(
                        "genesis migration: snap0 missing; cannot backfill genesis/state_root_v2"
                    );
                }
            }
        }
        // --- Migration: backfill missing checkpoint anchor at height 0 ---
        #[cfg(feature = "state-sync")]
        {
            // Only write if absent to keep this idempotent.
            if p.load_checkpoint_anchor()?.is_none() {
                // Prefer the persisted v2 root if available; otherwise try the snapshot root.
                let root_v2: [u8; 32] = (|| -> Result<[u8; 32], crate::persistence::PersistError> {
                    #[cfg(feature = "eth-ssz")]
                    {
                        if let Ok(r) = crate::persistence::load_genesis_state_root_v2(p) {
                            return Ok(r);
                        }
                    }
                    // Fallback: read snap0 and use whichever root is available.
                    let s0 = p
                        .get_latest_snapshot_at_or_below(0)?
                        .ok_or(crate::persistence::PersistError::NotFound)?;
                    #[cfg(feature = "eth-ssz")]
                    {
                        if s0.state_root_v2 != [0u8; 32] {
                            Ok(s0.state_root_v2)
                        } else {
                            Ok(s0.state_root)
                        }
                    }
                    #[cfg(not(feature = "eth-ssz"))]
                    {
                        Ok(s0.state_root)
                    }
                })()?;

                let anchor = CheckpointAnchor {
                    height: 0,
                    block_id: [0u8; 32],
                    state_root: root_v2,
                    qc_hash: [0u8; 32],
                    sig: None,
                    // default suite at genesis
                    suite_id: Some(CryptoSuite::MlDsa44.as_id()),
                };
                // Measure the duration of applying (persisting) the genesis anchor during migration.
                #[cfg(all(feature = "metrics", feature = "state-sync"))]
                let _t_ckpt_apply = Instant::now();
                p.save_checkpoint_anchor(&anchor)?;
                #[cfg(all(feature = "metrics", feature = "state-sync"))]
                {
                    EEZO_CHECKPOINT_APPLY_SECONDS
                        .observe(_t_ckpt_apply.elapsed().as_secs_f64());
                }
                log::info!("genesis migration: wrote missing unsigned checkpoint anchor (h=0)");
            }
        }
        return Ok(());
    }

    // Persist chain_id for a fresh store so clients can read it from persistence.
    p.set_chain_id(&cfg.chain_id)?;

    // Build a deterministic genesis block from config
    let g = build_genesis_block(cfg.clone());

    // Persist header and block at height 0
    p.put_header_and_block(0, &g.block.header, &g.block)?;

    // Write chain metadata
    p.set_genesis(0)?;
    p.set_tip(0)?;

    // Materialize initial state and write a snapshot
    let mut accs = Accounts::default();
    for (addr, bal) in &cfg.initial_accounts {
        accs.credit(*addr, *bal);
    }
    let supply = cfg.initial_supply.clone();

    // Seed the live account KV so /account/<addr> returns the funded balance.
    // Key format:  "acct:<hex20>"  (adjust the "acct:" prefix only if your reader uses a different one)
    // Value format: JSON of `Account { balance, nonce }` (serde)
    for (addr, bal) in &cfg.initial_accounts {
        let acc = Account { balance: *bal, nonce: 0 };
        let key = format!("acct:{}", to_lower_hex(addr.as_bytes()));
        let val  = bincode::serialize(&acc)
            .map_err(|e| PersistError::Internal(format!("serialize account json: {e}")))?;
        p.kv_put_sync(key.as_bytes(), &val)?;
    }

    // Persist initial validators for later use.
    for v in &cfg.initial_validators {
        // If you have a dedicated API, call it; otherwise write a KV like below:
        let vkey = format!("val:{}", to_lower_hex(v.address.as_bytes()));
        let vval = bincode::serialize(&v.stake)
            .map_err(|e| PersistError::Internal(format!("serialize validator stake: {e}")))?;
        p.kv_put_sync(vkey.as_bytes(), &vval)?;
    }

    // For Phase 2 bootstrap: until true ETH-SSZ root is available,
    // use state_root as a stand-in for state_root_v2.
    #[cfg(feature = "eth-ssz")]
    let state_root_v2 = g.state_root;

    let snap = StateSnapshot {
        height: 0,
        accounts: accs,
        supply,
        state_root: g.state_root,
		bridge: Some(crate::bridge::BridgeState::default()),
        #[cfg(feature = "eth-ssz")]
        codec_version: 2,
        #[cfg(feature = "eth-ssz")]
        state_root_v2,
    };
    p.put_state_snapshot(&snap)?;

    #[cfg(feature = "eth-ssz")]
    {
        // Best-effort precompute/cache the SSZ snapshot blob for this height.
        // Non-fatal for genesis path.
        if let Err(e) = crate::persistence::prewrite_snapshot_ssz_blob_v2(p, snap.height) {
            log::warn!(
                "prewrite SSZ snapshot blob (height {}) failed: {e}",
                snap.height
            );
        }
    }

    // Persist genesis state_root_v2 for manifest fallback (pre-anchor)
    #[cfg(feature = "eth-ssz")]
    {
        crate::persistence::save_genesis_state_root_v2(p, state_root_v2)?;
    }

    // Persist a genesis checkpoint anchor so /state/anchor returns immediately.
    // Unsigned at genesis; signature policy is enforced by the client depending on TLS.
    #[cfg(feature = "state-sync")]
    {
        // Prefer v2 root if available (eth-ssz feature), else use legacy root.
        let root_for_anchor: [u8; 32] = {
            #[cfg(feature = "eth-ssz")]
            { state_root_v2 }
            #[cfg(not(feature = "eth-ssz"))]
            { g.state_root }
        };
        let anchor = CheckpointAnchor {
            height: 0,
            block_id: [0u8; 32],
            state_root: root_for_anchor,
            qc_hash: [0u8; 32],
            sig: None,
            // default suite at genesis
            suite_id: Some(CryptoSuite::MlDsa44.as_id()),
        };
        // Measure the duration of applying (persisting) the genesis anchor on fresh init.
		#[cfg(all(feature = "metrics", feature = "state-sync"))]
		let _t_ckpt_apply = Instant::now();
		p.save_checkpoint_anchor(&anchor)?;
		#[cfg(all(feature = "metrics", feature = "state-sync"))]
		{
			EEZO_CHECKPOINT_APPLY_SECONDS
			    .observe(_t_ckpt_apply.elapsed().as_secs_f64());
		}
    }
    Ok(())
}
