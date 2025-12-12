#[cfg(feature = "pq44-runtime")]
pub mod consensus;

#[cfg(feature = "pq44-runtime")]
pub mod consensus_msg;

#[cfg(feature = "pq44-runtime")]
pub mod consensus_sig;

#[cfg(feature = "pq44-runtime")]
pub mod cert_store;

#[cfg(feature = "pq44-runtime")]
pub mod evidence;

// T77.SAFE-2: Centralized dev-unsafe mode gate
pub mod dev_unsafe;

pub mod tx;

pub mod mempool;

#[cfg(feature = "pq44-runtime")]
pub mod verify_cache;

pub mod config;

pub mod supply;

pub mod address;

pub mod accounts;

// T87.4: Arena-indexed account storage for STM executor
pub mod stm_arena;

pub mod tx_types;

pub mod tx_sig;

pub mod block;

#[cfg(feature = "pq44-runtime")]
pub mod consensus_api;

#[cfg(feature = "pq44-runtime")]
pub use consensus_api::{BlockExecutor, BlockProducer};

pub use config::{BatchVerifyCfg, FeeCfg, SupplyCapCfg, VerifyConfig};

#[cfg(feature = "pq44-runtime")]
pub use verify_cache::VerifyCache;

pub use supply::{MintSource, Supply, SupplyError};

pub use address::Address;

pub use accounts::{Account, Accounts};

// T87.4: Arena-indexed account storage for STM executor
pub use stm_arena::{AccountArena, SUPPLY_INDEX};

pub use tx_types::{tx_domain_bytes, validate_tx_shape, SignedTx, TxCore, TxStatelessError};

pub use tx_sig::verify_signed_tx;

pub use tx::{
    apply_signed_tx, apply_tx, sender_from_pubkey_first20, validate_tx_stateful, TxApplyError,
    TxStateError, TxWitness,
};

#[cfg(feature = "pq44-runtime")]
pub use mempool::{admit_signed_tx, AdmissionOk, MempoolTtlConfig, RejectReason};

pub use block::{
    apply_block, assemble_block, encoded_len_ssz, header_domain_bytes, header_hash, validate_block,
    validate_header, AssembleError, Block, BlockApplyError, BlockHeader, BlockValidationError,
    HeaderErr,
};

#[cfg(feature = "pq44-runtime")]
pub use consensus::{
    validate_consensus_batch, ConsensusError, ConsensusMsgCore, SignedConsensusMsg, SingleNode,
    SingleNodeCfg, SlotSummary,
};

// ═══════════════════════════════════════════════════════════════════════════════
// T85.0: DAG-ONLY CONSENSUS
// ═══════════════════════════════════════════════════════════════════════════════
// EEZO's consensus in this branch is DAG-primary + STM. HotStuff has been
// completely removed (T85.0). The only consensus mode available is DAG-based.
// ═══════════════════════════════════════════════════════════════════════════════

// ValidatorId is still used by cert_store and DAG consensus components
#[cfg(feature = "pq44-runtime")]
pub use crate::consensus_msg::ValidatorId;

#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(not(feature = "metrics"))]
pub mod metrics_shim;

// When metrics feature is off, expose a unified `metrics` via the shim
#[cfg(not(feature = "metrics"))]
pub use self::metrics_shim as metrics;

#[cfg(feature = "pq44-runtime")]
pub mod pq44_runtime;

// T34.2 — expose suite-rotation policy/helpers to dependents
pub mod rotation;
pub mod qc_sidecar; // T41.1: additive types for QC sidecar v2
pub use crate::rotation::RotationPolicy;

// NEW
#[cfg(feature = "persistence")]
pub mod persistence;

#[cfg(feature = "persistence")]
pub use crate::persistence::{Persistence, StateSnapshot};

#[cfg(feature = "persistence")]
pub use crate::config::PersistenceCfg;

#[cfg(feature = "persistence")]
pub mod genesis;

#[cfg(feature = "persistence")]
pub use crate::genesis::GenesisConfig; // Make sure this line is present
#[cfg(feature = "persistence")]
pub use genesis::{
    build_genesis_block, ensure_genesis, ConsensusParams, GenesisBlock,
    ValidatorEntry,
};

// Surface common persistence exports at the crate root as a convenience for node.
// (Still available under `eezo_ledger::persistence::*`.)
#[cfg(feature = "persistence")]
pub use crate::persistence::{
    ExportPersistError,
    load_genesis_state_root_v2, save_genesis_state_root_v2,
};

// --- T17.2 additions ---
#[cfg(feature = "checkpoints")]
pub mod checkpoints;

// Re-export checkpoint QuorumCert and helpers at crate root with their plain names
#[cfg(feature = "checkpoints")]
pub use crate::checkpoints::{
    is_checkpoint_height,
    qc_hash_of,
    qc_message_bytes,
    quorum_threshold,
    verify_quorum_cert,
    QcHash,
    QuorumCert, // <-- checkpoint QC exported as `eezo_ledger::QuorumCert`
};

// Heavy exports only when verify is on:
#[cfg(all(feature = "checkpoints", feature = "checkpoints-verify"))]
pub use checkpoints::{
    verify_quorum_cert_with_env, QcBatchItem, QcError, QcSigSet, QcVerifier, StubQcVerifier,
};
// --- end T17.2 additions ---

// === STATE-SYNC: re-exports for state sync APIs (ledger side) ===
#[cfg(feature = "state-sync")]
pub use checkpoints::CheckpointAnchor;
#[cfg(feature = "state-sync")]
pub use tx::{verify_sparse_merkle_proof, SparseMerkleProof};

// Bridge module and exports
pub mod bridge;
pub use bridge::{
    BridgeState, BridgeMintVoucher, OutboxEvent, ExtChain, DepositId,
    apply_bridge_mint, record_outbox_skeleton, canonical_mint_msg, BridgeError,
};

// Make `crate::serde::ssz::*` available (backed by the dependency `eezo-serde`)
pub use eezo_serde as serde;

// crates/ledger/src/lib.rs
// …your existing mods…

#[cfg(feature = "eth-ssz")]
pub mod eth_ssz;

// NEW: expose ETH-SSZ helpers
#[cfg(feature = "eth-ssz")]
pub mod merkle;

#[cfg(feature = "eth-ssz")]
pub mod light;

// --- State-sync (ETH-SSZ) helpers for node + tests ---
#[cfg(all(feature = "eth-ssz", feature = "state-sync"))]
pub mod state_sync;

#[cfg(all(feature = "eth-ssz", feature = "state-sync"))]
pub mod bootstrap;

// Re-export state-sync timing helpers for node (no-op without metrics).
// These symbols live inside `crate::state_sync` and are only compiled under
// eth-ssz + state-sync; re-exporting keeps call sites tidy.
#[cfg(all(feature = "eth-ssz", feature = "state-sync"))]
pub use crate::state_sync::{
    t32_bootstrap_finish, t32_bootstrap_start, t32_page_apply_finish, t32_page_apply_start,
};