pub mod cert;
pub mod consensus_wire;
pub mod handshake;
pub mod harness;
pub mod hkdf_sha3;
pub mod kem_adapter;
pub mod kemtls;
pub mod keyschedule;
pub mod secure;

#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "metrics")]
pub use metrics::{
    register_net_metrics,
    kemtls_handshake_observe_secs,
    kemtls_session_inc,
    kemtls_session_mark,
    kemtls_handshake_fail,
};

pub mod session;
pub mod sig_adapter;
pub mod sim;

// ── T37.2: AEAD tickets + sharded replay ────────────────────────────────
// Ticket crypto is in `tickets.rs` and is *consumed via* `kemtls`.
// We expose modules but avoid re-exporting internal types/functions.
#[cfg(feature = "mlkem")]
pub mod tickets;
#[cfg(feature = "mlkem")]
pub mod replay;

// Public types actually intended for downstream use
pub use crate::secure::FramedSession;

#[cfg(feature = "pq44-runtime")]
pub use eezo_ledger::consensus;
// Re-export legacy consensus message types for convenience (historical — see T81)
#[cfg(feature = "pq44-runtime")]
pub use eezo_ledger::consensus_msg;