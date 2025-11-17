//! eezo-ssz-bridge: thin facade over ledger/eth_ssz
//! - no SSZ logic here
//! - re-export canonical types/helpers only
//! - provide a simple version handshake + guard

use tracing::info;

/// The SSZ version this bridge surfaces externally (aligns with circuits/PI).
pub const EEZO_ACTIVE_SSZ_VERSION: u8 = 2;

/// Compile-time crate version string (from Cargo).
pub const BRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Logical SSZ API string for external consumers/tools (bump on wire changes).
pub const SERDE_SSZ_API_VERSION: &str = "eth-ssz-api-v1";

// === re-exports: canonical surface ==========================================
pub mod types {
    // pull the types from their public modules (not via eth_ssz) to avoid privacy errors
    pub use eezo_ledger::block::BlockHeader;
    pub use eezo_ledger::tx_types::{SignedTx, TxCore};
}

// helpers that downstreams actually use still come from eth_ssz
pub use eezo_ledger::eth_ssz::{state_root_v2, txs_root_v2};

// === version wiring ==========================================================
// Prefer pulling a version const from ledger if it exists; otherwise fall back.
#[cfg(feature = "ledger_has_version_const")]
pub use eezo_ledger::eth_ssz::LEDGER_SSZ_VERSION;

#[cfg(not(feature = "ledger_has_version_const"))]
pub const LEDGER_SSZ_VERSION: u8 = EEZO_ACTIVE_SSZ_VERSION;

/// Log both versions once at startup from each binary (prover/relay).
pub fn log_ssz_versions(component: &str) {
    info!(
        component = component,
        bridge_version = EEZO_ACTIVE_SSZ_VERSION,
        ledger_version = LEDGER_SSZ_VERSION,
        "eezo-ssz version handshake"
    );
}

/// Runtime guard: in dev/testnet we allow equality; ahead-of-ledger is a hard error.
pub fn assert_compat_or_warn() {
    if EEZO_ACTIVE_SSZ_VERSION > LEDGER_SSZ_VERSION {
        panic!(
            "eezo-ssz-bridge (v{}) is ahead of ledger SSZ (v{}). upgrade ledger first.",
            EEZO_ACTIVE_SSZ_VERSION, LEDGER_SSZ_VERSION
        );
    }
}

// === greppable one-liner & soft-compat (non-breaking additions) =============
/// Compact versions payload callers can render in logs/metrics.
#[derive(Debug, Clone, Copy)]
pub struct BridgeVersions {
    pub component: &'static str,
    pub bridge_version: &'static str,
    pub serde_api: &'static str,
}

impl BridgeVersions {
    /// Stable, single-line string for grep/kibana dashboards.
    pub fn to_log_line(&self) -> String {
        format!(
            "eezo-ssz-bridge handshaked: component={}, bridge_crate_v={}, serde_api={}",
            self.component, self.bridge_version, self.serde_api
        )
    }
}

/// Return a versions tuple the caller can print or export.
pub fn ssz_versions(component: &'static str) -> BridgeVersions {
    BridgeVersions {
        component,
        bridge_version: BRIDGE_VERSION,
        serde_api: SERDE_SSZ_API_VERSION,
    }
}

/// Optional soft-compat check (kept lenient for T37.7). Returns `true` always for now.
/// Use alongside [`assert_compat_or_warn`] if you want hard gating too.
pub fn assert_compat_or_warn_soft(_expected_api: Option<&str>) -> bool {
    true
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_not_ahead_of_ledger() {
        assert!(
            EEZO_ACTIVE_SSZ_VERSION <= LEDGER_SSZ_VERSION,
            "bridge claims newer SSZ than ledger; upgrade ledger or lower bridge version"
        );
    }
}
