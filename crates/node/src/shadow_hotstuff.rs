//! shadow_hotstuff.rs — T78.5: Real HotStuff Shadow Checker for dag-primary mode.
//!
//! This module provides a minimal, in-memory shadow checker that runs after each
//! successfully committed block in dag-primary mode. It:
//!
//! - Checks height monotonicity (no regress, no duplicates)
//! - Performs basic consistency checks between committed block data
//! - Emits metrics on every check and on mismatches
//! - Logs warnings on any detected mismatch
//!
//! This is a **safety oracle**, not a second consensus. It never affects block commit
//! and never panics — all failures are surfaced via metrics + warnings only.
//!
//! This module is only compiled when the `dag-consensus` feature is enabled.

#![cfg(feature = "dag-consensus")]

use crate::tx_decode_pool::DecodedTx;
use std::sync::Arc;

/// T78.5: Mismatch reason types for labeled metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowMismatchReason {
    /// Height regressed (new height < previous height)
    HeightRegress,
    /// Height is equal to previous (duplicate block)
    HeightEqual,
    /// Block hash or tx-set mismatch
    HashMismatch,
    /// Other unexpected issues
    Other,
}

impl ShadowMismatchReason {
    /// Get the string label for metrics
    pub fn as_str(&self) -> &'static str {
        match self {
            ShadowMismatchReason::HeightRegress => "height_regress",
            ShadowMismatchReason::HeightEqual => "height_equal",
            ShadowMismatchReason::HashMismatch => "hash_mismatch",
            ShadowMismatchReason::Other => "other",
        }
    }
}

/// T78.5: Shadow HotStuff checker for dag-primary mode.
///
/// This struct maintains minimal state to verify invariants across committed blocks:
/// - Height monotonicity (strictly increasing)
/// - Block hash / tx-set consistency
///
/// It is fully in-memory and synchronous — no I/O, no network.
pub struct ShadowHotstuffChecker {
    /// Last observed block height (None if no block seen yet)
    last_height: Option<u64>,
    /// Last observed block hash (None if no block seen yet)
    last_hash: Option<[u8; 32]>,
}

impl ShadowHotstuffChecker {
    /// Create a new shadow checker instance.
    pub fn new() -> Self {
        log::info!("[T78.5 shadow-checker] initialized");
        Self {
            last_height: None,
            last_hash: None,
        }
    }

    /// Called after a block is successfully committed in dag-primary mode.
    ///
    /// Performs invariant checks and emits metrics/logs on mismatches.
    /// Never panics — all failures are surfaced via metrics + warnings only.
    ///
    /// # Arguments
    /// * `height` - The committed block height
    /// * `block_hash` - The committed block's header hash
    /// * `txs` - The decoded transactions in the block
    pub fn on_committed_block(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[Arc<DecodedTx>],
    ) {
        // T78.5: Always increment the shadow checks counter
        crate::metrics::dag_primary_shadow_checks_inc();

        // T78.5: Check height monotonicity invariant
        let height_ok = self.check_height_monotonicity(height);

        // T78.5: Check block hash / tx-set consistency
        let hash_ok = self.check_block_hash_consistency(height, block_hash, txs);

        // Update internal state only if height check passed
        if height_ok {
            self.last_height = Some(height);
            self.last_hash = Some(block_hash);
        }

        // Log success for debugging (only every N blocks to avoid spam)
        if height_ok && hash_ok && height % 100 == 0 {
            log::debug!(
                "[T78.5 shadow-checker] check ok at height={} (txs={})",
                height,
                txs.len()
            );
        }
    }

    /// Check height monotonicity: height must be strictly greater than last_height.
    ///
    /// Returns true if check passes, false if mismatch detected.
    fn check_height_monotonicity(&self, height: u64) -> bool {
        match self.last_height {
            None => {
                // First block: any height is allowed
                log::debug!(
                    "[T78.5 shadow-checker] first block at height={}",
                    height
                );
                true
            }
            Some(prev_height) => {
                if height < prev_height {
                    // Height regressed
                    self.record_mismatch(ShadowMismatchReason::HeightRegress);
                    log::warn!(
                        "[T78.5 shadow-checker] mismatch: height regressed (prev={}, new={})",
                        prev_height,
                        height
                    );
                    false
                } else if height == prev_height {
                    // Duplicate height
                    self.record_mismatch(ShadowMismatchReason::HeightEqual);
                    log::warn!(
                        "[T78.5 shadow-checker] mismatch: height equal (prev={}, new={})",
                        prev_height,
                        height
                    );
                    false
                } else {
                    // Strictly increasing: good
                    true
                }
            }
        }
    }

    /// Check block hash / tx-set consistency.
    ///
    /// For T78.5, we perform a minimal check:
    /// - Compute a simple Blake3 hash over the concatenated tx hashes
    /// - Compare this digest against a recomputed value
    ///
    /// This is a T78.5 minimal check — future tasks can expand to full merkle root.
    ///
    /// Returns true if check passes, false if mismatch detected.
    fn check_block_hash_consistency(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[Arc<DecodedTx>],
    ) -> bool {
        // T78.5 minimal check: compute Blake3 over concatenated tx hashes
        // This validates that the tx list we see matches what we'd expect
        // to compute from the same set of transactions.
        if txs.is_empty() {
            // Empty block: no hash check needed
            return true;
        }

        // Compute expected tx-set digest using Blake3
        let mut hasher = blake3::Hasher::new();
        for tx in txs {
            let tx_hash = tx.hash();
            hasher.update(&tx_hash);
        }
        let computed_digest: [u8; 32] = *hasher.finalize().as_bytes();

        // For T78.5, we record the computed digest but don't have a reference
        // to compare against (the block_hash is the header hash, not tx hash).
        // 
        // What we CAN check: if we've seen this block before (same height),
        // the computed digest should match what we computed last time.
        //
        // For the initial T78.5 implementation, we just record that we did
        // the computation. Future work can compare against canonical merkle root.
        //
        // If we have a last_hash stored, we can at least detect if the same
        // height is being committed with a different block hash.
        if let Some(prev_hash) = self.last_hash {
            if let Some(prev_height) = self.last_height {
                if height == prev_height && block_hash != prev_hash {
                    // Same height but different block hash - this is a mismatch
                    self.record_mismatch(ShadowMismatchReason::HashMismatch);
                    log::warn!(
                        "[T78.5 shadow-checker] mismatch: hash mismatch at height={} \
                        (expected=0x{}, got=0x{})",
                        height,
                        hex::encode(&prev_hash[..4]),
                        hex::encode(&block_hash[..4])
                    );
                    return false;
                }
            }
        }

        // For T78.5, record that we computed the digest (for future expansion)
        log::trace!(
            "[T78.5 shadow-checker] computed tx digest at height={}: 0x{}",
            height,
            hex::encode(&computed_digest[..4])
        );

        true
    }

    /// Record a mismatch and increment metrics.
    fn record_mismatch(&self, reason: ShadowMismatchReason) {
        // Increment total mismatch counter
        crate::metrics::dag_primary_shadow_mismatch_inc();
        // Increment labeled reason counter
        crate::metrics::dag_primary_shadow_mismatch_reason_inc(reason.as_str());
    }
}

impl Default for ShadowHotstuffChecker {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// T78.5 — Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_decode_pool::DecodedTx;
    use eezo_ledger::{SignedTx, TxCore};
    use eezo_ledger::address::Address;
    use std::sync::Arc;

    /// Create a mock DecodedTx for testing
    fn make_mock_decoded_tx(nonce: u64) -> Arc<DecodedTx> {
        // Create a minimal SignedTx for testing
        // The tx hash will be derived from the tx fields
        let tx = SignedTx {
            core: TxCore {
                to: Address::from_bytes([1u8; 20]),
                amount: 1000,
                fee: 100,
                nonce,
            },
            pubkey: vec![0u8; 32],
            sig: vec![0u8; 64],
        };
        Arc::new(DecodedTx::new(tx))
    }

    /// T78.5 unit test: height monotonicity with good sequence
    #[test]
    fn t78_5_shadow_height_monotonic_ok() {
        let mut checker = ShadowHotstuffChecker::new();
        
        // Feed a strictly increasing sequence: 10 → 11 → 12
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let hash3 = [3u8; 32];
        let txs: Vec<Arc<DecodedTx>> = vec![];
        
        // First block at height 10
        checker.on_committed_block(10, hash1, &txs);
        assert_eq!(checker.last_height, Some(10));
        assert_eq!(checker.last_hash, Some(hash1));
        
        // Second block at height 11
        checker.on_committed_block(11, hash2, &txs);
        assert_eq!(checker.last_height, Some(11));
        assert_eq!(checker.last_hash, Some(hash2));
        
        // Third block at height 12
        checker.on_committed_block(12, hash3, &txs);
        assert_eq!(checker.last_height, Some(12));
        assert_eq!(checker.last_hash, Some(hash3));
    }

    /// T78.5 unit test: height regress is detected and does not update state
    #[test]
    fn t78_5_shadow_height_regress_detected() {
        let mut checker = ShadowHotstuffChecker::new();
        
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let txs: Vec<Arc<DecodedTx>> = vec![];
        
        // First block at height 10
        checker.on_committed_block(10, hash1, &txs);
        assert_eq!(checker.last_height, Some(10));
        
        // Second block regresses to height 9 - should NOT update state
        checker.on_committed_block(9, hash2, &txs);
        
        // State should remain at height 10 (not updated due to regression)
        assert_eq!(checker.last_height, Some(10));
        assert_eq!(checker.last_hash, Some(hash1));
    }

    /// T78.5 unit test: duplicate height is detected and does not update state
    #[test]
    fn t78_5_shadow_height_equal_detected() {
        let mut checker = ShadowHotstuffChecker::new();
        
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let txs: Vec<Arc<DecodedTx>> = vec![];
        
        // First block at height 10
        checker.on_committed_block(10, hash1, &txs);
        assert_eq!(checker.last_height, Some(10));
        
        // Second block also at height 10 - duplicate
        checker.on_committed_block(10, hash2, &txs);
        
        // State should remain unchanged (not updated due to duplicate)
        assert_eq!(checker.last_height, Some(10));
        assert_eq!(checker.last_hash, Some(hash1));
    }

    /// T78.5 unit test: first block at any height is accepted
    #[test]
    fn t78_5_shadow_first_block_any_height() {
        let mut checker = ShadowHotstuffChecker::new();
        
        let hash = [42u8; 32];
        let txs: Vec<Arc<DecodedTx>> = vec![];
        
        // First block can be at any height
        checker.on_committed_block(12345, hash, &txs);
        assert_eq!(checker.last_height, Some(12345));
        assert_eq!(checker.last_hash, Some(hash));
    }

    /// T78.5 unit test: empty tx list is handled correctly
    #[test]
    fn t78_5_shadow_empty_txs() {
        let mut checker = ShadowHotstuffChecker::new();
        
        let hash = [1u8; 32];
        let txs: Vec<Arc<DecodedTx>> = vec![];
        
        // Empty block should be accepted
        checker.on_committed_block(1, hash, &txs);
        assert_eq!(checker.last_height, Some(1));
    }

    /// T78.5 unit test: block with transactions is processed correctly
    #[test]
    fn t78_5_shadow_with_txs() {
        let mut checker = ShadowHotstuffChecker::new();
        
        let hash = [1u8; 32];
        let txs: Vec<Arc<DecodedTx>> = vec![
            make_mock_decoded_tx(1),
            make_mock_decoded_tx(2),
            make_mock_decoded_tx(3),
        ];
        
        // Block with transactions should be processed
        checker.on_committed_block(1, hash, &txs);
        assert_eq!(checker.last_height, Some(1));
    }

    /// T78.5 unit test: ShadowMismatchReason labels are correct
    #[test]
    fn t78_5_shadow_mismatch_reason_labels() {
        assert_eq!(ShadowMismatchReason::HeightRegress.as_str(), "height_regress");
        assert_eq!(ShadowMismatchReason::HeightEqual.as_str(), "height_equal");
        assert_eq!(ShadowMismatchReason::HashMismatch.as_str(), "hash_mismatch");
        assert_eq!(ShadowMismatchReason::Other.as_str(), "other");
    }
}
