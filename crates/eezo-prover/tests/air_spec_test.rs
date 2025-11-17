//! T38.1 — basic compile-time + structural test for the AIR spec.
//! This ensures the spec stays aligned with PI V2 layout and that
//! boundary structs can be constructed without pulling any prover code.

#[cfg(feature = "stark-air")]
mod tests {
    use eezo_prover::air_spec::{AirPiV2, Boundary};

    #[test]
    fn air_pi_v2_basic_layout() {
        let pi = AirPiV2 {
            chain_id20: [0u8; 20],
            height: 42,
            parent_hash: [1u8; 32],
            txs_root_v2: [2u8; 32],
            state_root_v2: [3u8; 32],
            sig_batch_digest: [4u8; 32],
            suite_id: 1,
            circuit_version: 2,
        };

        assert_eq!(pi.height, 42);
        assert_eq!(pi.suite_id, 1);
        assert_eq!(pi.circuit_version, 2);
    }

    #[test]
    fn air_boundary_construction() {
        let b = Boundary {
            row0_parent_hash: [9u8; 32],
            row_last_header_htr: [8u8; 32],
            row_last_txs_root_v2: [7u8; 32],
            row_last_state_root_v2: [6u8; 32],
            row_last_sig_batch_digest: [5u8; 32],
        };

        assert_eq!(b.row0_parent_hash[0], 9);
        assert_eq!(b.row_last_sig_batch_digest[0], 5);
    }
}
