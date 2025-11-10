#![cfg(feature = "pq44-runtime")]
#![cfg(feature = "metrics")]

use eezo_ledger::{SingleNode, SingleNodeCfg};
use pqcrypto_mldsa::mldsa44::keypair;
use prometheus::{gather, proto::MetricFamily};
mod support;

#[cfg(feature = "persistence")]
use support::temp_persistence;

fn fresh_node() -> SingleNode {
    #[cfg(feature = "persistence")]
    let (_persistence, _tmp) = temp_persistence();

    let cfg = SingleNodeCfg {
        chain_id: [0xE0; 20],
        block_byte_budget: 64 * 1024,
        header_cache_cap: 1024,
        ..Default::default()
    };
    let (pk, sk) = keypair();
    SingleNode::new(cfg, sk, pk)
}

fn require_histogram<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
    families
        .iter()
        .find(|m| m.get_name() == name)
        .unwrap_or_else(|| panic!("missing histogram family: {name}"))
}

#[test]
fn latency_histograms_observe_counts() {
    let mut node = fresh_node();

    // Nudge the code paths that record latency histograms.
    let _ = node.run_one_slot(false).expect("slot ok");
    let _ = node.run_one_slot(false).expect("slot ok");

    let mf = gather();

    // These names should match the ones exported by eezo_ledger::metrics.
    // If your actual names differ, update this list once here (not in multiple places).
    let target = [
        "block_proposal_duration_ms",
        "validation_duration_ms",
        "state_apply_duration_ms",
    ];

    for name in target {
        let fam = require_histogram(&mf, name);

        // At least one observation recorded.
        let total_count: u64 = fam
            .get_metric()
            .iter()
            .map(|met| met.get_histogram().get_sample_count())
            .sum();
        assert!(total_count > 0, "histogram {name} has zero total count");

        // Sum must be positive if we observed anything.
        let total_sum: f64 = fam
            .get_metric()
            .iter()
            .map(|met| met.get_histogram().get_sample_sum())
            .sum();
        assert!(total_sum > 0.0, "histogram {name} has non-positive sum");

        // Buckets must be monotonically non-decreasing (cumulative counts).
        for met in fam.get_metric() {
            let hist = met.get_histogram();
            let mut prev = 0u64;
            for b in hist.get_bucket() {
                let c = b.get_cumulative_count();
                assert!(
                    c >= prev,
                    "histogram {name} bucket counts are not monotonic: {prev} -> {c}"
                );
                prev = c;
            }
        }
    }
}

#[test]
fn budget_counters_registered() {
    // Touch the statics to ensure registration happens in this process.
    let _ = &*eezo_ledger::metrics::BLOCK_BYTES_USED;
    let _ = &*eezo_ledger::metrics::BLOCK_BYTES_WASTED;

    let names: Vec<String> = gather()
        .into_iter()
        .map(|m| m.get_name().to_string())
        .collect();

    assert!(
        names.iter().any(|n| n == "block_bytes_used"),
        "missing counter: block_bytes_used"
    );
    assert!(
        names.iter().any(|n| n == "block_bytes_wasted"),
        "missing counter: block_bytes_wasted"
    );
}