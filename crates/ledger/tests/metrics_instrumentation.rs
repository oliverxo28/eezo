#[cfg(feature = "metrics")]
#[test]
fn t32_metrics_register_and_appear() {
    // Force registration
    eezo_ledger::metrics::register_t32_metrics();
    // Scrape from prometheus registry directly
    let mf = prometheus::gather();
    let mut buf = vec![];
    prometheus::TextEncoder::new().encode(&mf, &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    for needle in &[
        "eezo_block_e2e_latency_seconds",
        "eezo_tx_verify_seconds",
        "eezo_qc_formed_total",
        "eezo_chain_height_gauge",
        "eezo_state_sync_page_apply_seconds",
        "eezo_state_sync_pages_applied_total",
        "eezo_checkpoint_apply_seconds",
        "eezo_checkpoints_written_total",
    ] {
        assert!(s.contains(needle), "missing metric: {needle}");
    }
}

#[cfg(not(feature = "metrics"))]
#[test]
fn t32_metrics_noop_when_feature_off() {
    // Should compile and do nothing
    eezo_ledger::metrics::register_t32_metrics();
}
