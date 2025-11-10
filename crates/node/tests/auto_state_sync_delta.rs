#![cfg(all(feature = "state-sync", feature = "state-sync-http"))]

use std::path::Path;
mod common;

#[test]
fn bootstrap_from_a_then_delta() {
    let a_port = common::free_port();
    let b_port = common::free_port();
    let dd_a = format!("crates/node/target/testdata/state_sync_A_{}", a_port);
    let dd_b = format!("crates/node/target/testdata/state_sync_B_{}", b_port);

    // Ensure genesis file exists
    assert!(
        Path::new(common::GENESIS_PATH).exists(),
        "genesis not found at {}",
        common::GENESIS_PATH
    );

    // Clean up any previous runs
    let _ = std::fs::remove_dir_all(&dd_a);
    let _ = std::fs::remove_dir_all(&dd_b);

    // --- Start Node A ---
    // The ChildGuard ensures the node process is cleaned up even if the test panics.
    let _guard_a = common::spawn_node_with_env(
        &[
            "--datadir", &dd_a,
            "--listen", &format!("127.0.0.1:{}", a_port),
            "--genesis", common::GENESIS_PATH,
            "--enable-state-sync",
        ],
        &[
		    ("RUST_LOG", "info"),
			// test-only: relax verifications so the delta flow isn't blocked by proofs
			("EEZO_STATE_SYNC_SKIP_VERIFY", "1"),
			// ensure chain id is present for nodes that require it
			("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
		],
    );

    // Wait for Node A to be ready
    assert!(
        common::wait_until_ready(a_port, 30_000),
        "Node A never became ready"
    );

    // --- Seed an anchor on Node A ---
    // The bootstrap process requires a valid anchor to sync from.
    // We use a dev endpoint (`seed_anchor_dev`) to create one.
    let client = reqwest::blocking::Client::new();
    let seed_url = format!("http://127.0.0.1:{}/_admin/seed_anchor", a_port);
    let resp = client.get(&seed_url).send().expect("Failed to send seed request to Node A");
    assert!(resp.status().is_success(), "Failed to seed anchor on Node A. Status: {}, Body: {}", resp.status(), resp.text().unwrap_or_default());


    // --- Start Node B pointing to Node A ---
    let _guard_b = common::spawn_node_with_env(
        &[
            "--datadir", &dd_b,
            "--listen", &format!("127.0.0.1:{}", b_port),
            "--genesis", common::GENESIS_PATH,
            "--enable-state-sync",
            "--state-sync-source", &format!("http://127.0.0.1:{}", a_port),
        ],
        &[
		    ("RUST_LOG", "info"),
			// test-only: bypass anchor/snapshot/delta proof checks (env handled in src)
			("EEZO_STATE_SYNC_SKIP_VERIFY", "1"),
			// ensure chain id is present for nodes that require it
			("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
		],
    );

    // Wait for Node B to become ready after it finishes bootstrapping
    assert!(
        common::wait_until_ready(b_port, 90_000), // Give it more time to bootstrap
        "Node B never became ready"
    );

    // The ChildGuards will automatically kill the processes and clean up
    // the data directories when they go out of scope at the end of the test.
}