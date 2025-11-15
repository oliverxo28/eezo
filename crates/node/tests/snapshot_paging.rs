#![cfg(feature = "state-sync")]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::blocking::Client;
use std::time::Duration;

// Import the common test helpers
mod common;

fn b64(s: &str) -> String {
    STANDARD.encode(s.as_bytes())
}

#[test]
fn snapshot_paging_matches_full_scan() {
    // Use the common helpers to spawn a node on a free port.
    let port = common::free_port();
    let datadir = format!("crates/node/target/testdata/snapshot_paging_{}", port);
    let _ = std::fs::remove_dir_all(&datadir); // Clean up previous runs

    // The ChildGuard will ensure the node is terminated and datadir is cleaned up.
    let _guard = common::spawn_node_with_env(
        &[
            "--datadir", &datadir,
            "--listen", &format!("127.0.0.1:{}", port),
            "--genesis", common::GENESIS_PATH,
            "--enable-state-sync",
        ],
        &[("RUST_LOG", "info")],
    );

    // Wait for the node to be ready before sending requests.
    assert!(
        common::wait_until_ready(port, 30_000),
        "Node never became ready"
    );

    let c = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Seed 5 keys
    let puts = [
        ("state:acct:a", "1"),
        ("state:acct:b", "2"),
        ("state:acct:c", "3"),
        ("state:meta:x", "9"),
        ("state:meta:y", "10"),
    ];
    for (k, v) in puts {
        // Use the dynamic port
        let url = format!(
            "http://127.0.0.1:{}/_admin/put?key={}&val={}",
            port,
            b64(k),
            b64(v)
        );
        let resp = c.get(url).send().unwrap();
        assert!(resp.status().is_success(), "Failed to seed key {}. Status: {}, Body: {}", k, resp.status(), resp.text().unwrap_or_default());
    }

    // Helper: fetch a page
    #[derive(serde::Deserialize, Debug)]
    struct Page {
        items: Vec<Item>,
        cursor: Option<String>,
    }
    #[derive(serde::Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Item {
        key_b64: String,
        val_b64: String,
    }

    let page = |cursor: Option<String>| {
        // Use the dynamic port
        let mut url = format!("http://127.0.0.1:{}/state/snapshot?limit=2", port);
        if let Some(cu) = cursor {
            url.push_str(&format!("&cursor={}", cu));
        }
        c.get(url).send().unwrap().json::<Page>().unwrap()
    };

    // Full scan via paging
    let mut all = Vec::new();
    let mut cur = None;
    loop {
        let p = page(cur.clone());
        all.extend(
            p.items
                .iter()
                .map(|it| (it.key_b64.clone(), it.val_b64.clone())),
        );
        if p.cursor.is_none() || p.items.is_empty() {
            break;
        }
        cur = p.cursor;
    }

    // Expect >=5 items; keys must be lexicographic and unique
    assert!(all.len() >= 5, "expected at least 5 seeded items; got {}", all.len());
    let mut sorted = all.clone();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted.dedup_by(|a, b| a.0 == b.0);
    assert_eq!(sorted, all, "Paging must be sorted and keys must be unique");
}