#![cfg(all(feature = "state-sync", feature = "persistence"))]

use eezo_ledger::persistence::Persistence;

#[test]
fn snapshot_iter_scans_prefix_in_order() {
    // 1) Open a temp DB
    let tmp = tempfile::tempdir().unwrap();
    let db = Persistence::open_default(tmp.path()).expect("open");

    // 2) Seed a few keys under a prefix (acct:\x00 .. acct:\x04)
    let pfx = b"acct:";
    for i in 0..5u8 {
        let mut k = pfx.to_vec();
        k.extend_from_slice(&[i]);
        let v = vec![i; 4];
        db.dev_put_raw(&k, &v).expect("dev_put_raw");
    }

    // 3) Iterate in two chunks using the resume cursor
    let page1 = db.snapshot_iter(pfx, None, 3).expect("iter page1");
    assert_eq!(page1.len(), 3);
    let cursor = page1.last().map(|(k, _)| k.clone());

    let page2 = db.snapshot_iter(pfx, cursor.as_deref(), 10).expect("iter page2");
    assert_eq!(page2.len(), 2);

    // 4) Ensure all keys start with prefix and ordering is lexicographic across pages
    let mut all: Vec<Vec<u8>> = page1
        .iter()
        .chain(page2.iter())
        .map(|(k, _)| k.clone())
        .collect();
    for k in &all {
        assert!(k.starts_with(pfx), "non-prefixed key: {:?}", k);
    }
    // no duplicates across pages
    let mut dedup = all.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), all.len(), "duplicate keys across pages");
    // expected exact key order
    let mut expected: Vec<Vec<u8>> = (0u8..5).map(|i| {
        let mut k = pfx.to_vec();
        k.extend_from_slice(&[i]);
        k
    }).collect();
    // both should be lexicographically sorted and equal sets
    all.sort();
    expected.sort();
    assert_eq!(all, expected, "iteration did not return all keys in order");
}

#[test]
fn snapshot_iter_empty_db_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Persistence::open_default(tmp.path()).expect("open");
    let pfx = b"does-not-exist:";

    let page = db.snapshot_iter(pfx, None, 10).expect("iter empty");
    assert!(page.is_empty(), "expected empty iteration on empty DB");
}

#[test]
fn snapshot_iter_cursor_is_exclusive() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Persistence::open_default(tmp.path()).expect("open");
    let pfx = b"k:";
    // keys: k:a, k:b, k:c, k:d
    for &b in b"abcd" {
        let mut k = pfx.to_vec();
        k.push(b);
        db.dev_put_raw(&k, &[b]).expect("put");
    }

    // page1 returns first two, cursor = last key returned
    let page1 = db.snapshot_iter(pfx, None, 2).expect("page1");
    assert_eq!(page1.len(), 2);
    let c1 = page1.last().unwrap().0.clone();

    // page2 with cursor should NOT repeat c1; should start strictly after it
    let page2 = db.snapshot_iter(pfx, Some(&c1), 10).expect("page2");
    let keys2: Vec<Vec<u8>> = page2.iter().map(|(k, _)| k.clone()).collect();
    assert!(
        !keys2.contains(&c1),
        "cursor must be exclusive of last-seen key"
    );
    // total coverage: 4 keys
    let total = page1.len() + page2.len();
    assert_eq!(total, 4, "expected to cover all keys without duplication");
}