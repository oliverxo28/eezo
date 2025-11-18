//! T37.1 — ticket rotation & replay policy tests (kemtls module)

use eezo_net::replay::ShardedReplay;
use eezo_net::tickets::{self};

// `Epoch` is no longer used, timestamps are u64
#[allow(dead_code)]
fn epoch_ms(s: u64) -> u64 {
    s * 1000
}

fn now() -> u64 {
    tickets::now_ms()
}

/// id = low byte of ticket_id[0]
fn t(id: u8, issued_ms: u64) -> tickets::ResumeTicketPlain {
    let mut ticket_id = [0u8; 12];
    ticket_id[0] = id;
    tickets::ResumeTicketPlain {
        ticket_id,
        issued_ms,
        session_id: [0; 3],
    }
}

#[test]
fn replay_window_accepts_and_rejects() {
    let store = ShardedReplay::new(128); // No 'mut' needed if we just use shard()
    let t1 = t(1, now());
    let key1 = u64::from_le_bytes(t1.ticket_id[..8].try_into().unwrap());
    assert!(store.shard(&key1).insert_if_absent(key1), "first accept OK");

    // check again
    assert!(!store.shard(&key1).insert_if_absent(key1), "should be a replay");

    // rotated
    let t2 = t(3, now() + 1);
    let key2 = u64::from_le_bytes(t2.ticket_id[..8].try_into().unwrap());
    assert!(store.shard(&key2).insert_if_absent(key2), "rotated ticket accepted");
}

#[test]
#[ignore] // This test logic is invalid for the new ShardedReplay (HashSet)
fn replay_eviction() {
    // // 2-slot store
    // let mut store = TicketReplayStore::new(2, MIN_TICKET_LIFE);
    // assert_eq!(store.capacity(), 2);
    // 
    // let t1 = t(1, epoch_ms(10));
    // let t2 = t(2, epoch_ms(11));
    // let t3 = t(3, epoch_ms(12));
    // 
    // // logic would change here
    // store.accept(&t1, epoch_ms(10)).unwrap();
    // store.accept(&t2, epoch_ms(11)).unwrap();
    // 
    // // evict t1
    // store.accept(&t3, epoch_ms(12)).unwrap();
    // 
    // // t1 should now be accepted again
    // store.accept(&t1, epoch_ms(13)).expect("t1 re-accepts after eviction");
}