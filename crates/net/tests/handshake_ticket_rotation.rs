//! T37.1 — ticket rotation & replay policy tests (kemtls module)

use eezo_net::kemtls::{
    validate_bytes, Epoch, Reject, TicketIssuer, TicketReplayStore, MIN_TICKET_LIFE,
};

fn epoch(n: u32) -> Epoch {
    n
}

#[test]
fn issues_unique_tickets_and_decodes() {
    let issuer = TicketIssuer::default();
    let sid = [7, 7, 7];

    let t1_raw = issuer.issue(sid, epoch(100));
    let t2_raw = issuer.issue(sid, epoch(101)); // rotated on “next epoch”

    assert_ne!(t1_raw, t2_raw, "ticket bytes must rotate (unique ids)");

    let t1 = validate_bytes(&t1_raw, epoch(100)).expect("t1 valid at issue time");
    let t2 = validate_bytes(&t2_raw, epoch(101)).expect("t2 valid at issue time");

    assert_eq!(t1.session_id, sid);
    assert_eq!(t2.session_id, sid);
    assert!(t1.epoch_expires >= t1.epoch_issued + MIN_TICKET_LIFE);
    assert!(t2.epoch_expires >= t2.epoch_issued + MIN_TICKET_LIFE);
}

#[test]
fn replay_rejected_then_accept_new_ticket() {
    let issuer = TicketIssuer::default();
    let mut store = TicketReplayStore::new(128, MIN_TICKET_LIFE);

    let sid = [1, 2, 3];
    let now = epoch(500);

    let raw = issuer.issue(sid, now);
    let t = validate_bytes(&raw, now).unwrap();

    // first use OK
    store.accept(&t, now).expect("first accept OK");

    // exact replay rejected
    let err = store.accept(&t, now).unwrap_err();
    assert_eq!(err, Reject::Replay);

    // new (rotated) ticket at next epoch should accept
    let raw2 = issuer.issue(sid, now + 1);
    let t2 = validate_bytes(&raw2, now + 1).unwrap();
    store.accept(&t2, now + 1).expect("rotated ticket accepted");
}

#[test]
fn expiry_enforced() {
    let issuer = TicketIssuer::default();
    let sid = [9, 9, 9];
    let now = epoch(900);

    let raw = issuer.issue(sid, now);
    // Move strictly past expiry
    let too_late = now + MIN_TICKET_LIFE + 1;
    let err = validate_bytes(&raw, too_late).unwrap_err();
    assert_eq!(err, Reject::Expired);
}

#[test]
fn lru_capacity_eviction_allows_reaccept_after_eviction() {
    // Small store to force eviction
    let mut store = TicketReplayStore::new(2, MIN_TICKET_LIFE);
    let issuer = TicketIssuer::default();
    let sid = [4, 4, 2];

    let raw1 = issuer.issue(sid, epoch(10));
    let raw2 = issuer.issue(sid, epoch(11));
    let raw3 = issuer.issue(sid, epoch(12));

    let t1 = validate_bytes(&raw1, epoch(10)).unwrap();
    let t2 = validate_bytes(&raw2, epoch(11)).unwrap();
    let t3 = validate_bytes(&raw3, epoch(12)).unwrap();

    // Accept t1, t2 — store is full
    store.accept(&t1, epoch(10)).unwrap();
    store.accept(&t2, epoch(11)).unwrap();

    // Accepting t3 causes LRU eviction of t1
    store.accept(&t3, epoch(12)).unwrap();

    // Since t1 was evicted from the replay set, it can be accepted again.
    // (This documents current policy: bounded-memory replay window.)
    store.accept(&t1, epoch(13)).expect("t1 re-accepts after eviction");
}
