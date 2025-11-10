#![cfg(feature = "checkpoints")]
use eezo_ledger::checkpoints::{qc_message_bytes, QC_DOMAIN};

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[test]
fn domain_constants_are_unique_and_nonempty() {
    // Collect all domain constants you care about
    // Extend this array if you add more (e.g. TX_DOMAIN, ANCHOR_DOMAIN, etc.)
    let domains = vec![QC_DOMAIN];

    // Non-empty and ASCII
    for d in &domains {
        assert!(!d.is_empty(), "domain must not be empty");
        assert!(d.is_ascii(), "domain must be ASCII");
    }

    // Uniqueness
    for i in 0..domains.len() {
        for j in (i + 1)..domains.len() {
            assert_ne!(domains[i], domains[j], "domains must be distinct");
        }
    }
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[test]
fn domain_prefix_is_bound_in_qc_message() {
    let chain = [0xE0u8; 20];
    let h: u64 = 7;
    let bh = [1u8; 32];

    let msg = qc_message_bytes(chain, h, &bh);
    assert!(
        msg.starts_with(QC_DOMAIN),
        "qc_message_bytes must prefix with QC_DOMAIN"
    );

    // Determinism
    let msg2 = qc_message_bytes(chain, h, &bh);
    assert_eq!(msg, msg2, "same input must give same output");

    // Input sensitivity: flip height → different
    let msg3 = qc_message_bytes(chain, h + 1, &bh);
    assert_ne!(msg, msg3, "height change must affect message");

    // Input sensitivity: flip chain → different
    let mut chain2 = chain;
    chain2[0] ^= 0xFF;
    let msg4 = qc_message_bytes(chain2, h, &bh);
    assert_ne!(msg, msg4, "chain change must affect message");

    // Input sensitivity: flip hash → different
    let mut bh2 = bh;
    bh2[0] ^= 0xFF;
    let msg5 = qc_message_bytes(chain, h, &bh2);
    assert_ne!(msg, msg5, "qc_hash change must affect message");
}