// crates/ledger/tests/witness.rs
use eezo_ledger::tx::TxWitness;
use eezo_ledger::consensus::{SigBytes, SIG_LEN};

#[test]
fn witness_basic_shape_and_contents() {
    let payload_hash = [0u8; 32];

    // One ML-DSA signature, fixed length SIG_LEN
    let sig = SigBytes([7u8; SIG_LEN]);

    let w = TxWitness {
        payload_hash,
        sigs: vec![sig],
    };

    assert_eq!(w.payload_hash, payload_hash);
    assert_eq!(w.sigs.len(), 1);
    assert_eq!(w.sigs[0].0, [7u8; SIG_LEN]);
}
