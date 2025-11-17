// crates/net/tests/handshake.rs
use eezo_net::handshake::{client_handshake, server_handshake, Kem};
use eezo_net::session::Session;
use rand::{rngs::OsRng, RngCore};

/// ----- Mock KEM for tests (NOT SECURE) -----
#[derive(Clone)]
struct MockPk([u8; 32]);
#[allow(dead_code)]
#[derive(Clone)]
struct MockSk([u8; 32]);
struct MockKem;

impl Kem for MockKem {
    type PublicKey = MockPk;
    type SecretKey = MockSk;

    fn encap(
        pk: &Self::PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), eezo_net::handshake::HandshakeError> {
        // ct = pk || rand16; ss = SHA3("SS" || pk || rand16)
        use sha3::{Digest, Sha3_256};
        let mut ct = Vec::with_capacity(48);
        ct.extend_from_slice(&pk.0);
        let mut r = [0u8; 16];
        OsRng.fill_bytes(&mut r);
        ct.extend_from_slice(&r);
        let mut h = Sha3_256::new();
        h.update(b"SS");
        h.update(pk.0);
        h.update(r);
        Ok((ct, h.finalize().to_vec()))
    }

    fn decap(
        ct: &[u8],
        _sk: &Self::SecretKey,
    ) -> Result<Vec<u8>, eezo_net::handshake::HandshakeError> {
        use sha3::{Digest, Sha3_256};
        assert!(ct.len() >= 48);
        let pk = &ct[0..32];
        let r = &ct[32..48];
        let mut h = Sha3_256::new();
        h.update(b"SS");
        h.update(pk);
        h.update(r);
        Ok(h.finalize().to_vec())
    }
}

#[test]
fn kemtls_1rtt_roundtrip() {
    // pretend server keypair bytes (mock)
    let mut sk = [0u8; 32];
    OsRng.fill_bytes(&mut sk);
    let mut pk = [0u8; 32];
    OsRng.fill_bytes(&mut pk);

    // client -> server
    let (chello, pending) = client_handshake::<MockKem>(&MockPk(pk)).unwrap();
    // server -> client
    let (shello, mut server_sess) = server_handshake::<MockKem>(&MockSk(sk), chello).unwrap();
    // client finalizes (verifies "ack")
    let mut client_sess: Session = pending.finish_t2(shello).unwrap();

    // traffic both ways
    let aad = b"EEZO:data";
    let m1 = b"ping from client";
    let c1 = client_sess.seal(aad, m1).unwrap();
    let p1 = server_sess.open(aad, &c1).unwrap();
    assert_eq!(p1, m1);

    let m2 = b"pong from server";
    let c2 = server_sess.seal(aad, m2).unwrap();
    let p2 = client_sess.open(aad, &c2).unwrap();
    assert_eq!(p2, m2);
}
