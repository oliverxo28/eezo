use pqcrypto_mlkem::mlkem768::keypair as kem_keypair;
use eezo_net::handshake::{client_handshake_t3, server_handshake_t3};
use eezo_net::kem_adapter::MlKem768;
use eezo_net::sig_adapter::{MlDsa, MlDsaLikeImpl};

#[test]
#[ignore = "T3 auth handshake is exercised in secure_async_auth; this unit uses an older flow and returns Err(Kem) with current API"]
fn t3_server_auth_roundtrip_ml_dsa() {
    // KEM keys
    let (kem_pk, kem_sk) = kem_keypair();
    // ML-DSA identities (server + client)
    let (auth_pk, auth_sk) = MlDsa::keypair(); // server
    let (client_pk, client_sk) = MlDsa::keypair(); // client

    // client -> server (T3)
    let (chello, pending) =
        client_handshake_t3::<MlKem768, MlDsaLikeImpl>(&kem_pk, &client_pk, &client_sk).unwrap();

    // server -> client (signs)
    let (shello, _server_sess) =
        server_handshake_t3::<MlKem768, MlDsaLikeImpl>(&kem_sk, chello.clone(), &auth_pk, &auth_sk)
            .unwrap();

    // client finalizes: verifies AEAD ack + ML-DSA signature
    let _client_sess = pending
        .finish_t3_verify::<MlDsaLikeImpl>(shello, &auth_pk)
        .unwrap();
}

#[test]
#[ignore = "See note above; keep ignored until we align this test with current T3 structs"]
fn t3_server_auth_replay_prevention() {
    // If session context changes, transcript hash differs -> signature invalid.
    let (kem_pk, kem_sk) = kem_keypair();
    let (auth_pk, auth_sk) = MlDsa::keypair(); // server
    let (client_pk, client_sk) = MlDsa::keypair(); // client

    let (chello1, pending1) =
        client_handshake_t3::<MlKem768, MlDsaLikeImpl>(&kem_pk, &client_pk, &client_sk).unwrap();

    let (_shello1, _s1) =
        server_handshake_t3::<MlKem768, MlDsaLikeImpl>(&kem_sk, chello1.clone(), &auth_pk, &auth_sk)
            .unwrap();

    // Use a completely new client hello (different salt_c / context)
    let (chello2, _pending2) =
        client_handshake_t3::<MlKem768, MlDsaLikeImpl>(&kem_pk, &client_pk, &client_sk).unwrap();
    let (shello2, _s2) =
        server_handshake_t3::<MlKem768, MlDsaLikeImpl>(&kem_sk, chello2.clone(), &auth_pk, &auth_sk)
            .unwrap();

    // original pending must fail to verify with different context
    let bad = pending1.finish_t3_verify::<MlDsaLikeImpl>(shello2, &auth_pk);
    assert!(bad.is_err());
}

