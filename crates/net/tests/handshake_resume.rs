//! T37.1 — handshake resume path smoke tests

use eezo_net::kem_adapter::MlKem768;
use eezo_net::secure::{client_connect_async, client_connect_resume_async, server_accept_async};
use pqcrypto_mlkem::mlkem768::keypair;
use tokio::io::duplex;

async fn run_full_then_resume_once() {
    // -------- keypair --------
    let (pk, sk) = keypair();

    // ========= 1) full handshake (split + join to avoid read/write stalls) =========
    let (c_io1, s_io1) = duplex(64 * 1024);
    let (c_r1, c_w1) = tokio::io::split(c_io1);
    let (s_r1, s_w1) = tokio::io::split(s_io1);

    // server side
    let sk1 = sk.clone();
    let srv1 = tokio::spawn(async move {
        // accept and respond; we don't need the returned session on server side for this smoke
        let mut s_join = tokio::io::join(s_r1, s_w1);
        let _srv_sess = server_accept_async::<MlKem768, _>(&sk1, &mut s_join).await.unwrap();
    });

    // client side
    let mut c_join1 = tokio::io::join(c_r1, c_w1);
    let mut cli1 = client_connect_async::<MlKem768, _>(&pk, &mut c_join1)
        .await
        .expect("client full handshake");

    srv1.await.expect("server 1 join");

    // ticket from first handshake (rotation)
    let ticket1 = cli1.take_new_ticket().expect("server must issue ticket on full handshake");
    let sess1 = cli1.into_inner();
    assert!(!sess1.resumed, "first handshake must be a full (non-resumed) session");

    // ========= 2) resume using ticket1 (split + join) =========
    let (c_io2, s_io2) = duplex(64 * 1024);
    let (c_r2, c_w2) = tokio::io::split(c_io2);
    let (s_r2, s_w2) = tokio::io::split(s_io2);
    let sk2 = sk.clone();
    let srv2 = tokio::spawn(async move {
        let mut s_join = tokio::io::join(s_r2, s_w2);
        let _srv_sess = server_accept_async::<MlKem768, _>(&sk2, &mut s_join).await.unwrap();
    });

    let mut c_join2 = tokio::io::join(c_r2, c_w2);
    let mut cli2 = client_connect_resume_async::<MlKem768, _>(&pk, ticket1.clone(), &mut c_join2)
        .await
        .expect("client resume handshake");

    srv2.await.expect("server 2 join");

    let ticket2 = cli2
        .new_ticket()
        .map(|b| b.to_vec())
        .expect("server should rotate and issue a fresh ticket on resume");
    let sess2 = cli2.into_inner();
    assert!(sess2.resumed, "second handshake should be resumed");

    assert_ne!(
        ticket2, ticket1,
        "server should rotate to a new ticket on successful resume"
    );

    // ========= 3) replay the old ticket -> expect fallback (non-resume) =========
    // Using the same ticket again should be rejected by the replay set,
    // causing the server to fall back to a full KEM path (resumed == false).
    let (c_io3, s_io3) = duplex(64 * 1024);
    let (c_r3, c_w3) = tokio::io::split(c_io3);
    let (s_r3, s_w3) = tokio::io::split(s_io3);

    let sk3 = sk.clone();
    let srv3 = tokio::spawn(async move {
        let mut s_join = tokio::io::join(s_r3, s_w3);
        let _srv_sess = server_accept_async::<MlKem768, _>(&sk3, &mut s_join).await.unwrap();
    });

    let mut c_join3 = tokio::io::join(c_r3, c_w3);
    let cli3 = client_connect_resume_async::<MlKem768, _>(&pk, ticket1.clone(), &mut c_join3)
        .await
        .expect("client resume attempt #2");

    srv3.await.expect("server 3 join");
    let sess3 = cli3.into_inner();
    assert!(
        !sess3.resumed,
        "reusing a ticket must fall back to a full KEM handshake (not resumed)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kemtls_resume_smoke() {
    run_full_then_resume_once().await;
}
