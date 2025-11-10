// crates/net/tests/secure_async.rs

// Use the net-layer KEM adapter type for the handshake generics
type K = eezo_net::kem_adapter::MlKem768;

use eezo_net::secure::{client_connect_async, server_accept_async};
use tokio::io::duplex;

// Pull keypair directly from pqcrypto-mlkem, since eezo_crypto::kem::ml_kem wraps it
use pqcrypto_mlkem::mlkem768::{keypair, PublicKey, SecretKey};

#[tokio::test(flavor = "multi_thread")]
async fn secure_async_roundtrip_with_real_mlkem() {
    // Generate a real ML-KEM keypair (Kyber768)
    let (pk, sk): (PublicKey, SecretKey) = keypair();

    // In-memory duplex to simulate client/server IO
    let (mut client_io, mut server_io) = duplex(64 * 1024);

    let client = async {
        // T2 (no auth) client connect with K as the KEM type
        let mut fs = client_connect_async::<K, _>(&pk, &mut client_io)
            .await
            .unwrap();

        fs.write_frame_async(&mut client_io, b"hello").await.unwrap();
        let got = fs.read_frame_async(&mut client_io).await.unwrap();
        assert_eq!(got, b"world");
    };

    let server = async {
        let mut fs = server_accept_async::<K, _>(&sk, &mut server_io)
            .await
            .unwrap();

        let got = fs.read_frame_async(&mut server_io).await.unwrap();
        assert_eq!(got, b"hello");
        fs.write_frame_async(&mut server_io, b"world").await.unwrap();
    };

    tokio::join!(client, server);
}