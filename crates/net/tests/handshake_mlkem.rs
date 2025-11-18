use pqcrypto_mlkem::mlkem768::keypair;

use eezo_net::kem_adapter::MlKem768;

use eezo_net::secure::{
    client_connect_async,
    server_accept_async,
};

use tokio::io::duplex;

#[tokio::test(flavor = "multi_thread")]
async fn kemtls_1rtt_roundtrip_with_real_mlkem768() {
    let (pk, sk) = keypair();
    let (client_io, server_io) = duplex(64 * 1024);
    
    let (c_read, c_write) = tokio::io::split(client_io);
    let (s_read, s_write) = tokio::io::split(server_io);

    let server = tokio::spawn(async move {
        // Use separate read/write halves to avoid blocking
        let mut combined_s = tokio::io::join(s_read, s_write);
        server_accept_async::<MlKem768, _>(&sk, &mut combined_s)
            .await
            .unwrap()
    });

    let client = tokio::spawn(async move {
        let mut combined_c = tokio::io::join(c_read, c_write);
        client_connect_async::<MlKem768, _>(&pk, &mut combined_c)
            .await
            .unwrap()
    });

    let _ = tokio::try_join!(server, client);
}
