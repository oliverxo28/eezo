use pqcrypto_mlkem::mlkem768::keypair as kem_keypair;
use eezo_net::kem_adapter::MlKem768;
use eezo_net::secure::{client_connect_auth_async, server_accept_auth_async};
use eezo_net::sig_adapter::{MlDsa, MlDsaLikeImpl};
use tokio::io::duplex;

#[tokio::test(flavor = "multi_thread")]
async fn t3_secure_async_auth_roundtrip() {
    let (kem_pk, kem_sk) = kem_keypair();
    let (auth_pk, auth_sk) = MlDsa::keypair();

    let (mut c, mut s) = duplex(64 * 1024);

    let client = async {
        let mut fs =
            client_connect_auth_async::<MlKem768, MlDsaLikeImpl, _>(&kem_pk, &auth_pk, &mut c)
                .await
                .unwrap();
        fs.write_frame_async(&mut c, b"hello").await.unwrap();
        let got = fs.read_frame_async(&mut c).await.unwrap();
        assert_eq!(got, b"world");
    };

    let server = async {
        let mut fs = server_accept_auth_async::<MlKem768, MlDsaLikeImpl, _>(
            &kem_sk, &auth_pk, &auth_sk, &mut s,
        )
        .await
        .unwrap();
        let got = fs.read_frame_async(&mut s).await.unwrap();
        assert_eq!(got, b"hello");
        fs.write_frame_async(&mut s, b"world").await.unwrap();
    };

    tokio::join!(client, server);
}