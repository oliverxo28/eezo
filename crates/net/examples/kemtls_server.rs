use eezo_net::kem_adapter::MlKem768; // adapter type param
use eezo_net::secure::{server_accept_async, FramedSession};

use pqcrypto_mlkem::mlkem768::{keypair, PublicKey, SecretKey}; // keypair generator
use pqcrypto_traits::kem::PublicKey as _; // <-- enables pk.as_bytes()

use std::error::Error;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1) generate server keypair
    let (pk, sk): (PublicKey, SecretKey) = keypair();

    // 2) print SERVER_PK=0x... (use this for EEZO_KEMTLS_SERVER_PK)
    print!("SERVER_PK=0x");
    for b in pk.as_bytes() { print!("{:02x}", b); }
    println!();

    // 3) listen and accept KEMTLS handshakes
    let addr: SocketAddr = "127.0.0.1:18281".parse()?;
    let listener = TcpListener::bind(addr).await?;
    eprintln!("kemtls server listening on {}", addr);

    loop {
        let (mut io, _peer) = listener.accept().await?;
        // complete KEMTLS handshake (full or resume); then drop the session
        let _sess: FramedSession = server_accept_async::<MlKem768, _>(&sk, &mut io).await?;
    }
}
