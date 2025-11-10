use eezo_net::cert::{verify_certificate, GenesisRoot, ValidatorCertificate};
use pqcrypto_mldsa::mldsa44 as dsa;
use pqcrypto_traits::sign::{DetachedSignature as SigTrait, PublicKey as PkTrait};

#[test]
fn cert_roundtrip_verify() {
    let (root_pk, root_sk) = dsa::keypair();

    let ml_dsa_pk = dsa::keypair().0;
    let cert_core = ValidatorCertificate {
        validator_id: [7u8; 20],
        ml_dsa_pubkey: ml_dsa_pk.as_bytes().to_vec(),
        valid_from: 100,
        valid_until: 1_000_000,
        revoked: false,
        genesis_signature: vec![],
    };
    let mut cert = cert_core;

    // sign core with genesis root
    #[derive(serde::Serialize)]
    struct Core<'a> {
        validator_id: &'a [u8; 20],
        ml_dsa_pubkey: &'a [u8],
        valid_from: u64,
        valid_until: u64,
        revoked: bool,
    }
    let core = Core {
        validator_id: &cert.validator_id,
        ml_dsa_pubkey: &cert.ml_dsa_pubkey,
        valid_from: cert.valid_from,
        valid_until: cert.valid_until,
        revoked: cert.revoked,
    };
    let core_bytes = bincode::serialize(&core).unwrap();
    let sig = dsa::detached_sign(&core_bytes, &root_sk);
    cert.genesis_signature = sig.as_bytes().to_vec();

    let root = GenesisRoot { pk: root_pk };
    let parsed_pk = verify_certificate(&root, 123_456, &cert).expect("cert ok");
    assert_eq!(parsed_pk.as_bytes(), ml_dsa_pk.as_bytes());
}
