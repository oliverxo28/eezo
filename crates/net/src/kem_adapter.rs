#![cfg(feature = "mlkem")]

use crate::handshake::{HandshakeError, Kem};

use pqcrypto_mlkem::mlkem768::{decapsulate, encapsulate, Ciphertext, PublicKey, SecretKey};

// Bring the traits into scope so their methods are available on the concrete types
use pqcrypto_traits::kem::{Ciphertext as CtTrait, SharedSecret as SsTrait};

pub struct MlKem;

impl Kem for MlKem {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    fn encap(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), HandshakeError> {
        // NOTE: pqcrypto-mlkem returns (SharedSecret, Ciphertext)
        let (ss_obj, ct_obj) = encapsulate(pk);
        Ok((ct_obj.as_bytes().to_vec(), ss_obj.as_bytes().to_vec()))
    }

    fn decap(ct: &[u8], sk: &Self::SecretKey) -> Result<Vec<u8>, HandshakeError> {
        // Recreate the ciphertext from its byte representation. To use the trait method, specify
        // the concrete type on the left-hand side so the compiler knows which implementation to pick.
        let ct_obj: Ciphertext =
            <Ciphertext as CtTrait>::from_bytes(ct).map_err(|_| HandshakeError::Kem)?;
        let ss_obj = decapsulate(&ct_obj, sk);
        // Convert the returned shared secret into raw bytes via the trait method.
        Ok(ss_obj.as_bytes().to_vec())
    }
}

/// T37.1: keep existing name but export the alias expected by callers.
pub type MlKem768 = MlKem;

impl MlKem {
    /// T37.1: Test helper function for generating ML-KEM 768 keypairs.
    /// Required by handshake_resume.rs and handshake_mlkem.rs tests.
    pub fn keypair() -> (PublicKey, SecretKey) {
        pqcrypto_mlkem::mlkem768::keypair()
    }
}
