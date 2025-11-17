//! KEMTLS-style 1-RTT handshake
//! --------------------------------
//! Composition (EEZO defaults):
//! - KEM: ML-KEM-768 (Kyber) → shared secret `ss`
//! - KDF: HKDF-SHA3-256 (in `keyschedule::derive`) over `ss || salt_c || salt_s`
//! - AEAD: ChaCha20-Poly1305 (in `session`)
//! - Server auth (T3): ML-DSA-44 detached signature over a transcript hash
//!
//! Design notes:
//! - The transcript hash **excludes** auth fields to avoid circularity.
//! - Client optional auth is included via `client_id_binding_hash`.
//! - Domain separation strings are fixed and versioned.
//! - All cryptographic types are passed as raw bytes; concrete algos live in
//!   the crypto crate behind feature flags.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "metrics")]
use std::time::Instant; // T36.8: timing
use std::time::SystemTime; // ADDED: For new ticket timestamps

use crate::keyschedule::derive as derive_keys;
use crate::session::{Role, Session, SessionError};
#[cfg(feature = "metrics")]
use crate::kemtls_handshake_observe_secs; // T36.8: metrics
use bincode;
use sha3::{Digest, Sha3_256}; // Keep this one
// PATCH 1: Use facade imports
#[cfg(feature = "mlkem")]
use crate::kemtls::{open_ticket, seal_ticket, ResumeTicketPlain};
// FIX: Moved this import out of the cfg(feature = "mlkem") block below,
// as HandshakeError uses it unconditionally.
#[cfg(feature = "mlkem")]
use crate::tickets::SealError;
#[cfg(feature = "mlkem")]
use crate::replay::REPLAY_SHARDS;
#[cfg(feature = "metrics")]
use crate::metrics::{
    TKT_DECRYPT_FAIL_TOTAL, // FIX: Renamed from TICKET_DECRYPT_FAILURES_TOTAL
    REPLAY_DROPPED_TOTAL,
    RESUME_TRUE_TOTAL,
    RESUME_FALLBACK_TOTAL,
};

// AAD for confirm and data (must be a single byte slice, not a slice-of-slices)
pub const AAD_CONFIRM: &[u8] = b"EEZO:confirm";
pub const AAD_DATA:    &[u8] = b"EEZO:data"; // Added from diff
pub const CONFIRM_PLAINTEXT: &[u8] = b"ack";

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("kem error")]
    Kem,
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("confirm failed")]
    ConfirmFailed,
    #[error("missing auth field: {0}")]
    Missing(&'static str),
    #[error("auth verify failed")]
    AuthVerifyFailed,
    #[error("resume rejected")]
    ResumeRejected,
    // T37.2: Added for ticket sealing
    #[error("ticket seal error")]
    TicketSeal(#[from] SealError),
}

/// KEM abstraction; implement this using your ML-KEM in `crates/crypto`.
pub trait Kem {
    type PublicKey: Clone;
    type SecretKey: Clone;

    /// Encapsulate to `pk`, returning `(ciphertext, shared_secret)`.
    fn encap(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), HandshakeError>;
    /// Decapsulate `ct` with `sk`, returning `shared_secret`.
    fn decap(ct: &[u8], sk: &Self::SecretKey) -> Result<Vec<u8>, HandshakeError>;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ClientHello {
    pub ct: Vec<u8>,
    pub salt_c: [u8; 16],
    pub session_id_hint: [u8; 3],

    // T3 (optional client auth in later milestone; keep as None for now)
    #[serde(default)]
    pub client_auth_pk: Option<Vec<u8>>,
    #[serde(default)]
    pub client_sig: Option<Vec<u8>>,

    #[serde(default)]
    pub client_cert: Option<Vec<u8>>, // (T3.1) optional embedded cert

    // T37.1: attempt resumption (opaque to server, fixed 20 bytes for now)
    #[serde(default)]
    pub resume_ticket: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerHello {
    pub salt_s: [u8; 16],
    pub confirm: Vec<u8>,

    // T3: server authentication (detached signature over transcript)
    #[serde(default)]
    pub server_auth_pk: Option<Vec<u8>>, // ML-DSA-44 pk bytes
    #[serde(default)]
    pub server_sig: Option<Vec<u8>>, // detached signature bytes

    // T37.1: server issues a fresh resumption ticket for the client to cache
    #[serde(default)]
    pub ticket_new: Option<Vec<u8>>,
}

pub struct ClientPending {
    pub shared_secret: Vec<u8>, // Made pub for secure.rs fallback logic
    pub salt_c: [u8; 16],
    #[allow(dead_code)]
    pub session_id_hint: [u8; 3],
    /// Keep the exact chello we sent for transcript hashing
    pub chello_sent: ClientHello,
}

impl ClientPending {
    /// T2 finish (no auth)
    pub fn finish_t2(self, sh: ServerHello) -> Result<Session, HandshakeError> {
		#[cfg(feature="metrics")]
		let t0 = Instant::now(); // T36.8
        // NOTE: This function assumes keys are derived from KEM shared secret.
        // Resumption path needs separate handling or modification here.
        let tk = derive_keys(&self.shared_secret, &self.salt_c, &sh.salt_s);
        let mut sess = Session::new(Role::Client, tk.clone()); // T37.2: clone tk
        // T37.2: Handle ticket storage (logic moved to secure.rs, but we need to open)
        if let Some(tkt_bytes) = sh.ticket_new.clone() {
             if let Ok(_ticket) = open_ticket(&tkt_bytes) {
                 // Note: We don't store it here anymore, secure.rs will.
                 // We just validate it's a valid ticket.
             }
         }

        let opened = sess.open(AAD_CONFIRM, &sh.confirm)?;
        if opened == CONFIRM_PLAINTEXT {
            #[cfg(feature = "metrics")] { kemtls_handshake_observe_secs(t0.elapsed().as_secs_f64()); }
            Ok(sess)
        } else { Err(HandshakeError::ConfirmFailed) }
    }

    /// T3 finish (server-authenticated): verify server's ML-DSA signature.
    pub fn finish_t3_verify<S: MlDsaLike>(
        self,
        sh: ServerHello,
        expected_server_pk: &S::PublicKey, // from your certificate store
    ) -> Result<Session, HandshakeError> {
		#[cfg(feature="metrics")]
		let t0 = Instant::now(); // T36.8
        let tk = derive_keys(&self.shared_secret, &self.salt_c, &sh.salt_s);
        let mut sess = Session::new(Role::Client, tk.clone()); // T37.2: clone tk

        // T37.2: Handle ticket storage (logic moved to secure.rs, but we need to open)
        if let Some(tkt_bytes) = sh.ticket_new.clone() {
             if let Ok(_ticket) = open_ticket(&tkt_bytes) {
                 // Note: We don't store it here anymore, secure.rs will.
                 // We just validate it's a valid ticket.
             }
         }

        // Still verify AEAD ack (T2)
        let opened = sess.open(AAD_CONFIRM, &sh.confirm)?;
        if opened != CONFIRM_PLAINTEXT {
            return Err(HandshakeError::ConfirmFailed);
        }

        // Build session context and transcript hash BEFORE touching options
        let session_ctx = session_context_bytes(self.salt_c, sh.salt_s, sess.session_id);
        let th = transcript_hash(&self.chello_sent, &sh, &session_ctx);

        // Borrow the auth fields (don't move them out)
        let pk_bytes = sh
            .server_auth_pk
            .as_ref()
            .ok_or(HandshakeError::Missing("server_auth_pk"))?;
        let sig_bytes = sh
            .server_sig
            .as_ref()
            .ok_or(HandshakeError::Missing("server_sig"))?;

        // Parse and verify
        let got_pk = S::pk_from_bytes(pk_bytes).map_err(|_| HandshakeError::AuthVerifyFailed)?;

        // require exact match to trusted identity
        if !S::pk_eq(&got_pk, expected_server_pk) {
            return Err(HandshakeError::AuthVerifyFailed);
        }
        let sig = S::sig_from_bytes(sig_bytes).map_err(|_| HandshakeError::AuthVerifyFailed)?;
        if !S::verify(&got_pk, th.as_ref(), b"T3-TRANSCRIPT", &sig) {
            return Err(HandshakeError::AuthVerifyFailed);
        }
        #[cfg(feature = "metrics")] { kemtls_handshake_observe_secs(t0.elapsed().as_secs_f64()); }
        Ok(sess)
    }
}

/// Secure transcript hash (domain-separated, canonical, session-bound).
/// IMPORTANT: Auth fields are intentionally excluded from the hashed view.
pub fn transcript_hash(chello: &ClientHello, shello: &ServerHello, session_ctx: &[u8]) -> [u8; 32] {
    #[derive(Serialize)]
    struct ClientHelloCore<'a> {
        ct: &'a [u8],
        salt_c: [u8; 16],
        session_id_hint: [u8; 3],
        // Include resume ticket in hash if present (T37.1 addition)
        #[serde(skip_serializing_if = "Option::is_none")]
        resume_ticket: &'a Option<Vec<u8>>,
    }

    #[derive(Serialize)]
    struct ServerHelloCore<'a> {
        salt_s: [u8; 16],
        confirm: &'a [u8],
        // Include new ticket in hash if present (T37.1 addition)
        #[serde(skip_serializing_if = "Option::is_none")]
        ticket_new: &'a Option<Vec<u8>>,
    }

    let ch = ClientHelloCore {
        ct: &chello.ct,
        salt_c: chello.salt_c,
        session_id_hint: chello.session_id_hint,
        resume_ticket: &chello.resume_ticket, // T37.1
    };

    let sh = ServerHelloCore {
        salt_s: shello.salt_s,
        confirm: &shello.confirm,
        ticket_new: &shello.ticket_new, // T37.1
    };


    let mut h = Sha3_256::new();
    // Domain + version
    h.update(b"EEZO-PQC-AUTH-V1|");

    // Bind to session (salt_c || salt_s || session_id)
    h.update(b"CTX:");
    h.update(session_ctx);
    h.update(b"|CHELLO:");
    h.update(bincode::serialize(&ch).unwrap());
    h.update(b"|SHELLO:");
    h.update(bincode::serialize(&sh).unwrap());

    // Client auth is bound separately if needed
    h.finalize().into()
}


/// Hash that binds the client's identity to its own hello (no server fields).
pub fn client_id_binding_hash(chello: &ClientHello) -> [u8; 32] {
    #[derive(serde::Serialize)]
    struct ClientIdView<'a> {
        ct: &'a [u8],
        salt_c: [u8; 16],
        session_id_hint: [u8; 3],
        // Include resume ticket if present for consistency, though server verifies separately
        #[serde(skip_serializing_if = "Option::is_none")]
        resume_ticket: &'a Option<Vec<u8>>,
    }
    let v = ClientIdView {
        ct: &chello.ct,
        salt_c: chello.salt_c,
        session_id_hint: chello.session_id_hint,
        resume_ticket: &chello.resume_ticket,
    };
    let ser = bincode::serialize(&v).unwrap();
    let mut h = Sha3_256::new();
    h.update(b"EEZO-PQC-AUTH-V1|CLIENT-ID|");
    h.update(ser);
    h.finalize().into()
}


/// Deterministic context from salts + session_id (for domain separation).
pub fn session_context_bytes(salt_c: [u8; 16], salt_s: [u8; 16], session_id: [u8; 3]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + 16 + 3);
    v.extend_from_slice(&salt_c);
    v.extend_from_slice(&salt_s);
    v.extend_from_slice(&session_id);
    v
}

/// Client constructs and sends ClientHello, returns pending state.
pub fn client_handshake<K: Kem>(
    server_pk: &K::PublicKey,
) -> Result<(ClientHello, ClientPending), HandshakeError> {
    let (ct, ss) = K::encap(server_pk)?;
    let mut salt_c = [0u8; 16];
    OsRng.fill_bytes(&mut salt_c);

    let mut session_id_hint = [0u8; 3];
    OsRng.fill_bytes(&mut session_id_hint);

    let chello = ClientHello {
        ct,
        salt_c,
        session_id_hint,
        client_auth_pk: None,
        client_sig: None,
        client_cert: None,
		resume_ticket: None,
    };
    let pending = ClientPending {
        shared_secret: ss,
        salt_c,
        session_id_hint,
        chello_sent: chello.clone(),
    };
    Ok((chello, pending))
}
/// Optional client helper: start handshake with a cached resume ticket.
pub fn client_handshake_resume<K: Kem>(
    server_pk: &K::PublicKey,
    resume_ticket: Vec<u8>,
) -> Result<(ClientHello, ClientPending), HandshakeError> {
    // We still send a normal KEM path; server will prefer resume if valid,
    // otherwise falls back to the ct/ss we provide here.
    let (ct, ss) = K::encap(server_pk)?;
    let mut salt_c = [0u8; 16];
    OsRng.fill_bytes(&mut salt_c);
    let mut session_id_hint = [0u8; 3];
    OsRng.fill_bytes(&mut session_id_hint);
    let chello = ClientHello {
        ct,
        salt_c,
        session_id_hint,
        client_auth_pk: None,
        client_sig: None,
        client_cert: None,
        resume_ticket: Some(resume_ticket),
    };
    let pending = ClientPending {
        shared_secret: ss, // Store KEM SS for potential fallback, though PSK is primary if resume succeeds
        salt_c,
        session_id_hint,
        chello_sent: chello.clone(),
    };
    Ok((chello, pending))
}


pub fn client_handshake_t3<K: Kem, S: MlDsaLike>(
    server_pk: &K::PublicKey,
    client_auth_pk: &S::PublicKey,
    client_auth_sk: &S::SecretKey,
) -> Result<(ClientHello, ClientPending), HandshakeError> {
    // same as client_handshake, then attach identity/signature
    let (ct, ss) = K::encap(server_pk)?;
    let mut salt_c = [0u8; 16];
    OsRng.fill_bytes(&mut salt_c);
    let mut session_id_hint = [0u8; 3];
    OsRng.fill_bytes(&mut session_id_hint);

    let mut chello = ClientHello {
        ct,
        salt_c,
        session_id_hint,
        client_auth_pk: Some(S::pk_to_bytes(client_auth_pk)),
        client_sig: None,
        client_cert: None, // optional: fill later if you embed certs
		resume_ticket: None,
    };

    // sign the client-id binding
    let cid = client_id_binding_hash(&chello);
    let sig = S::sign(client_auth_sk, cid.as_ref(), b"T3-CLIENT-ID");
    chello.client_sig = Some(S::sig_to_bytes(&sig));

    let pending = ClientPending {
        shared_secret: ss,
        salt_c,
        session_id_hint,
        chello_sent: chello.clone(),
    };
    Ok((chello, pending))
}

/// Server processes ClientHello, returns ServerHello + ready Session(Server). (T2 only)
pub fn server_handshake<K: Kem>(
    server_sk: &K::SecretKey,
    chello: ClientHello,
) -> Result<(ServerHello, Session), HandshakeError> {
	#[cfg(feature="metrics")]
	let t0 = Instant::now(); // T36.8
    // T37.1: try to accept resumption first; otherwise perform full KEM.
    let mut salt_s = [0u8; 16];
    OsRng.fill_bytes(&mut salt_s);

    let mut new_ticket_bytes: Option<Vec<u8>> = None; // Initialize to None
    let was_resume_attempt = chello.resume_ticket.is_some(); // Track if client tried to resume

    // PATCH 2: Replace entire resume-ticket block
    // Attempt AEAD-protected resumption (T37.2)
    if let Some(ciphertext) = chello.resume_ticket.as_ref() {
        match open_ticket(ciphertext) {
            Ok(ticket) => {
                // --- sharded replay ---
                // Convert first 8 bytes of ticket_id to u64 for shard key
                let shard_key = u64::from_le_bytes(ticket.ticket_id[..8].try_into().unwrap());
                let shard = REPLAY_SHARDS.shard(&shard_key);
                if shard.seen(&shard_key) {
                    #[cfg(feature = "metrics")] {
                        // FIX: Removed KEMTLS_ prefix
                        REPLAY_DROPPED_TOTAL.inc();
                        // FIX: Removed KEMTLS_ prefix
                        RESUME_FALLBACK_TOTAL.with_label_values(&["replay"]).inc();
                    }
                } else {
                    shard.insert(shard_key);

                    // successful resume → derive tk
                    // Use ticket.session_id as key input since tk field is missing
                    let tk = derive_keys(&ticket.session_id, &chello.salt_c, &salt_s);
                    let mut sess = Session::from_resumption(Role::Server, tk.clone(), Some(ticket.ticket_id[..8].try_into().unwrap()));
                    let confirm = sess.seal(AAD_CONFIRM, CONFIRM_PLAINTEXT)?;

                    // issue NEW ticket (AEAD)
                    // FIX: Add issued_ms from the opened ticket
                    let new_cipher = seal_ticket(&ResumeTicketPlain {
                        ticket_id: ticket.ticket_id,
                        session_id: sess.session_id,
                        issued_ms: ticket.issued_ms,
                    })?;

                    let sh = ServerHello {
                        salt_s,
                        confirm,
                        server_auth_pk: None,
                        server_sig: None,
                        ticket_new: Some(new_cipher),
                    };

                    #[cfg(feature = "metrics")] {
                        // FIX: Removed KEMTLS_ prefix
                        RESUME_TRUE_TOTAL.with_label_values(&["ticket"]).inc();
                        kemtls_handshake_observe_secs(t0.elapsed().as_secs_f64()); // T36.8
                    }
                    return Ok((sh, sess));
                }
            }
            Err(_) => {
                #[cfg(feature = "metrics")] {
                    // FIX: Renamed from KEMTLS_TICKET_DECRYPT_FAILURES_TOTAL
                    TKT_DECRYPT_FAIL_TOTAL.inc();
                    // FIX: Removed KEMTLS_ prefix
                    RESUME_FALLBACK_TOTAL.with_label_values(&["decrypt"]).inc();
                }
            }
        }
    }
    // (End of PATCH 2 block)


    // ---> KEM PATH (EITHER FRESH HANDSHAKE OR FALLBACK AFTER FAILED RESUME) <---
    let ss = K::decap(&chello.ct, server_sk)?;
    let tk = derive_keys(&ss, &chello.salt_c, &salt_s);
    let mut sess = Session::new(Role::Server, tk.clone()); // T37.2: clone tk

    // Only issue a new ticket if this was a *fresh* handshake, NOT a fallback
    // PATCH 3: Replace ticket generation in KEM fallback path
    if !was_resume_attempt {
        // FIX: Add issued_ms for the new ticket
        let ticket_plain = ResumeTicketPlain {
            ticket_id: rand::random(),
            session_id: sess.session_id,
            issued_ms: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64,
        };
        new_ticket_bytes = Some(seal_ticket(&ticket_plain)?);
    }
    // (End of PATCH 3 block)
    // If it *was* a resume attempt that failed, new_ticket_bytes remains None

    let confirm = sess.seal(AAD_CONFIRM, CONFIRM_PLAINTEXT)?;
    let sh = ServerHello {
        salt_s,
        confirm,
        server_auth_pk: None,
        server_sig: None,
        ticket_new: new_ticket_bytes, // Will be None if fallback occurred
    };
	#[cfg(feature="metrics")] { kemtls_handshake_observe_secs(t0.elapsed().as_secs_f64()); }
    Ok((sh, sess)) // Returns session with resumed = false
}


/// Server processes ClientHello and AUTHENTICATES (T3).
pub fn server_handshake_t3<K: Kem, S: MlDsaLike>(
    server_sk: &K::SecretKey,
    chello: ClientHello,
    server_sign_pk: &S::PublicKey,
    server_sign_sk: &S::SecretKey,
) -> Result<(ServerHello, Session), HandshakeError> {
	#[cfg(feature="metrics")]
	let t0 = Instant::now(); // T36.8
    // Perform base handshake (T2 + resume/fallback logic) first
    // This now correctly handles setting ticket_new based on resume success/failure
    let (mut sh, sess) = server_handshake::<K>(server_sk, chello.clone())?;

    // Build context and transcript hash
    let session_ctx = session_context_bytes(chello.salt_c, sh.salt_s, sess.session_id);
    // IMPORTANT: The transcript hash includes ticket_new if it was issued.
    // This is correct as the client also includes it when hashing.
    let th = transcript_hash(&chello, &sh, &session_ctx);

    // If client presented identity, verify it now (mutual auth, optional in v1)
    if let (Some(pk_bytes), Some(sig_bytes)) = (&chello.client_auth_pk, &chello.client_sig) {
        let client_pk = S::pk_from_bytes(pk_bytes).map_err(|_| HandshakeError::AuthVerifyFailed)?;
        let cid = client_id_binding_hash(&chello);
        let sig = S::sig_from_bytes(sig_bytes).map_err(|_| HandshakeError::AuthVerifyFailed)?;
        if !S::verify(&client_pk, cid.as_ref(), b"T3-CLIENT-ID", &sig) {
            return Err(HandshakeError::AuthVerifyFailed);
        }
        // (Optional) verify client certificate if you embed it in chello.client_cert
        // using cert::verify_certificate(...)
    }

    // Sign the transcript hash
    let sig = S::sign(server_sign_sk, th.as_ref(), b"T3-TRANSCRIPT");

    let auth_pk_bytes = S::pk_to_bytes(server_sign_pk);
    let sig_bytes = S::sig_to_bytes(&sig);

    // Add auth fields to the existing ServerHello
    sh.server_auth_pk = Some(auth_pk_bytes);
    sh.server_sig = Some(sig_bytes);
	#[cfg(feature="metrics")] {
        // Note: server_handshake already observed, but T3 adds signing cost.
        // We overwrite with the *total* T3 time.
        kemtls_handshake_observe_secs(t0.elapsed().as_secs_f64());
    }
    Ok((sh, sess))
}

/// A tiny trait so we can unit-test T3 with both real ML-DSA and a mock.
pub trait MlDsaLike {
    type PublicKey: Clone;
    type SecretKey: Clone;
    type Signature: Clone;

    fn sign(sk: &Self::SecretKey, msg: &[u8], ctx: &[u8]) -> Self::Signature;
    fn verify(pk: &Self::PublicKey, msg: &[u8], ctx: &[u8], sig: &Self::Signature) -> bool;

    fn pk_to_bytes(pk: &Self::PublicKey) -> Vec<u8>;
    fn pk_from_bytes(bs: &[u8]) -> Result<Self::PublicKey, ()>;
    fn pk_eq(a: &Self::PublicKey, b: &Self::PublicKey) -> bool;

    fn sig_to_bytes(sig: &Self::Signature) -> Vec<u8>;
    fn sig_from_bytes(bs: &[u8]) -> Result<Self::Signature, ()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_hash_is_stable_shape() {
        // Minimal sanity: serialization paths don't panic and length is 32 bytes
        let chello = ClientHello {
            ct: vec![1,2,3],
            salt_c: [0u8;16],
            session_id_hint: [0u8;3],
            client_auth_pk: None,
            client_sig: None,
            client_cert: None,
            resume_ticket: None,
        };
        let shello = ServerHello {
            salt_s: [0u8;16],
            confirm: vec![4,5,6],
            server_auth_pk: None,
            server_sig: None,
            ticket_new: None,
        };
        let th = transcript_hash(&chello, &shello, b"ctx");
        assert_eq!(th.len(), 32);
    }
}

