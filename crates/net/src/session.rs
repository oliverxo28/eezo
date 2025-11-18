#![allow(deprecated)]
//! Transport session with AEAD contexts and nonce sequences.
//!
//! Nonce format: flag(1) | session_id(3) | counter(8, LE).
//! Separate counters per direction; overflow => error.

use aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use core::convert::TryInto;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keyschedule::{TrafficKeys, KEY_LEN};
// T36.8: metrics (optional)
// (metrics import removed; we now mark sessions centrally in secure.rs)

pub const FLAG_C2S: u8 = 0xC1;
pub const FLAG_S2C: u8 = 0xC2;
/// Wire version for resumption tickets produced in T37.1
pub const TICKET_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("nonce counter overflow")]
    NonceOverflow,
    #[error("aead failure")]
    Aead,
}

#[derive(Clone)]
pub enum Role {
    Client,
    Server,
}

/// Opaque (to peers) resumable ticket metadata we carry *after* verification.
/// NOTE: actual authenticity/confidentiality is handled in the handshake layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumeTicket {
    /// ticket format version (allows rotation of layout)
    pub version: u8,
    /// 3-byte short session id bound into nonces
    pub session_id: [u8; 3],
    /// epoch the ticket was issued in (rotation on view change)
    pub epoch_issued: u32,
    /// epoch when ticket expires (>= epoch_issued + 10 by policy)
    pub epoch_expires: u32,
    /// anti-replay identifier (server maintains a small LRU/set of seen ids)
    pub ticket_id: [u8; 8],
}

impl ResumeTicket {
    /// Fixed serialized length: 1 + 3 + 4 + 4 + 8 = 20 bytes
    pub const LEN: usize = 20;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.version;
        out[1..4].copy_from_slice(&self.session_id);
        out[4..8].copy_from_slice(&self.epoch_issued.to_le_bytes());
        out[8..12].copy_from_slice(&self.epoch_expires.to_le_bytes());
        out[12..20].copy_from_slice(&self.ticket_id);
        out
    }

    /// Decode without authenticity checks (those are performed by handshake).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LEN { return None; }
        let version = bytes[0];
        let session_id: [u8; 3] = bytes[1..4].try_into().ok()?;
        let epoch_issued = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let epoch_expires = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let ticket_id: [u8; 8] = bytes[12..20].try_into().ok()?;
        Some(Self { version, session_id, epoch_issued, epoch_expires, ticket_id })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NonceSeq {
    flag: u8,
    session_id: [u8; 3],
    counter: u64,
}

impl NonceSeq {
    pub fn new(flag: u8, session_id: [u8; 3]) -> Self {
        Self {
            flag,
            session_id,
            counter: 0,
        }
    }

    fn next(&mut self) -> Result<[u8; 12], SessionError> {
        let ctr = self
            .counter
            .checked_add(1)
            .ok_or(SessionError::NonceOverflow)?;
        self.counter = ctr;
        let mut n = [0u8; 12];
        n[0] = self.flag;
        n[1..4].copy_from_slice(&self.session_id);
        n[4..12].copy_from_slice(&ctr.to_le_bytes());
        Ok(n)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    // keys — wiped on drop
    pub(crate) k_c2s: [u8; KEY_LEN],
    pub(crate) k_s2c: [u8; KEY_LEN],

    // AEADs — not Zeroize; skip (keys are stored & wiped above)
    #[zeroize(skip)]
    aead_c2s: ChaCha20Poly1305,
    #[zeroize(skip)]
    aead_s2c: ChaCha20Poly1305,

    // nonce sequences — wiped on drop
    pub(crate) send_seq: NonceSeq,
    pub(crate) recv_seq: NonceSeq,

    // role isn’t Zeroize; skip
    #[zeroize(skip)]
    pub role: Role,

    // short ID — wiped on drop
    pub session_id: [u8; 3],
    /// true if this session was established via resumption
    #[zeroize(skip)]
    pub resumed: bool,
    /// optional ticket id bound to this session for replay analytics
    pub ticket_id: Option<[u8; 8]>,
}

impl Session {
	/// fresh full handshake session
    pub fn new(role: Role, tk: TrafficKeys) -> Self {
        let aead_c2s = ChaCha20Poly1305::new(Key::from_slice(&tk.k_c2s));
        let aead_s2c = ChaCha20Poly1305::new(Key::from_slice(&tk.k_s2c));
        let (send_seq, recv_seq) = match role {
            Role::Client => (
                NonceSeq::new(FLAG_C2S, tk.session_id),
                NonceSeq::new(FLAG_S2C, tk.session_id),
            ),
            Role::Server => (
                NonceSeq::new(FLAG_S2C, tk.session_id),
                NonceSeq::new(FLAG_C2S, tk.session_id),
            ),
        };
        Self {
            k_c2s: tk.k_c2s,
            k_s2c: tk.k_s2c, // <-- FIX: Was k_c2s
            aead_c2s,
            aead_s2c,
            send_seq,
            recv_seq,
            role,
            session_id: tk.session_id,
			resumed: false,
			ticket_id: None,
        }
    } // <-- FIX: Added missing brace
	
    /// resumption constructor (keys already derived from PSK/ticket by handshake)
    pub fn from_resumption(role: Role, tk: TrafficKeys, ticket_id: Option<[u8; 8]>) -> Self {
        let mut s = Self::new(role, tk);
        s.resumed = true;
        s.ticket_id = ticket_id;
        s
    }

    fn aead_for_send(&self) -> &ChaCha20Poly1305 {
        match self.role {
            Role::Client => &self.aead_c2s,
            Role::Server => &self.aead_s2c,
        }
    }
    fn aead_for_recv(&self) -> &ChaCha20Poly1305 {
        match self.role {
            Role::Client => &self.aead_s2c,
            Role::Server => &self.aead_c2s,
        }
    }

    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.send_seq.next()?;
        self.aead_for_send()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| SessionError::Aead)
    }

    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.recv_seq.next()?;
        self.aead_for_recv()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| SessionError::Aead)
    }
}