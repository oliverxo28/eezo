//! opaque AEAD-protected resume tickets with key rotation
//! format: versioned, aead(chacha20poly1305), aad = b"EEZO:TKT|v1|" || node_id
//! plaintext = ticket_id(12) || issued_unix_ms(8) || session_id(3) || reserved(1)

use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::OnceCell;
use thiserror::Error; // ADDED THIS IMPORT

const VERSION: u8 = 1;
const AAD_PREFIX: &[u8] = b"EEZO:TKT|v1|";

#[derive(Clone)]
pub struct TekSet {
    /// current and previous Ticket Encryption Keys (32 bytes each)
    pub tek_current: [u8; 32],
    pub tek_previous: Option<[u8; 32]>,
    /// 16-byte node id included in AAD
    pub node_id16: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct OpaqueTicket(pub Vec<u8>); // ciphertext blob returned to clients

#[derive(Debug, Clone)]
pub struct ParsedTicket {
    pub ticket_id: [u8; 12],   // for replay shard key
    pub issued_ms: u64,        // for expiry windows
    pub session_id: [u8; 3],   // your 3-byte sid
}

/// global TEK set for callers that don't thread `TekSet` explicitly
pub static TICKET_TEK: OnceCell<TekSet> = OnceCell::new();
fn tek() -> &'static TekSet {
    TICKET_TEK.get().expect("tickets: TICKET_TEK not initialized")
}

fn aad(a: &TekSet) -> Vec<u8> {
    let mut v = Vec::with_capacity(AAD_PREFIX.len() + 16 + 1);
    v.extend_from_slice(AAD_PREFIX);
    v.extend_from_slice(&a.node_id16);
    v.push(VERSION);
    v
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Build a plaintext (versioned) then AEAD-encrypt it.
/// Nonce = ticket_id (12 bytes).
pub fn issue_ticket(tek: &TekSet, ticket_id: [u8; 12], session_id: [u8; 3]) -> OpaqueTicket {
    issue_ticket_with_time(tek, ticket_id, session_id, now_ms())
}

/// same as `issue_ticket` but lets callers supply the `issued_ms` (useful for re-sealing)
pub fn issue_ticket_with_time(tek: &TekSet, ticket_id: [u8;12], session_id: [u8;3], issued_ms: u64) -> OpaqueTicket {
    let mut plain = Vec::with_capacity(1 + 12 + 8 + 3 + 1);
    plain.push(VERSION);
    plain.extend_from_slice(&ticket_id);
    plain.extend_from_slice(&issued_ms.to_le_bytes());
    plain.extend_from_slice(&session_id);
    plain.push(0); // reserved

    let key = Key::from_slice(&tek.tek_current);
    let aead = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&ticket_id);
    let ct = aead.encrypt(nonce, chacha20poly1305::aead::Payload {
        msg: &plain,
        aad: &aad(tek),
    }).expect("encrypt ticket");

    // prepend ticket_id so decrypt side can recover nonce; store as: ticket_id || ct
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&ticket_id);
    out.extend_from_slice(&ct);

    // zeroize sensitive buf
    plain.zeroize();
    OpaqueTicket(out)
}

/// Decrypt with current, then previous TEK (if any)
pub fn decrypt_ticket(tek: &TekSet, blob: &[u8]) -> Result<ParsedTicket, DecryptError> {
    if blob.len() < 12 + 1 + 12 + 8 + 3 + 1 {
        return Err(DecryptError::Format);
    }
    let (ticket_id, ct) = blob.split_at(12);
    let mut id = [0u8; 12];
    id.copy_from_slice(ticket_id);

    let try_with = |key_bytes: &[u8;32]| -> Option<Vec<u8>> {
        let aead = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
        let nonce = Nonce::from_slice(&id);
        aead.decrypt(nonce, chacha20poly1305::aead::Payload {
            msg: ct,
            aad: &aad(tek),
        }).ok()
    };

    let plain = if let Some(p) = try_with(&tek.tek_current) {
        p
    } else if let Some(prev) = &tek.tek_previous {
        if let Some(p) = try_with(prev) { p } else { return Err(DecryptError::Auth) }
    } else {
        return Err(DecryptError::Auth)
    };

    if plain.len() < 1 + 12 + 8 + 3 + 1 { return Err(DecryptError::Format) }
    if plain[0] != VERSION { return Err(DecryptError::Version) }

    let mut ticket_id2 = [0u8; 12];
    ticket_id2.copy_from_slice(&plain[1..13]);

    let mut ms_bytes = [0u8; 8];
    ms_bytes.copy_from_slice(&plain[13..21]);
    let issued_ms = u64::from_le_bytes(ms_bytes);

    let mut sid = [0u8; 3];
    sid.copy_from_slice(&plain[21..24]);

    Ok(ParsedTicket {
        ticket_id: ticket_id2,
        issued_ms,
        session_id: sid,
    })
}

#[derive(Debug)]
pub enum DecryptError { Auth, Format, Version }

// ─────────────────────────────────────────────────────────────────────────────
// compatibility API expected by other modules/tests
//   - ResumeTicketPlain
//   - open_ticket(blob) -> Result<ResumeTicketPlain, DecryptError>
//   - seal_ticket(&ResumeTicketPlain) -> Result<Vec<u8>, SealError>
// these use the global TICKET_TEK; make sure it is initialized once at startup.

/// public alias to match older call-sites
pub type ResumeTicketPlain = ParsedTicket;

// UPDATED THIS ENUM
#[derive(Debug, Error)]
pub enum SealError {
    #[error("missing ticket encryption key")]
    MissingKey
}

/// decrypt using the process-global TEK
pub fn open_ticket(blob: &[u8]) -> Result<ResumeTicketPlain, DecryptError> {
    decrypt_ticket(tek(), blob)
}

/// re-seal (encrypt) using the process-global TEK; returns ciphertext bytes
pub fn seal_ticket(plain: &ResumeTicketPlain) -> Result<Vec<u8>, SealError> {
    let t = tek();
    let OpaqueTicket(out) =
        issue_ticket_with_time(t, plain.ticket_id, plain.session_id, plain.issued_ms);
    Ok(out)
}
