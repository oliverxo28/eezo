#![allow(deprecated)]
// crates/net/src/secure.rs
use crate::handshake::{
    client_handshake,    // T2
	// client_handshake_resume is no longer needed directly, client_connect_resume_async handles setup
    client_handshake_t3, // T3 with client auth
    server_handshake,    // T2
    server_handshake_t3, // T3
    ClientHello, ClientPending, // Import ClientPending
    Kem,
    MlDsaLike, // used by auth helpers
    ServerHello,
	HandshakeError, // Import HandshakeError
};
use crate::session::{Session, SessionError};
// PATCH: Add imports
use crate::session::Role; // for resumed-session construction
use crate::handshake::{AAD_CONFIRM, CONFIRM_PLAINTEXT}; // for confirm check
use thiserror::Error;
#[cfg(feature = "metrics")]
use std::time::Instant;
#[cfg(feature = "metrics")]
use crate::metrics::{EEZO_KEMTLS_HANDSHAKE_SECONDS, kemtls_session_mark};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
// PATCH: Add imports
use sha3::{Digest, Sha3_256};
use rand::{thread_rng, RngCore};

pub const AAD_DATA: &[u8] = b"EEZO:data"; 

#[derive(Debug, Error)]
pub enum SecureError {
    #[error("io")]
    Io(#[from] std::io::Error),
    #[error("session")]
    Session(#[from] SessionError),
    #[error("handshake")]
    Handshake(#[from] crate::handshake::HandshakeError),
    #[error("protocol: truncated frame")]
    Truncated,
    #[error("bincode")]
    Bincode(#[from] Box<bincode::ErrorKind>),
}

pub struct FramedSession {
    sess: Session,
    /// if the server issued a fresh resumption ticket during handshake, cache it here
    new_ticket: Option<Vec<u8>>,
}

impl FramedSession {
    pub fn new(sess: Session) -> Self {
        Self { sess, new_ticket: None }
    }
	pub fn new_with_ticket(sess: Session, t: Option<Vec<u8>>) -> Self {
        Self { sess, new_ticket: t }
    }

    // ---------- SYNC ----------
    pub fn write_frame<W: std::io::Write>(
        &mut self,
        mut w: W,
        plaintext: &[u8],
    ) -> Result<(), SecureError> {
        let ct = self.sess.seal(AAD_DATA, plaintext)?;
        let mut hdr = [0u8; 4];
        hdr.copy_from_slice(&(ct.len() as u32).to_be_bytes());
        w.write_all(&hdr)?;
        w.write_all(&ct)?;
        Ok(())
    }

    pub fn read_frame<R: std::io::Read>(&mut self, mut r: R) -> Result<Vec<u8>, SecureError> {
        let mut hdr = [0u8; 4];
        r.read_exact(&mut hdr)?;
        let len = u32::from_be_bytes(hdr) as usize;
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct)?;
        Ok(self.sess.open(AAD_DATA, &ct)?)
    }

    // ---------- ASYNC ----------
    pub async fn write_frame_async<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        plaintext: &[u8],
    ) -> Result<(), SecureError> {
        let ct = self.sess.seal(AAD_DATA, plaintext)?;
        let hdr = (ct.len() as u32).to_be_bytes();
        w.write_all(&hdr).await?;
        w.write_all(&ct).await?;
        Ok(())
    }

    pub async fn read_frame_async<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> Result<Vec<u8>, SecureError> {
        let mut hdr = [0u8; 4];
        r.read_exact(&mut hdr).await?;
        let len = u32::from_be_bytes(hdr) as usize;
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct).await?;
        Ok(self.sess.open(AAD_DATA, &ct)?)
    }

    pub fn into_inner(self) -> Session {
        self.sess
    }
    /// Peek at the most recently issued ticket (if any).
    pub fn new_ticket(&self) -> Option<&[u8]> {
        self.new_ticket.as_deref()
    }

    /// Take ownership of the most recently issued ticket (if any).
    pub fn take_new_ticket(&mut self) -> Option<Vec<u8>> {
        self.new_ticket.take()
    }
}

// Helper: send ClientHello
async fn send_client_hello<IO: AsyncWrite + Unpin>(
    io: &mut IO,
    chello: &ClientHello,
) -> Result<(), SecureError> {
    let ser = bincode::serialize(chello)?;
    io.write_all(&(ser.len() as u32).to_be_bytes()).await?;
    io.write_all(&ser).await?;
    Ok(())
}

// Helper: receive ServerHello
async fn recv_server_hello<IO: AsyncRead + Unpin>(io: &mut IO) -> Result<ServerHello, SecureError> {
    let mut hdr = [0u8; 4];
    io.read_exact(&mut hdr).await?;
    let l = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; l];
    io.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}


// ---------- SYNC handshake helpers (for completeness) ----------
pub fn client_connect<K: Kem, W: std::io::Write, R: std::io::Read>(
    server_pk: &K::PublicKey,
    mut out: W,
    mut inp: R,
) -> Result<FramedSession, SecureError> {
    let (chello, pending) = client_handshake::<K>(server_pk)?;
    let ser = bincode::serialize(&chello)?;
    out.write_all(&(ser.len() as u32).to_be_bytes())?;
    out.write_all(&ser)?;

    let mut hdr = [0u8; 4];
    inp.read_exact(&mut hdr)?;
    let l = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; l];
    inp.read_exact(&mut buf)?;
    let shello: ServerHello = bincode::deserialize(&buf)?;
    let ticket = shello.ticket_new.clone();
    Ok(FramedSession::new_with_ticket(pending.finish_t2(shello)?, ticket))
}

pub fn server_accept<K: Kem, R: std::io::Read, W: std::io::Write>(
    server_sk: &K::SecretKey,
    mut inp: R,
    mut out: W,
) -> Result<FramedSession, SecureError> {
    let mut hdr = [0u8; 4];
    inp.read_exact(&mut hdr)?;
    let l = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; l];
    inp.read_exact(&mut buf)?;
    let chello: ClientHello = bincode::deserialize(&buf)?;

    let (shello, sess) = server_handshake::<K>(server_sk, chello)?;
    let ser = bincode::serialize(&shello)?;
    out.write_all(&(ser.len() as u32).to_be_bytes())?;
    out.write_all(&ser)?;
    Ok(FramedSession::new(sess))
}

// ---------- ASYNC handshake helpers ----------
pub async fn client_connect_async<K: Kem, S: AsyncRead + AsyncWrite + Unpin>(
    server_pk: &K::PublicKey,
    stream: &mut S,
) -> Result<FramedSession, SecureError> {
	#[cfg(feature = "metrics")]
	let t0 = Instant::now();
    let (chello, pending) = client_handshake::<K>(server_pk)?;
	send_client_hello(stream, &chello).await?;
	let shello: ServerHello = recv_server_hello(stream).await?;
    let ticket = shello.ticket_new.clone();
    let sess = pending.finish_t2(shello)?;
	#[cfg(feature = "metrics")]
	{
		EEZO_KEMTLS_HANDSHAKE_SECONDS.observe(t0.elapsed().as_secs_f64());
		kemtls_session_mark("client", sess.resumed);
	}
	Ok(FramedSession::new_with_ticket(sess, ticket))
}

pub async fn server_accept_async<K: Kem, S: AsyncRead + AsyncWrite + Unpin>(
    server_sk: &K::SecretKey,
    stream: &mut S,
) -> Result<FramedSession, SecureError> {
    #[cfg(feature = "metrics")]
    let t0 = Instant::now();
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    let l = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; l];
    stream.read_exact(&mut buf).await?;
    let chello: ClientHello = bincode::deserialize(&buf)?;

    let (shello, sess) = server_handshake::<K>(server_sk, chello)?;
    let ser = bincode::serialize(&shello)?;
    stream.write_all(&(ser.len() as u32).to_be_bytes()).await?;
    stream.write_all(&ser).await?;
    #[cfg(feature = "metrics")]
    {
        EEZO_KEMTLS_HANDSHAKE_SECONDS.observe(t0.elapsed().as_secs_f64());
        kemtls_session_mark("server", sess.resumed);
    }
    Ok(FramedSession::new(sess))
}
/// ---------- SYNC resume helpers (T37.1) ----------
// PATCH: Replace entire function body
pub fn client_connect_resume<K: Kem, W: std::io::Write, R: std::io::Read>(
    server_pk: &K::PublicKey,
    resume_ticket: Vec<u8>,
    mut out: W,
    mut inp: R,
) -> Result<FramedSession, SecureError> {
    // 1) Always include a fallback KEM ciphertext; keep the shared secret
    let (ct_wire, kem_ss_bytes) = K::encap(server_pk)?;

    // 2) Derive PSK from the raw ticket bytes
    let mut h = Sha3_256::new();
    h.update(b"EEZO:RESUME-PSK|V1|");
    h.update(&resume_ticket);
    let psk = h.finalize(); // 32 bytes

    // 3) Random client salt
    let mut salt_c = [0u8; 16];
    thread_rng().fill_bytes(&mut salt_c);

    // 4) Build + send ClientHello carrying BOTH the KEM fallback and the opaque ticket
    let chello = ClientHello {
        ct: ct_wire.clone(),
        salt_c,
        session_id_hint: [0; 3],
        client_auth_pk: None,
        client_sig: None,
        client_cert: None,
        resume_ticket: Some(resume_ticket.clone()),
    };
    // Keep a local pending state (for fallback finish_t2)
    let pending_state = ClientPending {
        shared_secret: kem_ss_bytes.clone(),
        salt_c: chello.salt_c,
        session_id_hint: chello.session_id_hint,
        chello_sent: chello.clone(),
    };

    let ser = bincode::serialize(&chello)?;
    out.write_all(&(ser.len() as u32).to_be_bytes())?;
    out.write_all(&ser)?;

    // 5) Receive ServerHello
    let mut hdr = [0u8; 4];
    inp.read_exact(&mut hdr)?;
    let l = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; l];
    inp.read_exact(&mut buf)?;
    let shello: ServerHello = bincode::deserialize(&buf)?;

    let new_ticket = shello.ticket_new.clone();

    // 6) Decide: RESUME (ticket accepted) vs FALLBACK (ticket rejected)
    let final_session = if shello.ticket_new.is_some() {
        // Resumption: derive keys from PSK, verify confirm
        let tk = crate::keyschedule::derive_keys(psk.as_slice(), &chello.salt_c, &shello.salt_s);
        let mut sess = Session::new(Role::Client, tk);
        sess.resumed = true;
        let opened = sess.open(AAD_CONFIRM, &shello.confirm)?;
        if opened != CONFIRM_PLAINTEXT {
            return Err(SecureError::Handshake(HandshakeError::ConfirmFailed));
        }
        sess
    } else {
        // Fallback: finish T2 with the KEM shared secret path
        pending_state.finish_t2(shello)?
    };

    Ok(FramedSession::new_with_ticket(final_session, new_ticket))
}


/// ---------- ASYNC resume helpers (T37.1) ----------
pub async fn client_connect_resume_async<K, IO>(
    pk: &K::PublicKey,
    ticket_raw: Vec<u8>,
    io: &mut IO,
) -> Result<FramedSession, SecureError>
where
    K: Kem,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    use sha3::{Digest, Sha3_256};
    use rand::{thread_rng, RngCore};
    use crate::session::Role; // Import Role

    #[cfg(feature = "metrics")]
    let t0 = Instant::now();

    // 1) ALWAYS include a fallback KEM ciphertext in ClientHello
    //    SAVE the shared secret for potential fallback.
    let (ct_wire, kem_ss_bytes) = K::encap(pk)?;

    // 2) derive PSK from the **exact raw bytes we are about to send**
    let mut h = Sha3_256::new();
    h.update(b"EEZO:RESUME-PSK|V1|");
    h.update(&ticket_raw);
    let psk = h.finalize(); // 32 bytes

    // 3) fill client salt
    let mut salt_c = [0u8; 16];
    thread_rng().fill_bytes(&mut salt_c);

    // 4) build and send ClientHello with BOTH fields set
    let chello = ClientHello {
        ct: ct_wire.clone(), // KEM ciphertext (fallback)
        salt_c,
        session_id_hint: [0; 3], // Hint isn't critical for resume path
        client_auth_pk: None, // Assuming no client auth during resume for now
        client_sig: None,
        client_cert: None,
        resume_ticket: Some(ticket_raw.clone()), // The actual ticket
    };
    // Also create a ClientPending struct locally for fallback transcript hash later if needed
    let pending_state = ClientPending {
        shared_secret: kem_ss_bytes.clone(), // Store KEM SS here
        salt_c: chello.salt_c,
        session_id_hint: chello.session_id_hint,
        chello_sent: chello.clone(),
    };
    send_client_hello(io, &chello).await?;

    // 5) receive ServerHello
    let sh: ServerHello = recv_server_hello(io).await?;

    // --- DECIDE PATH: RESUME (ticket_new=Some) or FALLBACK (ticket_new=None) ---
    let final_session: Session;
    let new_ticket: Option<Vec<u8>> = sh.ticket_new.clone(); // Store ticket before consuming sh

    if sh.ticket_new.is_some() {
        // ---> RESUMPTION PATH <---
        // Derive keys using the PSK
        let tk = crate::keyschedule::derive_keys(psk.as_slice(), &chello.salt_c, &sh.salt_s);
        let mut sess = Session::new(Role::Client, tk); // Ensure Role::Client
        sess.resumed = true; // Mark session as resumed

        // Verify server's confirm message (using PSK-derived keys)
        let opened = sess.open(crate::handshake::AAD_CONFIRM, &sh.confirm)?;
        if opened != crate::handshake::CONFIRM_PLAINTEXT {
            return Err(SecureError::Handshake(HandshakeError::ConfirmFailed));
        }
        final_session = sess;

    } else {
        // ---> FALLBACK PATH <---
        // Server rejected ticket, derive keys using KEM shared secret
        // Use the `finish_t2` logic from the ClientPending state we created
        // Note: finish_t2 internally derives keys from pending_state.shared_secret
        let sess = pending_state.finish_t2(sh)?; // Verifies confirm AEAD using KEM keys
        // Session::new() inside finish_t2 already sets resumed = false
        // REMOVED faulty sanity check that caused E0599
        final_session = sess; // final_session.resumed is correctly false
    }

    // --- Common Post-Handshake ---
    #[cfg(feature = "metrics")]
    {
        EEZO_KEMTLS_HANDSHAKE_SECONDS.observe(t0.elapsed().as_secs_f64());
        kemtls_session_mark("client", final_session.resumed); // Mark based on actual outcome
    }

    Ok(FramedSession::new_with_ticket(final_session, new_ticket))
}


/// Client side: perform T2 handshake + T3 server auth, then return a ready session.
pub async fn client_connect_auth_async<K: Kem, S: MlDsaLike, IO: AsyncRead + AsyncWrite + Unpin>(
    server_kem_pk: &K::PublicKey,
    expected_server_auth_pk: &S::PublicKey,
    stream: &mut IO,
) -> Result<FramedSession, SecureError> {
    #[cfg(feature = "metrics")]
    let t0 = Instant::now();
    let (chello, pending) = client_handshake::<K>(server_kem_pk)?;
	send_client_hello(stream, &chello).await?;
    let shello: ServerHello = recv_server_hello(stream).await?;
    let ticket = shello.ticket_new.clone();
    // Finish T3 (verifies server signature); returns Session only if OK
    let sess = pending.finish_t3_verify::<S>(shello, expected_server_auth_pk)?;
    #[cfg(feature = "metrics")]
    {
        EEZO_KEMTLS_HANDSHAKE_SECONDS.observe(t0.elapsed().as_secs_f64());
        kemtls_session_mark("client", sess.resumed);
    }
    Ok(FramedSession::new_with_ticket(sess, ticket))
}

/// Client side: perform T3 mutual-auth (client ID in ClientHello) + server auth.
pub async fn client_connect_auth_with_client_id_async<K, S, IO>(
    server_kem_pk: &K::PublicKey,
    expected_server_auth_pk: &S::PublicKey,
    client_auth_pk: &S::PublicKey,
    client_auth_sk: &S::SecretKey,
    stream: &mut IO,
) -> Result<FramedSession, SecureError>
where
    K: Kem,
    S: MlDsaLike,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    #[cfg(feature = "metrics")]
    let t0 = Instant::now();
    let (chello, pending) =
        client_handshake_t3::<K, S>(server_kem_pk, client_auth_pk, client_auth_sk)?;
	send_client_hello(stream, &chello).await?;
    let shello: ServerHello = recv_server_hello(stream).await?;
    let ticket = shello.ticket_new.clone(); // T37.1: grab new ticket
    let sess = pending.finish_t3_verify::<S>(shello, expected_server_auth_pk)?;
    #[cfg(feature = "metrics")]
    {
        EEZO_KEMTLS_HANDSHAKE_SECONDS.observe(t0.elapsed().as_secs_f64());
        kemtls_session_mark("client", sess.resumed);
    }
    Ok(FramedSession::new_with_ticket(sess, ticket)) // T37.1: pass ticket up
}

/// Server side: process ClientHello, sign transcript with ML-DSA, return session when done.
pub async fn server_accept_auth_async<K: Kem, S: MlDsaLike, IO: AsyncRead + AsyncWrite + Unpin>(
    server_kem_sk: &K::SecretKey,
    server_auth_pk: &S::PublicKey,
    server_auth_sk: &S::SecretKey,
    stream: &mut IO,
) -> Result<FramedSession, SecureError> {
	#[cfg(feature = "metrics")]
    let t0 = Instant::now();
    // recv ClientHello
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    let l = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; l];
    stream.read_exact(&mut buf).await?;
    let chello: ClientHello = bincode::deserialize(&buf)?;

    // Build ServerHello + sign
    let (shello, sess) =
        server_handshake_t3::<K, S>(server_kem_sk, chello, server_auth_pk, server_auth_sk)?;
    let ser = bincode::serialize(&shello)?;
    stream.write_all(&(ser.len() as u32).to_be_bytes()).await?;
    stream.write_all(&ser).await?;
	#[cfg(feature = "metrics")]
	{
		EEZO_KEMTLS_HANDSHAKE_SECONDS.observe(t0.elapsed().as_secs_f64());
		kemtls_session_mark("server", sess.resumed);
	}
    Ok(FramedSession::new(sess))
}



