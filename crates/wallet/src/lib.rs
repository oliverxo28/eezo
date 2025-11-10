pub mod address;
pub mod keystore;

use anyhow::{Context, Result};
use eezo_crypto::sig::ml_dsa::{sk_from_bytes, MlDsa44};
use eezo_crypto::sig::{PkBytes, SigBytes, SignatureScheme};
use eezo_ledger::tx_types::{SignedTx, TxCore};
use serde_json;
use std::env;
use std::{fs, io::Write, path::Path};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use zeroize::Zeroize;

// =============================================================================
// Node key loader (T36.3): simple file-based ML-DSA-44 keypair management
// Enabled only with `--features pq44-runtime`
// Files:
//   {dir}/mldsa44_pk.bin  (1312 bytes)
//   {dir}/mldsa44_sk.bin  (2560 bytes)
// On first run (if missing), we generate and write them.
// =============================================================================
#[cfg(feature = "pq44-runtime")]
pub mod node_keys {
    use std::{fs, path::Path};
    use std::io::{Error, ErrorKind, Result};
    use pqcrypto_mldsa::mldsa44::{keypair, PublicKey, SecretKey};
    // bring trait methods into scope for as_bytes()/from_bytes()
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

    /// Load ML-DSA-44 keypair from `{dir}/mldsa44_pk.bin` and `{dir}/mldsa44_sk.bin`.
    /// If missing and `create_if_missing` is true, generate and write them.
    pub fn load_or_create_mldsa44(dir: &Path, create_if_missing: bool) -> Result<(PublicKey, SecretKey)> {
        let pk_path = dir.join("mldsa44_pk.bin");
        let sk_path = dir.join("mldsa44_sk.bin");

        let have_both = pk_path.exists() && sk_path.exists();
        if !have_both {
            if !create_if_missing {
                return Err(Error::new(ErrorKind::NotFound, "mldsa44 key files not found"));
            }
            fs::create_dir_all(dir)?;
            let (pk, sk) = keypair();
            fs::write(&pk_path, pk.as_bytes())?;
            fs::write(&sk_path, sk.as_bytes())?;
            return Ok((pk, sk));
        }

        let pkb = fs::read(&pk_path)?;
        let skb = fs::read(&sk_path)?;
        // Defensive length checks (backend constants: pk=1312, sk=2560 for ML-DSA-44)
        if pkb.len() != 1312 || skb.len() != 2560 {
            return Err(Error::new(ErrorKind::InvalidData, "unexpected pk/sk lengths"));
        }

        // from_bytes() validates encoding
        let pk = PublicKey::from_bytes(&pkb).map_err(|_| Error::new(ErrorKind::InvalidData, "bad pk"))?;
        let sk = SecretKey::from_bytes(&skb).map_err(|_| Error::new(ErrorKind::InvalidData, "bad sk"))?;
        Ok((pk, sk))
    }
}

// === CLI helpers ===
/// Back-compat wrapper: create a new keystore using built-in KDF defaults.
pub fn cmd_new(out_path: Option<&str>, password: Option<&str>, prompt: bool) -> Result<()> {
    cmd_new_ex(out_path, password, prompt, None, None, None, None)
}

/// Create a new keystore with optional password file and tunable Argon2id params.
/// - `password_file`: read password from file if provided (overridden by `password` arg).
/// - `kdf_time`: Argon2 iterations (default 3)
/// - `kdf_mem_mib`: Argon2 memory in MiB (default 256)
/// - `kdf_lanes`: Argon2 lanes/parallelism (default 1)
pub fn cmd_new_ex(
    out_path: Option<&str>,
    password: Option<&str>,
    prompt: bool,
    password_file: Option<&str>,
    kdf_time: Option<u32>,
    kdf_mem_mib: Option<u32>,
    kdf_lanes: Option<u32>,
) -> Result<()> {
    // 0) Decide password source (explicit > file > prompt)
    let mut pw = match (password, password_file, prompt) {
        (Some(p), _, _) => p.to_owned(),
        (None, Some(path), _) => {
            let s = fs::read_to_string(path)
                .with_context(|| format!("reading password-file {}", path))?;
            // strip trailing newlines so `printf 'pw\n'` works
            s.trim_end_matches(&['\r', '\n'][..]).to_owned()
        }
        (None, None, true) => {
            let p1 = rpassword::prompt_password("Enter new wallet password: ")?;
            let p2 = rpassword::prompt_password("Confirm password: ")?;
            if p1 != p2 {
                anyhow::bail!("passwords do not match");
            }
            p1
        }
        (None, None, false) => {
            anyhow::bail!("no password provided; pass --password, --password-file, or --prompt")
        }
    };

    // 1) Generate ML-DSA-44 keypair (enabled by --features pq44-runtime)
    let (pk, sk) = eezo_crypto::sig::ml_dsa::MlDsa44::keypair();
    let pkb = eezo_crypto::sig::ml_dsa::MlDsa44::pk_as_bytes(&pk);
    let skb = eezo_crypto::sig::ml_dsa::MlDsa44::sk_as_bytes(&sk);

    // 2) Encrypt into a keystore with algo id 0x0144 (ML-DSA-44), allowing KDF overrides.
    let t = kdf_time.unwrap_or(3);
    let m = kdf_mem_mib.unwrap_or(256).saturating_mul(1024); // MiB -> KiB
    let pp = kdf_lanes.unwrap_or(1);
    // Guardrails (mirror keystore::validate ranges)
    if !(1..=6).contains(&t) {
        anyhow::bail!("kdf_time out of bounds (1..=6)");
    }
    if !(64..=1024).contains(&kdf_mem_mib.unwrap_or(256)) {
        anyhow::bail!("kdf_mem_mib out of bounds (64..=1024)");
    }
    if !(1..=8).contains(&pp) {
        anyhow::bail!("kdf_lanes out of bounds (1..=8)");
    }
    // New signature: (password, algo_id, secret, pubkey: Option<&[u8]>, t, m_kib, lanes)
    let ks = keystore::encrypt_secret_with_params(&pw, 0x0144, skb, Some(pkb), t, m, pp);
    // Zeroize password ASAP after use
    pw.zeroize();

    // 3) Write keystore (0600, atomic)
    let out = out_path
        .map(Path::new)
        .unwrap_or_else(|| Path::new("keystore.json"));
    write_keystore_atomic(out, &ks)?;
    
    // 4) Derive and display wallet address for convenience
	if let Some(pk) = ks.pubkey() {
		let addr = crate::address::pubkey_to_address(pk);
		println!("✅ Created keystore: {}", out.display());
		println!("🔑 Address: {}", addr);
		println!("📄 Saved at: {}", std::fs::canonicalize(out)?.display());
	}else {
		println!("✅ Created keystore: {} (no public key found)", out.display());
	}
	Ok(())
}

pub fn cmd_balance(addr: &str) -> Result<()> {
    use reqwest::blocking::Client;
    use std::env;

    // 1) Determine node URL (default http://127.0.0.1:8080)
    let node = env::var("EEZO_NODE").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    // 2) Build full URL: /account/{addr}
    let url = format!("{node}/account/{addr}");

    // 3) Perform GET request
    let resp = Client::new()
        .get(&url)
        .send()
        .with_context(|| format!("querying node {url}"))?;

    // 4) Parse JSON
    let body = resp.text().context("reading node response")?;
    if body.contains("error") {
        println!("Node error: {body}");
    } else {
        println!("Account info for {addr}:\n{body}");
    }
    Ok(())
}

pub fn cmd_send(from: &str, to: &str, amount: u128, fee: u64, nonce: Option<u64>) -> Result<()> {
    // Node base URL (default local)
    let node = env::var("EEZO_NODE").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let base = node.trim_end_matches('/');

    // Chain ID: read from EEZO_CHAIN_ID (required by node)
    let chain_id = env::var("EEZO_CHAIN_ID")
        .map(|s| format!("0x{}", s.trim_start_matches("0x")))
        .context("EEZO_CHAIN_ID not set (expected 20-byte hex like 0000..0001)")?;

    // If nonce not provided, fetch from node
    let nonce_str = if let Some(n) = nonce {
        n.to_string()
    } else {
        // GET /account/{from} → { balance, nonce }
        let url = format!("{}/account/{}", base, from);
        let resp: serde_json::Value = ureq::get(&url)
            .call()
            .map_err(|e| anyhow::anyhow!("GET {} failed: {}", url, e))?
            .into_json()
            .map_err(|e| anyhow::anyhow!("parsing {} JSON failed: {}", url, e))?;
        resp.get("nonce")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("account query returned no nonce"))?
            .to_string()
    };

    // Build SignedTxEnvelope compatible with the node
    let env_json = serde_json::json!({
        "tx": {
            "from": from,
            "to": to,
            "amount": amount.to_string(),
            "fee": fee.to_string(),
            "nonce": nonce_str,
            "chain_id": chain_id
        },
        // dev node ignores sig; real signing comes later
        "sig": "deadbeef"
    });

    // POST /tx
    let url = format!("{}/tx", base);
    let resp: serde_json::Value = ureq::post(&url)
        .send_json(env_json)
        .map_err(|e| anyhow::anyhow!("POST {} failed: {}", url, e))?
        .into_json()
        .map_err(|e| anyhow::anyhow!("parsing {} JSON failed: {}", url, e))?;

    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

// === Sign helper ===
pub fn sign_tx(core: &TxCore, pubkey: Vec<u8>, sig: Vec<u8>) -> SignedTx {
    SignedTx {
        core: core.clone(),
        pubkey,
        sig,
    }
}

/// Write keystore JSON atomically with `0600` perms.
pub fn write_keystore_atomic(path: &Path, ks: &keystore::Keystore) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(ks)?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no parent dir"))?;
    fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");

    // Create/truncate temp file
    let mut f = fs::File::create(&tmp)?;
    #[cfg(unix)]
    {
        let mut perm = f.metadata()?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&tmp, perm)?;
    }
    f.write_all(&json)?;
    f.sync_all()?; // flush temp

    // Atomic rename over target
    fs::rename(&tmp, path)?;
    // fsync directory to persist the rename on crashy filesystems
    #[cfg(unix)]
    {
        if let Ok(dirf) = fs::File::open(dir) {
            let _ = dirf.sync_all();
        }
    }
    Ok(())
}

/// Sign an arbitrary message using the ML-DSA-44 key stored in a keystore.
/// Prints the signature as hex to stdout.
pub fn cmd_sign(keystore_path: &str, password: &str, msg: &str) -> anyhow::Result<()> {
    // 1) Read keystore.json
    let data = fs::read(keystore_path)
        .with_context(|| format!("reading keystore {}", keystore_path))?;
    let ks: crate::keystore::Keystore =
        serde_json::from_slice(&data).context("parsing keystore json")?;

    // 2) Decrypt secret key bytes
    let plain = crate::keystore::decrypt_secret(password, &ks)
        .context("decrypting secret from keystore")?;

    // 3) Reconstruct ML-DSA-44 secret key (requires --features pq44-runtime)
    let sk = sk_from_bytes(&plain.0)
        .ok_or_else(|| anyhow::anyhow!("invalid ML-DSA-44 key bytes"))?;

    // 4) Sign and print hex (scripts can capture this)
    let sig = MlDsa44::sign(&sk, msg.as_bytes());
    // Ensure decrypted bytes are dropped now (PlainSecret zeroizes on Drop)
    drop(plain);
    println!("{}", hex::encode(sig.0));
    Ok(())
}

/// Print the bech32 (or project-standard) address derived from the keystore's public key.
pub fn cmd_address(keystore_path: &str) -> anyhow::Result<()> {
    // 1) Read keystore.json
    let data = fs::read(keystore_path)
        .with_context(|| format!("reading keystore {}", keystore_path))?;
    let ks: crate::keystore::Keystore =
        serde_json::from_slice(&data).context("parsing keystore json")?;

    // 2) Get pubkey (stored in clear in keystore)
    let pk = ks
        .pubkey()
        .ok_or_else(|| anyhow::anyhow!("keystore has no public key stored"))?;

    // 3) Derive address using the new helper from the address module
    let addr = crate::address::pubkey_to_address(pk);
    println!("{addr}");
    Ok(())
}

/// Print the public key (hex) from a keystore.
pub fn cmd_pubkey(keystore_path: &str) -> anyhow::Result<()> {
    let data = fs::read(keystore_path)
        .with_context(|| format!("reading keystore {}", keystore_path))?;
    let ks: crate::keystore::Keystore =
        serde_json::from_slice(&data).context("parsing keystore json")?;
    let pk = ks
        .pubkey()
        .ok_or_else(|| anyhow::anyhow!("keystore has no public key stored"))?;
    let hex_pk = hex::encode(pk);
    let addr = crate::address::pubkey_to_address(pk);
    println!("Public Key: {hex_pk}");
    println!("Address: {addr}");
    Ok(())
}

/// Verify a hex signature against the keystore's public key and message.
pub fn cmd_verify(keystore_path: &str, msg: &str, sig_hex: &str) -> anyhow::Result<()> {
    let data = fs::read(keystore_path)
        .with_context(|| format!("reading keystore {}", keystore_path))?;
    let ks: crate::keystore::Keystore =
        serde_json::from_slice(&data).context("parsing keystore json")?;
    let pk = ks
        .pubkey()
        .ok_or_else(|| anyhow::anyhow!("keystore has no public key stored"))?;
    let sig = hex::decode(sig_hex).context("parsing sig hex")?;
    let ok = MlDsa44::verify(&PkBytes(pk.to_vec()), msg.as_bytes(), &SigBytes(sig));
    println!("{}", if ok { "OK" } else { "FAIL" });
    Ok(())
}