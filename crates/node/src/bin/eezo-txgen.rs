use anyhow::{anyhow, Context, Result};
use eezo_ledger::address::Address;
use eezo_ledger::tx::sign_tx_core_mldsa;
use eezo_ledger::tx_types::TxCore;
use serde::Serialize;
use std::env;

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)
}

fn parse_hex20(name: &str, s: &str) -> Result<[u8; 20]> {
    let raw = hex::decode(strip_0x(s))
        .with_context(|| format!("invalid hex for {}", name))?;
    if raw.len() != 20 {
        return Err(anyhow!(
            "{} must be 20 bytes, got {}",
            name,
            raw.len()
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[derive(Serialize)]
struct TransferTxJson {
    from: String,
    to: String,
    amount: String,
    nonce: String,
    fee: String,
    chain_id: String,
}

#[derive(Serialize)]
struct SignedTxEnvelopeJson {
    tx: TransferTxJson,
    pubkey: String,
    sig: String,
}

fn main() -> Result<()> {
    // 1) CLI: nonce
    let nonce_arg = env::args()
        .nth(1)
        .context("usage: eezo-txgen <nonce>")?;
    let nonce: u64 = nonce_arg.parse().context("invalid nonce")?;

    // 2) Env config (all required for now)
    let from = env::var("EEZO_TX_FROM")
        .context("EEZO_TX_FROM not set (expected 0x-address)")?;
    let to = env::var("EEZO_TX_TO")
        .context("EEZO_TX_TO not set (expected 0x-address)")?;
    let chain_id_hex = env::var("EEZO_TX_CHAIN_ID")
        .context("EEZO_TX_CHAIN_ID not set (expected 0x + 40 hex)")?;
    let amount_str = env::var("EEZO_TX_AMOUNT")
        .context("EEZO_TX_AMOUNT not set")?;
    let fee_str = env::var("EEZO_TX_FEE")
        .context("EEZO_TX_FEE not set")?;
    let pk_hex = env::var("EEZO_TX_PK_HEX")
        .context("EEZO_TX_PK_HEX not set (ML-DSA pk hex)")?;
    let sk_hex = env::var("EEZO_TX_SK_HEX")
        .context("EEZO_TX_SK_HEX not set (ML-DSA sk hex)")?;

    // 3) Parse numeric fields
    let amount: u128 = amount_str
        .parse()
        .context("EEZO_TX_AMOUNT must be u128")?;
    let fee: u128 = fee_str
        .parse()
        .context("EEZO_TX_FEE must be u128")?;

    // 4) Parse chain_id + to address to 20-byte arrays
    let chain_id20 = parse_hex20("EEZO_TX_CHAIN_ID", &chain_id_hex)?;
    let to_bytes20 = parse_hex20("EEZO_TX_TO", &to)?;
    let to_addr = Address(to_bytes20);

    // 5) Build TxCore
    let core = TxCore {
        to: to_addr,
        amount,
        fee,
        nonce,
    };

    // 6) Decode secret key and sign
    let sk_bytes = hex::decode(strip_0x(&sk_hex))
        .context("failed to decode EEZO_TX_SK_HEX")?;
    let sig = sign_tx_core_mldsa(chain_id20, &core, &sk_bytes)
        .context("sign_tx_core_mldsa failed")?;

    // 7) Hex-encode signature (0x + hex) for HTTP
    let sig_hex = format!("0x{}", hex::encode(&sig.0[..]));

    // 8) Normalise hex strings for JSON (ensure 0x prefix)
    fn ensure_0x(s: &str) -> String {
        if s.starts_with("0x") || s.starts_with("0X") {
            s.to_string()
        } else {
            format!("0x{}", s)
        }
    }

    let from_out = ensure_0x(&from);
    let to_out = ensure_0x(&to);
    let chain_id_out = ensure_0x(&chain_id_hex);
    let pk_out = ensure_0x(&pk_hex);

    let tx_json = TransferTxJson {
        from: from_out,
        to: to_out,
        amount: amount_str,
        nonce: nonce.to_string(),
        fee: fee_str,
        chain_id: chain_id_out,
    };

    let env_json = SignedTxEnvelopeJson {
        tx: tx_json,
        pubkey: pk_out,
        sig: sig_hex,
    };

    let out = serde_json::to_string(&env_json)
        .context("failed to serialize SignedTxEnvelopeJson")?;
    println!("{}", out);

    Ok(())
}

