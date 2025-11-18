//! eezo-prover CLI — Bridge V1.1 (ML-DSA batch verification)
//!
//! Usage example:
//!   cargo run -p eezo-prover -- prove-checkpoint --height 100 --batch-sigs 16

use alloy_primitives::{B256, FixedBytes, keccak256};
use alloy_sol_types::sol; // <- needed for the `sol!{}` macro
use alloy_sol_types::SolValue;
use anyhow::{Context, Result};
use clap::Parser;
use eezo_ssz_bridge::{log_ssz_versions, assert_compat_or_warn};
use eezo_prover::prover_loop::{run_prover_loop, ProverConfig};
use eezo_prover::metrics::spawn_metrics_server;
use eezo_prover::v1_mldsa::{compute_sig_batch_digest, prove_mldsa_batch, PublicInputsV2};
use eezo_prover::pi_canonical::CanonicalPi;
use blake3::hash as blake3_hash;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

sol! {
    struct HeaderV2 {
        uint32 circuitVersion;
        uint64 height;
        bytes32 txRootV2;
        bytes32 stateRootV2;
        bytes32 sigBatchDigest;
        uint32 batchLen;
        bytes20 chainId20;
        uint32 suiteId; // CHANGED: uint8 -> uint32
    }
}

#[derive(Parser, Debug)]
#[command(name = "eezo-prover", version)]
enum Cmd {
    /// Produce a proof for a finalized checkpoint (one-shot)
    ProveCheckpoint(ProveCheckpoint),

    /// Run the continuous proving loop (T37.5: prover follows LC)
    Auto(Auto),
}

#[derive(Parser, Debug)]
struct ProveCheckpoint {
    /// Block height of the checkpoint
    #[clap(long)]
    height: u64,

    /// Number of signatures to include in batch
    #[clap(long, default_value_t = 16)]
    batch_sigs: u32,

    /// Optional input file with triples [(pk,msg,sig)], JSON-encoded
    #[clap(long)]
    input: Option<PathBuf>,

    /// Optional output file (default: stdout)
    #[clap(long)]
    output: Option<PathBuf>,

    /// EEZO chain-id (20 bytes hex, e.g. 0x...0001). Falls back to EEZO_CHAIN_ID20 if set.
    #[clap(long)]
    chain_id20: Option<String>,

    /// Crypto suite id (1=ml-dsa-44, 2=sphincs+). Defaults to active suite.
    #[clap(long, default_value_t = 1)]
    suite_id: u8,
}

#[derive(Parser, Debug)]
struct Auto {
    /// Base URL of the node (default: http://127.0.0.1:8080)
    #[clap(long)]
    node_url: Option<String>,

    /// Directory for proof output (default: $EEZO_PROOF_DIR or ./proof)
    #[clap(long)]
    proof_dir: Option<PathBuf>,

    /// Checkpoint interval (e.g., 32); used to compute LC.next target
    #[clap(long, default_value_t = 32)]
    checkpoint_every: u64,

    /// Batch size (default: 16)
    #[clap(long, default_value_t = 16)]
    batch_size: u32,

    /// EEZO chain-id (20 bytes hex)
    #[clap(long)]
    chain_id20: Option<String>,
	
    /// Ethereum RPC URL (falls back to $ETH_RPC or http://127.0.0.1:8545)
    #[clap(long)]
    eth_rpc: Option<String>,

    /// Light Client address (falls back to $LC_ADDR)
    #[clap(long)]
    lc_addr: Option<String>,	

    /// Poll interval in milliseconds
    #[clap(long, default_value_t = 500)]
    poll_ms: u64,
}

fn main() -> Result<()> {
    // simple logger so `log::info!` works (RUST_LOG=info)
    let _ = env_logger::try_init();
    // advertise SSZ surface and check version compatibility (bridge ↔ ledger)
    log_ssz_versions("prover");
    assert_compat_or_warn();

    // T43.4: log which hash backend is compiled in (CPU vs GPU).
    log_hash_backend_banner();

    let cmd = Cmd::parse();

    match cmd {
        Cmd::ProveCheckpoint(args) => run_prove_checkpoint(args)?,
        Cmd::Auto(args) => run_auto(args)?,
    }
    Ok(())
}

fn run_prove_checkpoint(args: ProveCheckpoint) -> Result<()> {
    // Load dummy triples or read from file
    let triples: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = if let Some(path) = args.input {
        let data = fs::read(path)?;
        serde_json::from_slice(&data)?
    } else {
        vec![(vec![1u8], vec![2u8], vec![3u8])] // placeholder
    };

    let digest = compute_sig_batch_digest(
        triples.iter().map(|(pk, msg, sig)| (&pk[..], &msg[..], &sig[..])),
    );

    // Non-zero placeholder roots so Light Client "zero root" guard passes.
    let txr_bytes = keccak256(format!("txroot-{}", args.height).as_bytes());
    let str_bytes = keccak256(format!("stroot-{}", args.height).as_bytes());

    // Resolve chainId20 first: CLI flag > env EEZO_CHAIN_ID20 > default 0x...0001
    let chain_hex = args
        .chain_id20
        .or_else(|| std::env::var("EEZO_CHAIN_ID").ok())
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000001".to_string());
    let chain_bytes = parse_hex_20(&chain_hex)
        .with_context(|| format!("invalid --chain-id20 / EEZO_CHAIN_ID20: {}", chain_hex))?;
    let chain_arr: [u8; 20] = chain_bytes
        .as_slice()
        .try_into()
        .expect("parse_hex_20 must return 20 bytes");
    let chain_b20: FixedBytes<20> = FixedBytes::from_slice(&chain_arr);

    // Now build the public inputs with the new fields
    let pis = PublicInputsV2 {
        circuit_version: 2,
        height: args.height,
        tx_root_v2: txr_bytes.0,
        state_root_v2: str_bytes.0,
        sig_batch_digest: digest,
        batch_len: args.batch_sigs,
        chain_id20: chain_arr,
        suite_id: args.suite_id as u32, // <--- THIS IS THE FIX
    };

    // ABI-encode public inputs exactly as the Solidity contract expects
    let header = HeaderV2 {
        circuitVersion: 2,
        height: pis.height,
        txRootV2: B256::from(pis.tx_root_v2),
        stateRootV2: B256::from(pis.state_root_v2),
        sigBatchDigest: B256::from(pis.sig_batch_digest),
        batchLen: pis.batch_len,
        chainId20: chain_b20,
        suiteId: args.suite_id as u32, // CHANGED: cast to u32
    };
    let public_inputs_abi = header.abi_encode();
    // build canonical pi digest (synthetic header_hash as in prover_loop)
    let mut concat = Vec::with_capacity(96);
    concat.extend_from_slice(&pis.tx_root_v2);
    concat.extend_from_slice(&pis.state_root_v2);
    concat.extend_from_slice(&pis.sig_batch_digest);
    let hdr_hash: [u8;32] = *blake3_hash(&concat).as_bytes();
    let canon = CanonicalPi {
        chain_id20: chain_arr,
        suite_id: args.suite_id,
        circuit_version: 2,
        ssz_version: 2,
        header_hash: hdr_hash,
        txs_root_v2: pis.tx_root_v2,
        state_root_v2: pis.state_root_v2,
        sig_batch_digest: pis.sig_batch_digest,
        height: pis.height,
    };
    let pi_digest = canon.digest();	

    let proof = prove_mldsa_batch(
        &pis,
        triples.iter().map(|(pk, msg, sig)| (&pk[..], &msg[..], &sig[..])),
    )?;

    let output = json!({
        "circuit_version": pis.circuit_version,
        "height": pis.height,
        "batch_len": pis.batch_len,
        "sig_batch_digest": hex::encode(pis.sig_batch_digest),
        "proof_len": proof.len(),
        "proof_hex": hex::encode(&proof),
        "public_inputs_abi_len": public_inputs_abi.len(),
        "public_inputs_abi_hex": hex::encode(&public_inputs_abi),
        "chain_id20": chain_hex,
        "suite_id": args.suite_id,
        "pi_digest": format!("0x{}", hex::encode(pi_digest)),
    });

    if let Some(out) = args.output {
        fs::write(out, serde_json::to_vec_pretty(&output)?)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&output)?);
    }
    Ok(())
}

fn run_auto(args: Auto) -> Result<()> {
    // 1) Resolve node URL
    let node_url = args
        .node_url
        .or_else(|| std::env::var("EEZO_NODE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

    // 2) Resolve proof directory
    let proof_root = args
        .proof_dir
        .or_else(|| std::env::var("EEZO_PROOF_DIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("./proof"));

    // 3) Resolve chain ID
    let chain_hex = args
        .chain_id20
        .or_else(|| std::env::var("EEZO_CHAIN_ID20").ok())
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000001".to_string());
    let chain_arr = parse_hex_20(&chain_hex)?;
	
    // 4) Resolve ETH RPC and LC address (required for LC.latestHeight())
    let eth_rpc = args
        .eth_rpc
        .or_else(|| std::env::var("ETH_RPC").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let lc_addr = args
        .lc_addr
        .or_else(|| std::env::var("LC_ADDR").ok())
        .unwrap_or_default();
    if lc_addr.is_empty() {
        anyhow::bail!("LC address is required. Pass --lc-addr or set $LC_ADDR");
    }	

    // 5) Build config
    let cfg = ProverConfig {
        node_url,
        proof_root,
        checkpoint_every: args.checkpoint_every,
        batch_size: args.batch_size,
        chain_id20: chain_arr,
        eth_rpc,
        lc_addr,
        poll_interval_ms: args.poll_ms,
    };

    log::info!("eezo-prover: starting automatic proving loop...");
    log::info!("  node_url     = {}", cfg.node_url);
    log::info!("  proof_root   = {:?}", cfg.proof_root);
    log::info!("  checkpoint_every = {}", cfg.checkpoint_every);
    log::info!("  batch_size   = {}", cfg.batch_size);
    log::info!("  chain_id20   = {}", chain_hex);
    log::info!("  eth_rpc      = {}", cfg.eth_rpc);
    log::info!("  lc_addr      = {}", cfg.lc_addr);	

    // 6) Run async loop (+ start metrics HTTP server on :9099)
    let rt = tokio::runtime::Runtime::new().context("failed to build tokio runtime")?;
    rt.block_on(async {
        if let Err(e) = spawn_metrics_server().await {
            log::warn!("metrics server failed to start: {}", e);
        }		
        run_prover_loop(cfg).await
    })
}

fn log_hash_backend_banner() {
    #[cfg(feature = "gpu-hash")]
    {
        log::info!("eezo-prover: hash backend = gpu (feature gpu-hash=on, currently CPU fallback)");
    }

    #[cfg(not(feature = "gpu-hash"))]
    {
        log::info!("eezo-prover: hash backend = cpu (feature gpu-hash=off)");
    }
}

fn parse_hex_20(s: &str) -> Result<[u8; 20]> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() != 40 {
        anyhow::bail!("expected 20-byte hex (40 nibbles)");
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
            .map_err(|_| anyhow::anyhow!("bad hex at byte {}", i))?;
    }
    Ok(out)
}