use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use zeroize::Zeroize;
use pqcrypto_mldsa::mldsa44 as pq44;
use pqcrypto_traits::sign::{PublicKey as PkTrait, SecretKey as SkTrait};

use eezo_crypto::sig::SignatureScheme;
use eezo_ledger::cert_store::{CertLookup, ValidatedPk};
use eezo_ledger::config::BatchVerifyCfg;
use eezo_ledger::consensus::{
    signer_id_from_pk, ConsensusMsgCore, PreVote, SignedConsensusMsg, PkBytes as LedPk,
};
use eezo_ledger::consensus_sig::sign_core;
use eezo_ledger::consensus::validate_consensus_batch;
use eezo_ledger::VerifyCache;

type PqPk = pq44::PublicKey;

/// Secure wrapper around raw secret-key bytes so we can actually zeroize.
struct PqSkWrap([u8; 2560]); // SK_LEN for ML-DSA-44

impl Zeroize for PqSkWrap {
    fn zeroize(&mut self) {
        // Overwrite the buffer in-place.
        self.0.as_mut_slice().zeroize();
    }
}

struct Pq44;

impl eezo_crypto::sig::SignatureScheme for Pq44 {
    type PublicKey = PqPk;
    type SecretKey = PqSkWrap;
    type Signature = pq44::DetachedSignature;

    const ALGO_ID: eezo_crypto::sig::AlgoId = eezo_crypto::sig::AlgoId::MlDsa2;
    const PK_LEN: usize = 1312;
    const SK_LEN: usize = 2560;
    const SIG_MAX_LEN: usize = 2420;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (pk, sk) = pq44::keypair();
        // Copy the opaque SK into our zeroizable buffer
        let mut wrap = PqSkWrap([0u8; Self::SK_LEN]);
        wrap.0.copy_from_slice(sk.as_bytes());
        (pk, wrap)
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        // Reconstruct an ephemeral SecretKey from bytes just for this call.
        // This keeps the inner buffer zeroizable while still using pqcrypto's API.
        let ephem = <pq44::SecretKey as SkTrait>::from_bytes(&sk.0)
            .expect("valid mldsa44 secret key bytes");
        pq44::detached_sign(msg, &ephem)
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        pq44::verify_detached_signature(sig, msg, pk).is_ok()
    }

    fn pk_as_bytes(pk: &Self::PublicKey) -> &[u8] {
        pk.as_bytes()
    }

    fn sk_as_bytes(sk: &Self::SecretKey) -> &[u8] {
        &sk.0
    }
}

/// Dummy cert-store that always returns the provided pk as valid forever.
struct DummyCerts {
    pk: PqPk,
}

// Add these implementations for thread safety
unsafe impl Sync for DummyCerts {}
unsafe impl Send for DummyCerts {}

impl DummyCerts {
    fn new_valid_for_pk(pk: &PqPk) -> Self {
        DummyCerts { pk: pk.clone() }
    }
}

impl CertLookup for DummyCerts {
    fn get_pk(&self, _validator_id: &eezo_ledger::consensus::SignerId, _at_height: u64) -> Option<ValidatedPk> {
        Some(ValidatedPk {
            pk: self.pk.clone(),
            valid_until: u64::MAX,
            revoked: false,
        })
    }
}

/// Build N signed PreVote messages using Pq44 keys.
fn make_msgs(
    n: usize,
    sk: &PqSkWrap,
    pk: &PqPk,
    chain_id: &[u8],
    valid_ratio: f32,
) -> Vec<SignedConsensusMsg> {
    let mut rng = StdRng::seed_from_u64(42);
    let signer_pk_led = LedPk::from_pq(pk);
    let _signer_id = signer_id_from_pk(&signer_pk_led);

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut block_id = [0u8; 32];
        rng.fill_bytes(&mut block_id);

        let core = ConsensusMsgCore::PreVote(PreVote {
            height: 1,
            round: (i as u32) % 10, // PreVote.round is u32
            block_id,
        });

        // sign_core returns (signer_pk, sig, signer_id)
        let (signer_pk, sig, signer_id) = sign_core::<Pq44>(&core, chain_id, sk, pk);

        // Construct SignedConsensusMsg
        let mut msg = SignedConsensusMsg {
            core: core.clone(),
            signer_id,
            signer_pk,
            sig,
            height: 1,
            round: (i as u32) % 10,
        };

        // Corrupt some signatures based on valid_ratio
        if (i as f32 / n as f32) > valid_ratio {
            // Flip a random byte in the signature to invalidate it
            let mut sig_bytes = msg.sig.0;
            let byte_idx = rng.gen_range(0..sig_bytes.len());
            sig_bytes[byte_idx] = sig_bytes[byte_idx].wrapping_add(1);
            msg.sig.0 = sig_bytes;
        }

        out.push(msg);
    }
    out
}

fn bench_consensus_batch(c: &mut Criterion) {
    let sizes = [16usize, 64, 256, 1024];
    let ratios = [(1.0, "100%"), (0.9, "90%"), (0.5, "50%")];

    // shared config knobs
    let mut cfg = BatchVerifyCfg::default();
    cfg.threshold = 64;      // batch kicks in at >=64
    cfg.max_batch = 4096;
    cfg.parallel = true;     // toggle to false to compare serial
    cfg.cache_enabled = true;
    cfg.cache_capacity = 100_000;

    const CHAIN_LABEL: &[u8] = b"eezo-devnet";
    let mut chain_id = [0u8; 20];
    chain_id[..CHAIN_LABEL.len()].copy_from_slice(CHAIN_LABEL);

    // Generate keys with Pq44 scheme
    let (pk, sk) = <Pq44 as SignatureScheme>::keypair();
    let certs = DummyCerts::new_valid_for_pk(&pk);

    let mut group = c.benchmark_group("consensus_verify");
    for &n in &sizes {
        group.throughput(Throughput::Elements(n as u64));
        for &(ratio, lbl) in &ratios {
            // fresh msgs
            let msgs = make_msgs(n, &sk, &pk, &chain_id, ratio);

            // optional cache warmup pass (simulates hot validator set)
            let cache = if cfg.cache_enabled {
                Some(VerifyCache::new(cfg.cache_capacity))
            } else { None };

            if let Some(ref vc) = cache {
                // warm: verify once so second pass benefits from hits
                let mut warm = msgs.clone();
                validate_consensus_batch(chain_id, &certs, &cfg, &mut warm, Some(vc));
            }

            group.bench_function(
                BenchmarkId::new(format!("n={}", n), format!("valid={}", lbl)),
                |b| {
                    b.iter(|| {
                        let mut m = msgs.clone();
                        validate_consensus_batch(chain_id, &certs, &cfg, &mut m, cache.as_ref());
                        criterion::black_box(&m);
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_consensus_batch);
criterion_main!(benches);