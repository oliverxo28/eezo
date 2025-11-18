// T38.5 — FRI scaffolding (minimal, deterministic).
// This file defines:
//   - FRI layer structure
//   - folding function
//   - transcript-based challenge derivation
//   - layer-by-layer commitments
//
// NOTE: This is NOT optimized math.
// It is the structural pipeline needed for T38.5 tests.
// Real field folding & FFT integration come in T38.6–T38.7.

use crate::merkle::merkle_root;
use crate::poly::Polynomial;
use crate::domain::Domain;
use crate::hash_b3::Blake3Lanes;

use blake3::Hasher;

/// One layer of the FRI proof:
/// - committed evaluations
/// - merkle root of that layer
#[derive(Clone, Debug)]
pub struct FriLayer {
    pub evals: Vec<u64>,
    pub root: [u8; 32],
}

/// The result of running FRI on an evaluation vector.
#[derive(Clone, Debug)]
pub struct FriProof {
    pub layers: Vec<FriLayer>,
    pub final_poly: Polynomial,
    pub challenges: Vec<u64>,
}

/// Simple transcript for challenge derivation (Fiat–Shamir).
#[derive(Clone, Debug)]
pub struct Transcript {
    hasher: Hasher,
}

impl Default for Transcript { // <-- ADDED: Default implementation
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    pub fn new() -> Self {
        Self { hasher: Hasher::new() }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn challenge_u64(&mut self) -> u64 {
        let digest = self.hasher.finalize();
        let bytes = digest.as_bytes();
        // deterministically convert 8 bytes → u64
        let mut out = 0u64;
        for (i, &b) in bytes.iter().take(8).enumerate() { // <-- FIXED: better iteration pattern
            out |= (b as u64) << (8 * i);
        }
        // re-seed for next challenge
        self.hasher = Hasher::new();
        self.hasher.update(bytes);
        out
    }
}

/// Minimal FRI folding function.
/// Real version later uses field ops / permutation.
/// For now:
///     f'(i) = f(2i) + α * f(2i + 1)
fn fold_layer(prev: &[u64], alpha: u64) -> Vec<u64> {
    let mut out = Vec::with_capacity(prev.len() / 2);

    for i in (0..prev.len()).step_by(2) {
        if i + 1 >= prev.len() {
            out.push(prev[i]); // odd node promoted
        } else {
            let a = prev[i];
            let b = prev[i + 1];
            let folded = a.wrapping_add(b.wrapping_mul(alpha));
            out.push(folded);
        }
    }

    out
}

/// Run the FRI protocol on a polynomial evaluated over a domain.
pub fn fri_prove(
    evals: Vec<u64>,
    _domain: &Domain, // <-- FIXED: prefix with underscore since parameter is unused
) -> FriProof {
    let mut transcript = Transcript::new();
    let mut layers = Vec::new();
    let mut challenges = Vec::new();

    // Layer 0: the initial evaluations.
    // Hash all evals in one shot via the BLAKE3 lanes helper (each u64 → 8 LE bytes).
    let eval_bytes: Vec<[u8; 8]> = evals.iter().map(|x| x.to_le_bytes()).collect();
    let leaves: Vec<[u8; 32]> = Blake3Lanes::hash_many(
        eval_bytes.iter().map(|b| b.as_slice()),
    );
    let root0 = merkle_root(&leaves);
    layers.push(FriLayer { evals: evals.clone(), root: root0 });

    // absorb the first root
    transcript.absorb(&root0);

    // FRI rounds: keep folding until polynomial gets small (<= 16 coeffs).
    let mut cur = evals;
    while cur.len() > 16 {
        // derive challenge α
        let alpha = transcript.challenge_u64();
        challenges.push(alpha);

        // fold
        cur = fold_layer(&cur, alpha);

        // commit to layer: hash all folded evals via lanes helper
        let eval_bytes: Vec<[u8; 8]> = cur.iter().map(|x| x.to_le_bytes()).collect();
        let leaves: Vec<[u8; 32]> = Blake3Lanes::hash_many(
            eval_bytes.iter().map(|b| b.as_slice()),
        );

        let root = merkle_root(&leaves);
        layers.push(FriLayer { evals: cur.clone(), root });

        // update transcript
        transcript.absorb(&root);
    }

    // final polynomial = interpret last evals as polynomial coefficients
    let final_poly = Polynomial { coeffs: cur };

    FriProof {
        layers,
        final_poly,
        challenges,
    }
}