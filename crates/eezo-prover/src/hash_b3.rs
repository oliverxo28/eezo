// ======================================================================
// T38.3 ‚Äî BLAKE3 state_root_v2 gadget skeleton
// Minimal structure only; no real algebraic constraints yet.
// This file is safe, compiling, and ready for incremental filling.
// ======================================================================

use crate::field::{rotr32};

/// Witness data for the state_root_v2 BLAKE3 gadget.
/// For now this only contains the final digest bytes.
/// Later we will add per-round lanes, word ops, etc.
#[derive(Clone, Debug)]
pub struct DigestWitness {
    pub digest: [u8; 32],
}

/// Generic backend interface for BLAKE3-based hashing.
///
/// This lets us swap implementations (CPU vs GPU) behind a stable API.
pub trait Blake3Backend {
    fn hash_many<I>(inputs: I) -> Vec<[u8; 32]>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>;

    fn hash_one(input: &[u8]) -> [u8; 32] {
        Self::hash_many(core::iter::once(input))
            .into_iter()
            .next()
            .expect("hash_one always returns exactly one digest")
    }
}

// T44.5 — hash mode selection (CPU-only vs CPU+GPU compare).
// This is only compiled when the `gpu-hash` feature is enabled.
#[cfg(feature = "gpu-hash")]
#[derive(Copy, Clone, Debug)]
enum HashMode {
    /// Only CPU hashing is used.
    CpuOnly,
    /// Both CPU and GPU hashing are run; CPU result is canonical and
    /// any mismatch is logged and counted via metrics.
    GpuCompare,
}

#[cfg(feature = "gpu-hash")]
fn current_hash_mode() -> HashMode {
    use std::sync::OnceLock;

    static MODE: OnceLock<HashMode> = OnceLock::new();

    *MODE.get_or_init(|| {
        let raw = std::env::var("EEZO_GPU_HASH_MODE").unwrap_or_else(|_| "cpu".to_string());
        let lower = raw.to_ascii_lowercase();
        match lower.as_str() {
            "cpu" | "" => HashMode::CpuOnly,
            "compare" | "cmp" => HashMode::GpuCompare,
            other => {
                log::warn!(
                    "gpu-hash: unknown EEZO_GPU_HASH_MODE='{}', falling back to cpu-only",
                    other
                );
                HashMode::CpuOnly
            }
        }
    })
}

/// CPU implementation (default backend).
pub struct Blake3CpuBackend;

impl Blake3Backend for Blake3CpuBackend {
    fn hash_many<I>(inputs: I) -> Vec<[u8; 32]>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        inputs
            .into_iter()
            .map(|bytes| *blake3::hash(bytes.as_ref()).as_bytes())
            .collect()
    }
}

/// Stub GPU implementation (currently CPU-backed).
///
/// When `gpu-hash` is enabled, this type becomes the active backend,
/// but for now it simply forwards to the CPU implementation. In later
/// T43.x tasks we will replace this with real GPU kernels.
#[cfg(feature = "gpu-hash")]
pub struct Blake3GpuBackend;

#[cfg(feature = "gpu-hash")]
impl Blake3Backend for Blake3GpuBackend {
    fn hash_many<I>(inputs: I) -> Vec<[u8; 32]>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        use crate::gpu_hash::Blake3GpuBatch;

        const DIGEST_LEN: usize = 32;

        // Own all inputs so we can build a single contiguous blob.
        let owned: Vec<Vec<u8>> = inputs
            .into_iter()
            .map(|item| item.as_ref().to_vec())
            .collect();

        let n = owned.len();
        if n == 0 {
            return Vec::new();
        }

        // Build the concatenated input blob + per-message metadata.
        let mut input_blob: Vec<u8> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(n);
        let mut lens: Vec<u32> = Vec::with_capacity(n);

        for msg in &owned {
            let off = input_blob.len();
            input_blob.extend_from_slice(msg.as_slice());
            offsets.push(
                off.try_into()
                    .expect("gpu-hash: message offset does not fit in u32"),
            );
            lens.push(
                msg.len()
                    .try_into()
                    .expect("gpu-hash: message length does not fit in u32"),
            );
        }

        let mut digests_out = vec![0u8; n * DIGEST_LEN];

        // Construct the batch view for the engine.
        let mut batch = Blake3GpuBatch {
            input_blob: &input_blob,
            offsets: &offsets,
            lens: &lens,
            digests_out: &mut digests_out,
        };

        // For T45.3 we call through the metrics + compare harness,
        // which internally selects CPU vs GPU and can optionally run
        // CPU-vs-GPU cross-checks based on env settings.
        crate::gpu_hash::hash_batch_with_metrics(&mut batch)
            .expect("gpu-hash: batch hashing should not fail in T45.3");

        // Convert the flat digest buffer into Vec<[u8; 32]>.
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let start = i * DIGEST_LEN;
            let end = start + DIGEST_LEN;
            let mut d = [0u8; DIGEST_LEN];
            d.copy_from_slice(&digests_out[start..end]);
            out.push(d);
        }

        out
    }
}

/// Front-door type used by the rest of the prover.
///
/// This picks a concrete backend at compile time based on features,
/// so call sites only depend on `Blake3Lanes` and never on which
/// backend is active.
pub struct Blake3Lanes;

impl Blake3Lanes {
    /// Hash many independent messages, returning one 32-byte digest per input.
    pub fn hash_many<I>(inputs: I) -> Vec<[u8; 32]>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        #[cfg(feature = "gpu-hash")]
        {
            use crate::metrics::{GPU_HASH_COMPARE_TOTAL, GPU_HASH_MISMATCH_TOTAL};

            match current_hash_mode() {
                HashMode::CpuOnly => {
                    // Simple: only CPU backend.
                    <Blake3CpuBackend as Blake3Backend>::hash_many(inputs)
                }
                HashMode::GpuCompare => {
                    // We need to reuse inputs for both CPU and GPU, so take ownership.
                    let owned: Vec<Vec<u8>> = inputs
                        .into_iter()
                        .map(|item| item.as_ref().to_vec())
                        .collect();

                    // CPU canonical digests.
                    let cpu_digests = <Blake3CpuBackend as Blake3Backend>::hash_many(
                        owned.iter().map(|v| v.as_slice()),
                    );

                    // GPU digests via the GPU backend.
                    GPU_HASH_COMPARE_TOTAL.inc();
                    let gpu_digests = <Blake3GpuBackend as Blake3Backend>::hash_many(
                        owned.iter().map(|v| v.as_slice()),
                    );

                    if gpu_digests != cpu_digests {
                        GPU_HASH_MISMATCH_TOTAL.inc();
                        log::error!(
                            "gpu-hash: mismatch between CPU and GPU digests in compare mode; \
                             using CPU digest as canonical"
                        );
                    }

                    cpu_digests
                }
            }
        }

        #[cfg(not(feature = "gpu-hash"))]
        {
            // No GPU backend compiled in; always CPU.
            <Blake3CpuBackend as Blake3Backend>::hash_many(inputs)
        }
    }

    /// Convenience wrapper for the common single-input case.
    #[inline]
    pub fn hash_one(input: &[u8]) -> [u8; 32] {
        Self::hash_many(core::iter::once(input))
            .into_iter()
            .next()
            .expect("hash_one always returns exactly one digest")
    }
}


/// Build the *witness* for the state_root_v2 digest.
///
/// Internally this now uses the BLAKE3 lanes abstraction so we can
/// later swap in a GPU-backed implementation without changing callers.
pub fn prove_state_root_digest(state_bytes: &[u8]) -> DigestWitness {
    let digest = Blake3Lanes::hash_one(state_bytes);
    DigestWitness { digest }
}

/// Enforce the algebraic constraints for the state_root_v2 gadget.
/// For T38.3 step-2 this is a **stub** and always passes.
/// In later steps we will verify add/xor/rot transitions and the lanes.
pub fn enforce_state_root_constraints(
    _rows: &mut [crate::trace::Row],
    _w: &DigestWitness,
) -> Result<(), &'static str> {
    // T38.3 phase-0: no constraints yet
    Ok(())
}

/// In later steps this will map the digest witness into final trace lanes.
/// For now we leave only a stub (called by witness builder).
pub fn place_digest_into_trace(
    _row: &mut crate::trace::Row,
    _w: &DigestWitness,
) {
    // Will fill during T38.3 ‚Üí T38.4
}
// ======================================================================
// T38.3 phase-3 ‚Äî first algebraic step (byte-aligned rotations)
//
// We enforce/validate the equivalence of 32-bit ROTR by 8 and 16 using
// a byte-lane rewire. This is a true algebraic identity at the limb
// (8-bit) level and requires no bit gadgets. ROTR by 12 and 7 will come
// later with bit-slicing.
// ======================================================================

#[inline]
fn u32_to_be_bytes(x: u32) -> [u8;4] { x.to_be_bytes() }

#[inline]
fn be_bytes_to_u32(b: [u8;4]) -> u32 { u32::from_be_bytes(b) }

/// Rotate-right by k ‚àà {8,16} using byte-lane rewiring in BE order.
/// (We pick BE for a canonical limb order; choice is arbitrary as long as tests match.)
fn rotr_bytes_8_or_16_be(x: u32, k: u32) -> u32 {
    debug_assert!(k == 8 || k == 16);
    let mut v = u32_to_be_bytes(x);
    // rotr 8:  [b0,b1,b2,b3] -> [b3,b0,b1,b2]
    // rotr16: [b0,b1,b2,b3] -> [b2,b3,b0,b1]
    let out = match k {
        8  => [v[3], v[0], v[1], v[2]],
        16 => [v[2], v[3], v[0], v[1]],
        _  => unreachable!(),
    };
    be_bytes_to_u32(out)
}

/// Check that byte-lane rotation equals software rotate_right for k ‚àà {8,16}.
pub fn check_rotr_8_16_consistency(x: u32) -> bool {
    let r8_sw  = rotr32(x, 8);
    let r8_lm  = rotr_bytes_8_or_16_be(x, 8);
    let r16_sw = rotr32(x, 16);
    let r16_lm = rotr_bytes_8_or_16_be(x, 16);
    r8_sw == r8_lm && r16_sw == r16_lm
}

/// Backwards-compat alias for older tests.
/// Prefer `check_rotr_8_16_consistency` in new code.
pub fn check_rotr8_16_consistency(x: u32) -> bool {
    check_rotr_8_16_consistency(x)
}

/// A tiny "mini-round" identity we can validate now without bit-gadgets:
/// x' = (x + y) ^ z (in 32-bit software), then ensure ROTR by {8,16}
/// matches the byte-lane rewire model above.
pub fn check_add_xor_then_rotr8_16(x: u32, y: u32, z: u32) -> bool {
    let x1 = x.wrapping_add(y) ^ z;
    check_rotr_8_16_consistency(x1)
}

#[cfg(test)]
mod tests {
    use super::{Blake3Lanes, prove_state_root_digest};

    #[test]
    fn lanes_matches_direct_blake3_for_many_inputs() {
        let inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"eezo".to_vec(),
            vec![0u8; 32],
            (0u8..=255).collect(),
        ];

        let expected: Vec<[u8; 32]> = inputs
            .iter()
            .map(|m| *blake3::hash(m).as_bytes())
            .collect();

        // call through the front-door lanes type
        let got = Blake3Lanes::hash_many(inputs.iter().map(|m| m.as_slice()));

        assert_eq!(expected, got);
    }

    #[test]
    fn prove_state_root_digest_uses_same_hash_as_lanes() {
        let msg = b"state-root-v2-test";
        let w = prove_state_root_digest(msg);
        let expected = Blake3Lanes::hash_one(msg);
        assert_eq!(w.digest, expected);
    }
}