// T38.6 — proof (de)serialization for current StarkProof/FriProof shapes.
// Format (little-endian, versioned):
//   u8  : version (=1)
//   [32]: trace_root
//   [32]: public_inputs_hash
//   u32 : fri.layers.len()
//     repeat L times:
//       [32]: layer.root
//       u32 : layer.evals.len()
//       u64 * len : layer.evals
//   u32 : fri.challenges.len()
//     u64 * k : challenges
//   u32 : query_indices.len()
//     u32 * q : query_indices
//   u32 : layer_openings.len()  // = L
//     repeat L times:
//       u32 : openings_in_layer (= q)
//       repeat q times:
//         [32]: proof.leaf
//         u32 : path.len()
//           repeat path.len(): [32] sibling, u8 is_left
//         [32]: proof.root
//   u32 : layer_values.len() // = L
//     repeat L times:
//       u32 : values_in_layer (= q)
//       repeat q times: u64 value

use crate::fri::FriProof;
use crate::merkle::MerkleProof;
use crate::proof::StarkProof;

pub fn serialize_proof(p: &StarkProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 << 12);

    // version
    out.push(1u8);

    // trace_root
    out.extend_from_slice(&p.trace_root);
    // pi hash
    out.extend_from_slice(&p.public_inputs_hash);

    // fri layers
    write_u32(&mut out, p.fri.layers.len() as u32);
    for layer in &p.fri.layers {
        out.extend_from_slice(&layer.root);
        write_u32(&mut out, layer.evals.len() as u32);
        for &v in &layer.evals {
            write_u64(&mut out, v);
        }
    }

    // fri challenges
    write_u32(&mut out, p.fri.challenges.len() as u32);
    for &c in &p.fri.challenges {
        write_u64(&mut out, c);
    }

    // query indices
    write_u32(&mut out, p.query_indices.len() as u32);
    for &qi in &p.query_indices {
        write_u32(&mut out, qi as u32);
    }

    // layer openings
    write_u32(&mut out, p.layer_openings.len() as u32);
    for layer in &p.layer_openings {
        write_u32(&mut out, layer.len() as u32);
        for proof in layer {
            out.extend_from_slice(&proof.leaf);
            write_u32(&mut out, proof.path.len() as u32);
            for node in &proof.path {
                out.extend_from_slice(&node.sibling);
                out.push(if node.is_left { 1 } else { 0 });
            }
            out.extend_from_slice(&proof.root);
        }
    }

    // layer values
    write_u32(&mut out, p.layer_values.len() as u32);
    for vals in &p.layer_values {
        write_u32(&mut out, vals.len() as u32);
        for &v in vals {
            write_u64(&mut out, v);
        }
    }
    // prev_left_openings (L-1)
    write_u32(&mut out, p.prev_left_openings.len() as u32);
    for layer in &p.prev_left_openings {
        write_u32(&mut out, layer.len() as u32);
        for proof in layer {
            out.extend_from_slice(&proof.leaf);
            write_u32(&mut out, proof.path.len() as u32);
            for node in &proof.path {
                out.extend_from_slice(&node.sibling);
                out.push(if node.is_left { 1 } else { 0 });
            }
            out.extend_from_slice(&proof.root);
        }
    }

    // prev_right_openings (L-1)
    write_u32(&mut out, p.prev_right_openings.len() as u32);
    for layer in &p.prev_right_openings {
        write_u32(&mut out, layer.len() as u32);
        for proof in layer {
            out.extend_from_slice(&proof.leaf);
            write_u32(&mut out, proof.path.len() as u32);
            for node in &proof.path {
                out.extend_from_slice(&node.sibling);
                out.push(if node.is_left { 1 } else { 0 });
            }
            out.extend_from_slice(&proof.root);
        }
    }

    // prev_left_values (L-1)
    write_u32(&mut out, p.prev_left_values.len() as u32);
    for vals in &p.prev_left_values {
        write_u32(&mut out, vals.len() as u32);
        for &v in vals {
            write_u64(&mut out, v);
        }
    }

    // prev_right_values (L-1)
    write_u32(&mut out, p.prev_right_values.len() as u32);
    for vals in &p.prev_right_values {
        write_u32(&mut out, vals.len() as u32);
        for &v in vals {
            write_u64(&mut out, v);
        }
    }
    // === constraints commitment & openings ===
    out.extend_from_slice(&p.constraints_root);
    write_u32(&mut out, p.constraints_openings.len() as u32);
    for mp in &p.constraints_openings {
        out.extend_from_slice(&mp.leaf);
        write_u32(&mut out, mp.path.len() as u32);
        for node in &mp.path {
            out.extend_from_slice(&node.sibling);
            out.push(if node.is_left { 1 } else { 0 });
        }
        out.extend_from_slice(&mp.root);
    }
    write_u32(&mut out, p.constraints_values.len() as u32);
    for &v in &p.constraints_values {
        write_u64(&mut out, v);
    }
    // === T38.6.4: final polynomial (coeffs) + commitment root ===
    write_u32(&mut out, p.fri.final_poly.coeffs.len() as u32);
    for &c in &p.fri.final_poly.coeffs {
        write_u64(&mut out, c);
    }
    out.extend_from_slice(&p.final_poly_root);	
    out
}

pub fn deserialize_proof(mut bytes: &[u8]) -> Option<StarkProof> {
    // version
    let version = read_u8(&mut bytes)?;
    if version != 1 { return None; }

    // roots/hashes
    let trace_root = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
    let public_inputs_hash = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion

    // fri layers
    let lcnt = read_u32(&mut bytes)? as usize;
    let mut layers = Vec::with_capacity(lcnt);
    for _ in 0..lcnt {
        let root: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
        let len = read_u32(&mut bytes)? as usize;
        let mut evals = Vec::with_capacity(len);
        for _ in 0..len { evals.push(read_u64(&mut bytes)?); }
        layers.push(crate::fri::FriLayer { evals, root });
    }

    // fri challenges
    let ccnt = read_u32(&mut bytes)? as usize;
    let mut challenges = Vec::with_capacity(ccnt);
    for _ in 0..ccnt { challenges.push(read_u64(&mut bytes)?); }
    let fri = FriProof { layers, final_poly: crate::poly::Polynomial { coeffs: Vec::new() }, challenges };

    // query indices
    let qcnt = read_u32(&mut bytes)? as usize;
    let mut query_indices = Vec::with_capacity(qcnt);
    for _ in 0..qcnt { query_indices.push(read_u32(&mut bytes)? as usize); }

    // layer openings
    let lcnt2 = read_u32(&mut bytes)? as usize;
    let mut layer_openings = Vec::with_capacity(lcnt2);
    for _ in 0..lcnt2 {
        let q = read_u32(&mut bytes)? as usize;
        let mut proofs = Vec::with_capacity(q);
        for _ in 0..q {
            let leaf: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
            let plen = read_u32(&mut bytes)? as usize;
            let mut path = Vec::with_capacity(plen);
            for _ in 0..plen {
                let sib: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
                let is_left = read_u8(&mut bytes)? == 1;
                path.push(crate::merkle::ProofNode { sibling: sib, is_left });
            }
            let root: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
            proofs.push(MerkleProof { leaf, path, root });
        }
        layer_openings.push(proofs);
    }

    // layer values
    let lcnt3 = read_u32(&mut bytes)? as usize;
    let mut layer_values = Vec::with_capacity(lcnt3);
    for _ in 0..lcnt3 {
        let q = read_u32(&mut bytes)? as usize;
        let mut vals = Vec::with_capacity(q);
        for _ in 0..q { vals.push(read_u64(&mut bytes)?); }
        layer_values.push(vals);
    }
    // prev_left_openings
    let plc = read_u32(&mut bytes)? as usize;
    let mut prev_left_openings = Vec::with_capacity(plc);
    for _ in 0..plc {
        let q = read_u32(&mut bytes)? as usize;
        let mut proofs = Vec::with_capacity(q);
        for _ in 0..q {
            let leaf: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
            let plen = read_u32(&mut bytes)? as usize;
            let mut path = Vec::with_capacity(plen);
            for _ in 0..plen {
                let sib: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
                let is_left = read_u8(&mut bytes)? == 1;
                path.push(crate::merkle::ProofNode { sibling: sib, is_left });
            }
            let root: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
            proofs.push(crate::merkle::MerkleProof { leaf, path, root });
        }
        prev_left_openings.push(proofs);
    }

    // prev_right_openings
    let prc = read_u32(&mut bytes)? as usize;
    let mut prev_right_openings = Vec::with_capacity(prc);
    for _ in 0..prc {
        let q = read_u32(&mut bytes)? as usize;
        let mut proofs = Vec::with_capacity(q);
        for _ in 0..q {
            let leaf: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
            let plen = read_u32(&mut bytes)? as usize;
            let mut path = Vec::with_capacity(plen);
            for _ in 0..plen {
                let sib: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
                let is_left = read_u8(&mut bytes)? == 1;
                path.push(crate::merkle::ProofNode { sibling: sib, is_left });
            }
            let root: [u8;32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
            proofs.push(crate::merkle::MerkleProof { leaf, path, root });
        }
        prev_right_openings.push(proofs);
    }

    // prev_left_values
    let plv = read_u32(&mut bytes)? as usize;
    let mut prev_left_values = Vec::with_capacity(plv);
    for _ in 0..plv {
        let q = read_u32(&mut bytes)? as usize;
        let mut vals = Vec::with_capacity(q);
        for _ in 0..q { vals.push(read_u64(&mut bytes)?); }
        prev_left_values.push(vals);
    }

    // prev_right_values
    let prv = read_u32(&mut bytes)? as usize;
    let mut prev_right_values = Vec::with_capacity(prv);
    for _ in 0..prv {
        let q = read_u32(&mut bytes)? as usize;
        let mut vals = Vec::with_capacity(q);
        for _ in 0..q { vals.push(read_u64(&mut bytes)?); }
        prev_right_values.push(vals);
    }
    // === constraints commitment & openings ===
    let constraints_root: [u8; 32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
    let c_cnt = read_u32(&mut bytes)? as usize;
    let mut constraints_openings = Vec::with_capacity(c_cnt);
    for _ in 0..c_cnt {
        let leaf: [u8; 32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
        let plen = read_u32(&mut bytes)? as usize;
        let mut path = Vec::with_capacity(plen);
        for _ in 0..plen {
            let sib: [u8; 32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
            let is_left = read_u8(&mut bytes)? == 1;
            path.push(crate::merkle::ProofNode { sibling: sib, is_left });
        }
        let root: [u8; 32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion
        constraints_openings.push(crate::merkle::MerkleProof { leaf, path, root });
    }
    let cv_cnt = read_u32(&mut bytes)? as usize;
    let mut constraints_values = Vec::with_capacity(cv_cnt);
    for _ in 0..cv_cnt {
        constraints_values.push(read_u64(&mut bytes)?);
    }

    // === T38.6.4: final polynomial (coeffs) + commitment root ===
    let fcnt = read_u32(&mut bytes)? as usize;
    let mut final_coeffs = Vec::with_capacity(fcnt);
    for _ in 0..fcnt { final_coeffs.push(read_u64(&mut bytes)?); }
    let final_poly_root: [u8; 32] = read_32(&mut bytes)?; // <-- FIXED: removed unnecessary conversion

    Some(StarkProof {
        trace_root,
        fri: FriProof {
            layers: fri.layers,
            final_poly: crate::poly::Polynomial { coeffs: final_coeffs },
            challenges: fri.challenges,
        },
        public_inputs_hash,
        query_indices,
        layer_openings,
        layer_values,
        prev_left_openings,
        prev_right_openings,
        prev_left_values,
        prev_right_values,
        constraints_root,
        constraints_openings,
        constraints_values,
        final_poly_root,		
    })
}

// ---- little-endian helpers ----
fn write_u32(out: &mut Vec<u8>, x: u32) { out.extend_from_slice(&x.to_le_bytes()); }
fn write_u64(out: &mut Vec<u8>, x: u64) { out.extend_from_slice(&x.to_le_bytes()); }

fn read_u8(inp: &mut &[u8]) -> Option<u8> { if inp.is_empty() {None} else {let v=inp[0]; *inp=&inp[1..]; Some(v)} } // <-- FIXED: use is_empty()
fn read_32(inp: &mut &[u8]) -> Option<[u8;32]> { if inp.len()<32 {None} else {let mut a=[0u8;32]; a.copy_from_slice(&inp[..32]); *inp=&inp[32..]; Some(a)} }
fn read_u32(inp: &mut &[u8]) -> Option<u32> {
    if inp.len() < 4 { None } else {
        let mut a=[0u8;4]; a.copy_from_slice(&inp[..4]); *inp=&inp[4..];
        Some(u32::from_le_bytes(a))
    }
}
fn read_u64(inp: &mut &[u8]) -> Option<u64> {
    if inp.len() < 8 { None } else {
        let mut a=[0u8;8]; a.copy_from_slice(&inp[..8]); *inp=&inp[8..];
        Some(u64::from_le_bytes(a))
    }
}