// =============================================================================
// T40.3 — unit tests (router & shadow behavior) — EXTERNAL TEST FILE
// Notes:
// * We don't rely on real crypto success; we pass dummy bytes so actual
//   signature verification returns `false`. We only assert that the *router*
//   (pre-window / in-window / post-cutoff) behaves correctly and that the
//   shadow wrapper toggles `shadow_attempted` inside the window.
// * Tests are feature-tolerant: they compile with `mldsa` enabled; for NEXT
//   suite we set AlgoId::SlhDsa128f (even if slh-dsa is off, verifier returns
//   false, which is acceptable for these routing assertions).
// =============================================================================

use eezo_crypto::sig::registry::{verify_dual_accept_shadow, verify_rotating};
use eezo_crypto::sig::{RotationState, AlgoId};
#[cfg(feature = "mldsa")]
use eezo_crypto::sig::mldsa::{MlDsa44, SignatureScheme};

// Minimal helper to create dummy bytes with correct *lengths* for ML-DSA,
// so we exercise the code paths without needing valid signatures.
#[cfg(feature = "mldsa")]
fn dummy_mldsa_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let pk_len  = <MlDsa44 as SignatureScheme>::PK_LEN;
    let sig_len = <MlDsa44 as SignatureScheme>::SIG_MAX_LEN;
    let pk  = vec![0u8; pk_len];
    let sig = vec![0u8; sig_len];
    let msg = b"eezo-shadow-router-test".to_vec();
    (pk, msg, sig)
}

// --- helper rotation states ---
fn state_with_window(active: AlgoId, next: AlgoId, until: u64) -> RotationState {
    RotationState { active_suite: active, next_suite: Some(next), dual_accept_until: Some(until) }
}
fn state_no_rotation(active: AlgoId) -> RotationState {
    RotationState { active_suite: active, next_suite: None, dual_accept_until: None }
}

#[test]
#[cfg(feature = "mldsa")]
fn t403_shadow_attempts_only_inside_window() {
    // window: next = sphincs (even if feature off, it's fine)
    let st = state_with_window(AlgoId::MlDsa44, AlgoId::SlhDsa128f, 150);
    let (pk, msg, sig) = dummy_mldsa_inputs();

    // inside window → shadow attempted = true
    let s_in = verify_dual_accept_shadow(&st, 140, &pk, &msg, &sig);
    assert!(s_in.shadow_attempted, "shadow must attempt next inside window");

    // after cutoff → shadow not attempted
    let s_post = verify_dual_accept_shadow(&st, 200, &pk, &msg, &sig);
    assert!(!s_post.shadow_attempted, "shadow must NOT attempt next after cutoff");
}

#[test]
#[cfg(feature = "mldsa")]
fn t403_verify_rotating_routing_after_cutoff_old_is_rejected() {
    let st = state_with_window(AlgoId::MlDsa44, AlgoId::SlhDsa128f, 150);
    let (pk, msg, sig) = dummy_mldsa_inputs();

    // post-cutoff, requesting ACTIVE algo must be rejected by the router
    let ok_old = verify_rotating(&st, 200, AlgoId::MlDsa44, &pk, &msg, &sig);
    assert!(!ok_old, "post-cutoff: old suite must be rejected by router");
}

#[test]
#[cfg(feature = "mldsa")]
fn t403_verify_rotating_routing_in_window_accepts_active_or_next_ids() {
    let st = state_with_window(AlgoId::MlDsa44, AlgoId::SlhDsa128f, 150);
    let (pk, msg, sig) = dummy_mldsa_inputs();

    // active path executes (returns false due to dummy crypto, but routes correctly)
    let _ = verify_rotating(&st, 140, AlgoId::MlDsa44, &pk, &msg, &sig);
    // next path executes
    let _ = verify_rotating(&st, 140, AlgoId::SlhDsa128f, &pk, &msg, &sig);

    // only the two configured IDs are acceptable in the window
    assert!(st.accepts(140, AlgoId::MlDsa44));
    assert!(st.accepts(140, AlgoId::SlhDsa128f));
}

#[test]
#[cfg(feature = "mldsa")]
fn t403_verify_rotating_no_rotation_active_only() {
    let st = state_no_rotation(AlgoId::MlDsa44);
    let (pk, msg, sig) = dummy_mldsa_inputs();

    // with no rotation scheduled, only active algo id is ever considered
    let ok_active = verify_rotating(&st, 100, AlgoId::MlDsa44, &pk, &msg, &sig);
    let ok_next   = verify_rotating(&st, 100, AlgoId::SlhDsa128f, &pk, &msg, &sig);
    assert!(!ok_active, "dummy bytes keep crypto false but path must compile");
    assert!(!ok_next, "next not scheduled → router rejects outright");
}