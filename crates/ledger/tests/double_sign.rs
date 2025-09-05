#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[test]
fn double_sign_evidence_emitted() {
    // TODO produce two signed msgs with same (h,r,step) and different block_id, expect evidence
}