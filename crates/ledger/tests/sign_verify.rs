use eezo_ledger::consensus::*;
use eezo_ledger::cert_store::*;

#[allow(dead_code)]
struct DummyCerts;
impl CertLookup for DummyCerts {
    fn get_pk(&self, _vid: &SignerId, _h: u64) -> Option<ValidatedPk> { None }
}

#[cfg_attr(not(feature = "consensus-tests"), ignore)]
#[test]
fn sign_and_verify_roundtrip() {
    // TODO: create core, chain_id, use your MlDsaLikeImpl to sign, then verify via DummyCerts
}