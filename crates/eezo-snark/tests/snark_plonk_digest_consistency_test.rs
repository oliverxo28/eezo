#![cfg(feature = "plonk_kzg")]

use eezo_snark::transcript::circuit_public_digest;
use eezo_snark::public::pack_public;
use eezo_snark::backend::plonk_kzg::prove_plonk;

use eezo_prover::stark_snark_prep::prepare_for_snark;
use eezo_prover::proof::prove as stark_prove;
use eezo_prover::{trace::Trace, air_spec::AirSpec};

#[test]
fn plonk_digest_consistency() {
    let mut t = Trace::new();
    t.push_row(0);
    let a = AirSpec::default();
    let stark = stark_prove(&t, &a);

    let sp = prepare_for_snark(&stark);
    let digest = circuit_public_digest(&sp);

    assert_ne!(digest, [0u8; 32], "digest must be nonzero");

    let _pf = prove_plonk(&sp);

    // circuit vs host consistent because we use the same digest
    let digest2 = circuit_public_digest(&sp);
    assert_eq!(digest, digest2);
}
