#![cfg(feature = "plonk_kzg")]

use eezo_snark::backend::plonk_kzg::{prove_plonk, verify_plonk};
use eezo_prover::stark_snark_prep::prepare_for_snark;
use eezo_prover::proof::prove as stark_prove;
use eezo_prover::{trace::Trace, air_spec::AirSpec};

#[test]
fn plonk_prove_verify_roundtrip_ok() {
    let mut t = Trace::new();
    t.push_row(0);
    let a = AirSpec::default();

    let stark = stark_prove(&t, &a);
    let sp = prepare_for_snark(&stark);

    let proof = prove_plonk(&sp);
    assert!(verify_plonk(&sp, &proof));
}
