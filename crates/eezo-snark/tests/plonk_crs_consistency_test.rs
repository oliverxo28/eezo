#![cfg(feature = "plonk_kzg")]

use eezo_snark::backend::plonk_kzg::keys::{load_crs_bytes, ensure_keys_dir};

#[test]
fn crs_files_exist_or_created() {
    ensure_keys_dir().expect("keys dir");
    let crs = load_crs_bytes().expect("load CRS");
    assert!(!crs.is_empty());
}
