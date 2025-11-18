#![cfg(feature = "plonk_kzg")]

use std::fs;
use std::path::PathBuf;
use crate::backend::plonk_kzg::types::{PlonkPk, PlonkVk};

/// Default key directory for dev. You can change this later or make it configurable.
pub fn default_keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("keys")
}

/// Ensure the keys directory exists.
pub fn ensure_keys_dir() -> std::io::Result<PathBuf> {
    let dir = default_keys_dir();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// (Stub) load CRS bytes. In T39.3 we will replace with a real CRS.
pub fn load_crs_bytes() -> std::io::Result<Vec<u8>> {
    let dir = ensure_keys_dir()?;
    let path = dir.join("snark_crs.bin");
    if !path.exists() {
        // write a small stub so flows work end-to-end
        fs::write(&path, b"EEZO_STUB_CRS_V1")?;
    }
    fs::read(path)
}

pub fn load_pk() -> std::io::Result<PlonkPk> {
    let dir = ensure_keys_dir()?;
    let path = dir.join("snark_pk.bin");
    if !path.exists() {
        fs::write(&path, b"EEZO_STUB_PK_V1")?;
    }
    let bytes = fs::read(path)?;
    Ok(PlonkPk { bytes })
}

pub fn load_vk() -> std::io::Result<PlonkVk> {
    let dir = ensure_keys_dir()?;
    let path = dir.join("snark_vk.bin");
    if !path.exists() {
        fs::write(&path, b"EEZO_STUB_VK_V1")?;
    }
    let bytes = fs::read(path)?;
    Ok(PlonkVk { bytes })
}

/// (Optional) Save generated PK/VK if you create them at runtime later.
pub fn save_pk(bytes: &[u8]) -> std::io::Result<()> {
    let dir = ensure_keys_dir()?;
    fs::write(dir.join("snark_pk.bin"), bytes)
}
pub fn save_vk(bytes: &[u8]) -> std::io::Result<()> {
    let dir = ensure_keys_dir()?;
    fs::write(dir.join("snark_vk.bin"), bytes)
}
