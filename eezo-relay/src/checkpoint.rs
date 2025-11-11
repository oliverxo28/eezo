// crates/eezo-relay/src/checkpoint.rs
use std::{path::{Path, PathBuf}, fs::File, io::BufReader};
use anyhow::{Result, Context};
use eezo_ledger::checkpoints::{BridgeHeader, checkpoint_filename_tagged};

pub fn checkpoint_path(proof_root: &Path, height: u64) -> PathBuf {
    let file = checkpoint_filename_tagged(height, "active");
    proof_root.join("checkpoints").join(file)
}

pub fn read_checkpoint(proof_root: &Path, height: u64) -> Result<Option<BridgeHeader>> {
    let p = checkpoint_path(proof_root, height);
    match File::open(&p) {
        Ok(f) => {
            let r = BufReader::new(f);
            let hdr: BridgeHeader = serde_json::from_reader(r)
                .with_context(|| format!("parse checkpoint json {}", p.display()))?;
            Ok(Some(hdr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("open {}", p.display())),
    }
}
