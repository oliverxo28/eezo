// crates/eezo-relay/src/checkpoint.rs
use std::{path::{Path, PathBuf}, fs::File, io::BufReader};
use anyhow::{Result, Context};
use eezo_ledger::checkpoints::{BridgeHeader, checkpoint_filename_tagged};
use log::warn;

pub fn checkpoint_path(proof_root: &Path, height: u64) -> PathBuf {
    let file = checkpoint_filename_tagged(height, "active");
    proof_root.join("checkpoints").join(file)
}

pub fn read_checkpoint(proof_root: &Path, height: u64) -> Result<Option<BridgeHeader>> {
    let p = checkpoint_path(proof_root, height);
    match File::open(&p) {
        Ok(f) => {
            let r = BufReader::new(f);
            // T42.3: treat parse failures and stale/mismatched heights as "no checkpoint"
            let hdr: BridgeHeader = match serde_json::from_reader(r) {
                Ok(h) => h,
                Err(e) => {
                    warn!(
                        "relay: corrupted checkpoint json at {} (height={}): {} → skipping",
                        p.display(),
                        height,
                        e
                    );
                    return Ok(None);
                }
            };
            if hdr.height != height {
                warn!(
                    "relay: checkpoint {} has mismatched height (expected {}, got {}) → skipping",
                    p.display(),
                    height,
                    hdr.height
                );
                return Ok(None);
            }
            Ok(Some(hdr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("open {}", p.display())),
    }
}
