use std::{fs, path::PathBuf};

use eezo_ledger::checkpoints::{
    checkpoint_filename_tagged, write_checkpoint_json_tagged, BridgeHeader,
};

fn arr(fill: u8) -> [u8; 32] {
    [fill; 32]
}

fn hex64(fill: u8) -> String {
    // 64 hex chars, e.g. "01" * 32
    let byte = format!("{:02x}", fill);
    byte.repeat(32)
}

#[test]
fn bridge_header_hex_json_roundtrip() {
    let hdr = BridgeHeader {
        height: 42,
        header_hash: arr(0x01),
        state_root_v2: arr(0xAB),
        tx_root_v2: arr(0xCD),
        timestamp: 1_234_567_890,
        finality_depth: 2,
        suite_id: 1,
		qc_sidecar_v2: None,
    };

    // serialize → string must contain 0x-hex (not arrays)
    let s = serde_json::to_string(&hdr).expect("serialize");
    assert!(s.contains("\"header_hash\":\"0x"));
    assert!(s.contains("\"state_root_v2\":\"0x"));
    assert!(s.contains("\"tx_root_v2\":\"0x"));

    // round-trip
    let back: BridgeHeader = serde_json::from_str(&s).expect("deserialize back");
    assert_eq!(back, hdr);
}

#[test]
fn bridge_header_accepts_bare_hex_on_deserialize() {
    // Make a JSON string where the 32B fields are bare 64-hex (no 0x)
    let j = format!(
        r#"{{
            "height": 7,
            "header_hash": "{hh}",
            "state_root_v2": "{sr}",
            "tx_root_v2": "{tr}",
            "timestamp": 99,
            "finality_depth": 1,
            "suite_id": 1
        }}"#,
        hh = hex64(0x11),
        sr = hex64(0x22),
        tr = hex64(0x33),
    );

    let v: BridgeHeader = serde_json::from_str(&j).expect("bare-hex accepted");
    assert_eq!(v.height, 7);
    assert_eq!(v.header_hash, [0x11; 32]);
    assert_eq!(v.state_root_v2, [0x22; 32]);
    assert_eq!(v.tx_root_v2, [0x33; 32]);
}

#[test]
fn rotation_filename_is_stable_and_writes() {
    // temp dir without extra deps
    let mut dir = std::env::temp_dir();
    dir.push(format!("eezo_ckpt_test_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("mkdir");

    let hdr = BridgeHeader {
        height: 123,
        header_hash: arr(0xAA),
        state_root_v2: arr(0xBB),
        tx_root_v2: arr(0xCC),
        timestamp: 777,
        finality_depth: 2,
        suite_id: 1,
		qc_sidecar_v2: None,
    };

    // write with tag "active"
    let written: PathBuf =
        write_checkpoint_json_tagged(&dir, &hdr, "active").expect("write");
    let expect_name = checkpoint_filename_tagged(123, "active");
    assert_eq!(
        written.file_name().unwrap().to_string_lossy(),
        expect_name
    );

    // file exists and parses back
    let bytes = fs::read(&written).expect("read back");
    let parsed: BridgeHeader =
        serde_json::from_slice(&bytes).expect("parse back");
    assert_eq!(parsed, hdr);

    // cleanup best-effort
    let _ = fs::remove_file(&written);
    let _ = fs::remove_dir(&dir);
}
