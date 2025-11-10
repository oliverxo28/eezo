use eezo_wallet::{cmd_balance, cmd_new, cmd_send};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn cli_helpers_smoke() {
    // Non-interactive: write ./keystore.json with password "pw"
    cmd_new(Some("keystore.json"), Some("pw"), false).expect("new ok");
    cmd_balance("eezo1testaddress").expect("balance ok");
    cmd_send("fromX", "toY", 123u128, 10u64, Some(0)).expect("send ok");
}

/// Ensure the `wallet prove-bridge` CLI writes a proof artifact to proof/bridge/.
#[test]
fn cli_prove_bridge_writes_artifact() {
    // Prepare a minimal header JSON where the CLI can point to (optional input)
    let height: u64 = 128;
    let mut hdr_dir = PathBuf::from("proof/checkpoints");
    fs::create_dir_all(&hdr_dir).unwrap();
    let mut hdr_path = hdr_dir.clone();
    hdr_path.push(format!("{:020}.json", height));
    let header_json = r#"{
      "height": 128,
      "header_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
      "state_root_v2": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
      "tx_root_v2": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
      "timestamp": 0,
      "finality_depth": 2
    }"#;
    fs::write(&hdr_path, header_json.as_bytes()).unwrap();

    // Ensure output dir exists/clean
    fs::create_dir_all("proof/bridge").unwrap();

    // Synthetically valid 32-byte hex values
    let leaf = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let root = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let branch = "0x1111111111111111111111111111111111111111111111111111111111111111,\
                  0x2222222222222222222222222222222222222222222222222222222222222222";

    // Invoke the compiled wallet binary (Cargo exposes this path to integration tests)
    let exe = env!("CARGO_BIN_EXE_wallet");
    let out = Command::new(exe)
        .args([
            "prove-bridge",
            "--height",
            &height.to_string(),
            "--leaf",
            leaf,
            "--root",
            root,
            "--branch",
            branch,
            "--header",
            &hdr_path.to_string_lossy(),
            "--out-dir",
            "proof/bridge",
        ])
        .output()
        .expect("wallet prove-bridge exec");
    assert!(
        out.status.success(),
        "prove-bridge should succeed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The CLI prints the output filepath on stdout; ensure that file exists and contains our marker
    let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!path_str.is_empty(), "CLI must print output path");
    let proof_json = fs::read_to_string(&path_str).expect("read proof json");
    assert!(proof_json.contains("\"type\":\"EEZO_BRIDGE_PROOF_V1\""));
    assert!(proof_json.contains("\"height\":128"));
}
