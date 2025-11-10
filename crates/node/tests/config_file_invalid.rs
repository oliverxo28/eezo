use std::{fs, path::PathBuf, process::Command};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eezo-node"))
}

#[test]
fn empty_listen_in_file_fails() {
    let td = PathBuf::from("crates/node/target/testdata/config_file_invalid");
    let _ = fs::remove_dir_all(&td);
    fs::create_dir_all(&td).unwrap();
    fs::write(
        td.join("cfg.toml"),
        r#"
        listen = ""
        datadir = "crates/node/target/testdata/tmp"
    "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .arg("--config-file")
        .arg(td.join("cfg.toml"))
        .arg("--listen")
        .arg("127.0.0.1:0") // ensure we don’t fail on bind
        .arg("--datadir")
        .arg(td.join("tmp"))
        .arg("--genesis")
        .arg("crates/node/../genesis.min.json")
        .env("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001")
        .output()
        .unwrap();

    assert!(!out.status.success(), "should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("config: 'listen' cannot be empty"),
        "stderr: {err}"
    );
}
