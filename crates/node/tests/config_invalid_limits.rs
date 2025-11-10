use std::fs;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_eezo-node")
}

fn td(name: &str) -> String {
    let p = format!("crates/node/target/testdata/{}", name);
    let _ = fs::create_dir_all(&p);
    p
}

fn cmd_base(testname: &str) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_remove("RUST_LOG");
    cmd.env("EEZO_LISTEN", "127.0.0.1:0");
    cmd.env("EEZO_DATADIR", td(testname));
    // Provide a valid chain id so we exercise the limit checks (and not fail earlier).
    cmd.env("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001");
    cmd
}

#[test]
fn max_block_bytes_too_small_fails_fast() {
    let mut cmd = cmd_base("invalid_limit_small");
    // Below lower bound (1 << 10)
    cmd.env("EEZO_MAX_BLOCK_BYTES", "100");

    let out = cmd.output().expect("failed to spawn eezo-node");
    assert!(
        !out.status.success(),
        "node should fail fast for too-small EEZO_MAX_BLOCK_BYTES"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("EEZO_MAX_BLOCK_BYTES out of range") || stderr.contains("out of range"),
        "stderr did not mention out-of-range.\nstderr:\n{}",
        stderr
    );
}

#[test]
fn max_block_bytes_too_large_fails_fast() {
    let mut cmd = cmd_base("invalid_limit_large");
    // Above upper bound (64 << 20) => choose something larger than 64MiB
    cmd.env(
        "EEZO_MAX_BLOCK_BYTES",
        format!("{}", (64u64 << 20) + 1).as_str(),
    );

    let out = cmd.output().expect("failed to spawn eezo-node");
    assert!(
        !out.status.success(),
        "node should fail fast for too-large EEZO_MAX_BLOCK_BYTES"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("EEZO_MAX_BLOCK_BYTES out of range") || stderr.contains("out of range"),
        "stderr did not mention out-of-range.\nstderr:\n{}",
        stderr
    );
}

#[test]
fn max_block_bytes_non_integer_fails_fast() {
    let mut cmd = cmd_base("invalid_limit_nonint");
    cmd.env("EEZO_MAX_BLOCK_BYTES", "ten-megabytes");

    let out = cmd.output().expect("failed to spawn eezo-node");
    assert!(
        !out.status.success(),
        "node should fail fast for non-integer EEZO_MAX_BLOCK_BYTES"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("EEZO_MAX_BLOCK_BYTES must be an integer"),
        "stderr did not mention integer requirement.\nstderr:\n{}",
        stderr
    );
}
