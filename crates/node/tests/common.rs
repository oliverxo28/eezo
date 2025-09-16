use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Spawn eezo-node directly using the compiled binary.
/// Pass only node args in `node_args`, e.g. &["--listen", "127.0.0.1:18080"].
#[allow(dead_code)]
pub fn spawn_node(node_args: &[&str]) -> Child {
    spawn_node_with_env(node_args, &[])
}

#[allow(dead_code)]
pub fn spawn_node_with(node_args: &[&str]) -> Child {
    spawn_node_with_env(node_args, &[])
}

/// Same as above, but also injects environment variables into the child.
/// Uses the compiled binary instead of `cargo run` for faster, less flaky tests.
pub fn spawn_node_with_env(node_args: &[&str], env_vars: &[(&str, &str)]) -> Child {
    // Use the built binary directly
    let bin_path = env!("CARGO_BIN_EXE_eezo-node");
    let mut cmd = Command::new(bin_path);

    // Run in the eezo-node crate dir so relative paths in tests line up
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.args(node_args);

    // Pass environment variables to the child process
    cmd.envs(env_vars.iter().cloned());

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd.spawn().expect("failed to spawn node")
}

/// Poll /ready on the given port until success or timeout (milliseconds).
/// Uses short per-request timeouts to avoid long hangs.
pub fn wait_until_ready(port: u16, timeout_ms: u64) -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(800)) // short per-try timeout
        .build()
        .expect("build client");

    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(timeout_ms) {
        let url = format!("http://127.0.0.1:{}/ready", port);
        if let Ok(resp) = client.get(&url).send() {
            if resp.status().is_success() {
                return true;
            }
        }
        sleep(Duration::from_millis(100));
    }
    false
}

/// Kill a child process and wait for it to exit (best-effort).
#[allow(dead_code)]
pub fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Read stdout from a child process (best-effort).
#[allow(dead_code)]
pub fn read_stdout(child: &mut Child) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    out
}

/// Read stderr from a child process (best-effort).
#[allow(dead_code)]
pub fn read_stderr(child: &mut Child) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut out);
    }
    out
}

/// Capture both stdout and stderr (best-effort).
#[allow(dead_code)]
pub fn get_child_output(child: &mut Child) -> (String, String) {
    let stdout = read_stdout(child);
    let stderr = read_stderr(child);
    (stdout, stderr)
}
