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
/// This now uses the compiled binary directly instead of cargo run.
pub fn spawn_node_with_env(node_args: &[&str], env_vars: &[(&str, &str)]) -> Child {
    // Use the built binary directly instead of cargo run
    let bin_path = env!("CARGO_BIN_EXE_eezo-node");
    let mut cmd = Command::new(bin_path);

    // Ensure the child runs in the `crates/node` directory so relative paths line up
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.args(node_args);

    // Set environment variables for the child process
    cmd.envs(env_vars.iter().copied());

    cmd.stdout(Stdio::piped())
       .stderr(Stdio::piped());

    cmd.spawn().expect("failed to spawn node")
}

/// Poll /ready on the given port until success or timeout (milliseconds).
pub fn wait_until_ready(port: u16, timeout_ms: u64) -> bool {
    let start = Instant::now();
    let url = format!("http://127.0.0.1:{}/ready", port);
    println!("Polling readiness at: {}", url);

    while start.elapsed() < Duration::from_millis(timeout_ms) {
        match reqwest::blocking::get(&url) {
            Ok(resp) => {
                println!("Received status: {}", resp.status());
                if resp.status().is_success() {
                    return true;
                }
            }
            Err(e) => {
                println!("Request to /ready failed: {}", e);
            }
        }
        sleep(Duration::from_millis(100));
    }

    println!(
        "Timeout reached: node did not respond at /ready within {} ms",
        timeout_ms
    );
    false
}

/// Helper function to kill a child process and wait for it to exit
#[allow(dead_code)]
pub fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Helper function to read stdout from a child process.
/// If the child is still alive, return empty string to avoid blocking.
#[allow(dead_code)]
pub fn read_stdout(child: &mut Child) -> String {
    use std::io::Read;
    let mut output = String::new();

    if child.try_wait().ok().flatten().is_none() {
        // Child still running, don’t block
        return output;
    }

    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut output);
    }
    output
}

/// Helper function to read stderr from a child process.
/// If the child is still alive, return empty string to avoid blocking.
#[allow(dead_code)]
pub fn read_stderr(child: &mut Child) -> String {
    use std::io::Read;
    let mut output = String::new();

    if child.try_wait().ok().flatten().is_none() {
        // Child still running, don’t block
        return output;
    }

    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut output);
    }
    output
}

/// Helper function to get the full output (stdout + stderr) from a child process
#[allow(dead_code)]
pub fn get_child_output(child: &mut Child) -> (String, String) {
    let stdout = read_stdout(child);
    let stderr = read_stderr(child);
    (stdout, stderr)
}
