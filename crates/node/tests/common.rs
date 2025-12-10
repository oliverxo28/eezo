use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Internal spawn helper for normal and fail-fast test cases.
/// `panic_on_early_exit`: if true (default for most tests), panic if the node dies on startup. If false, allow early exit for fail-fast tests.
/// Path to the repo's genesis file, resolved at compile time.
#[allow(dead_code)]
pub const GENESIS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../genesis.min.json");

// Use the already-built binary for this test profile.
const BIN: &str = env!("CARGO_BIN_EXE_eezo-node");

fn wait_for_port(addr: &str, attempts: u32, sleep_ms: u64) -> bool {
    for _ in 0..attempts {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        sleep(Duration::from_millis(sleep_ms));
    }
    false
}

pub fn spawn_with_opts(
    args: &[&str],
    envs: &[(&str, &str)],
    panic_on_early_exit: bool,
) -> ChildGuard {
    // Use the pre-compiled binary directly (more efficient than cargo run)
    let mut cmd = Command::new(BIN);

    // Ensure the child runs in the `crates/node` directory so relative paths line up
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.args(args);
    cmd.envs(envs.iter().map(|(k, v)| (k, v)));
    // If PATH is needed (especially if you ever use env_clear()), restore it
    if let Some(path) = std::env::var_os("PATH") {
		cmd.env("PATH", path);
	}     
    // --- Begin: ensure node has a chain-id in tests ---
    // Only set a default if the caller (or environment) didn't already provide it.
    let has_chain_in_args = envs.iter().any(|(k, _)| *k == "EEZO_CHAIN_ID");
    let has_chain_in_env = std::env::var("EEZO_CHAIN_ID").is_ok();
    if !has_chain_in_args && !has_chain_in_env {
        // Fixed, known-good chain ID for tests
        cmd.env("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001");
    }
    // --- End: ensure node has a chain-id in tests ---
    
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn node");

    eprintln!("Spawned node with PID: {}", child.id());
	// This removes races where the test polls /ready before the node reports 200.
	std::thread::sleep(std::time::Duration::from_millis(500));

    // Extract the listen address from args to wait for port
    let listen_addr = extract_listen_addr(args);
    
    // If we have a listen address, wait for the port to be available
    if let Some(addr) = listen_addr {
        if !wait_for_port(&addr, 180, 100) {
            if panic_on_early_exit {
                let mut g = ChildGuard::new(child, extract_datadir(args));
                eprintln!("Node did not open its port in time: {}", addr);
                eprintln!("Node stdout:\n{}", g.read_stdout());
                eprintln!("Node stderr:\n{}", g.read_stderr());
                panic!("Node at {} did not open its port in time", addr);
            }
            // if it never came up, make the failure obvious and avoid zombies
            let _ = child.kill();
            return ChildGuard::new(child, extract_datadir(args));
        }
    }

    // Give the process a moment to exit if it's going to crash or fail fast.
    sleep(Duration::from_millis(1500));
    if let Ok(Some(status)) = child.try_wait() {
        if panic_on_early_exit {
            let mut g = ChildGuard::new(child, extract_datadir(args));
            eprintln!("Node exited early with status: {:?}", status);
            eprintln!("Node stdout:\n{}", g.read_stdout());
            eprintln!("Node stderr:\n{}", g.read_stderr());
            panic!(
                "Node process crashed during startup with status: {:?}",
                status
            );
        }
        // allow tests to handle early exit
        return ChildGuard::new(child, extract_datadir(args));
    }

    ChildGuard::new(child, extract_datadir(args))
}

fn extract_datadir(args: &[&str]) -> String {
    args.windows(2)
        .find(|w| w[0] == "--datadir")
        .map(|w| w[1].to_string())
        .unwrap_or_else(|| "unknown-datadir".to_string())
}

fn extract_listen_addr(args: &[&str]) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == "--listen")
        .map(|w| format!("127.0.0.1:{}", w[1].split(':').next_back().unwrap_or(w[1])))
}

/// Spawn eezo-node directly using the compiled binary (default: panic if early exit).
#[allow(dead_code)]
pub fn spawn_node(datadir: &str, listen_addr: &str, extra_args: &[&str]) -> ChildGuard {
    let mut args = vec!["--datadir", datadir, "--listen", listen_addr];
    args.extend(extra_args);
    spawn_with_opts(&args, &[], true)
}

/// Env-aware variant used by TLS/state-sync tests.
#[allow(dead_code)]
pub fn spawn_node_env(
    datadir: &str,
    listen_addr: &str,
    envs: &[(&str, &str)],
    extra_args: &[&str],
) -> ChildGuard {
    let mut args = vec!["--datadir", datadir, "--listen", listen_addr];
    args.extend(extra_args);
    spawn_with_opts(&args, envs, true)
}

/// Normal spawn (panics on early exit)
#[allow(dead_code)]
pub fn spawn_node_with(node_args: &[&str]) -> ChildGuard {
    spawn_with_opts(node_args, &[], true)
}

#[allow(dead_code)]
pub fn unique_test_datadir(prefix: &str, port: u16) -> String {
    format!("test-{}-{}", prefix, port)
}

/// Spawn with env (default: panic if early exit)
pub fn spawn_node_with_env(node_args: &[&str], env_vars: &[(&str, &str)]) -> ChildGuard {
    spawn_with_opts(node_args, env_vars, true)
}

/// Helper for fail-fast tests (do NOT panic on early exit; let test assert exit status)
#[allow(dead_code)]
pub fn spawn_node_for_failfast(node_args: &[&str], env: &[(&str, &str)]) -> ChildGuard {
    spawn_with_opts(node_args, env, false)
}

/// Spawn a node on a specific port with auto-generated datadir
#[allow(dead_code)]
pub fn spawn_node_on_port(port: u16) -> ChildGuard {
    let datadir = unique_test_datadir("http-neg", port);
    spawn_node(&datadir, &format!("127.0.0.1:{}", port), &[])
}

/// Get a free port by binding to port 0
#[allow(dead_code)]
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Wait until a condition is true, with retries and delay
#[allow(dead_code)]
pub fn wait_until<F>(condition: F, max_attempts: usize, delay: Duration) -> bool
where
    F: Fn() -> bool,
{
    for _ in 0..max_attempts {
        if condition() {
            return true;
        }
        sleep(delay);
    }
    false
}

/// --- Added for auto_cluster_quorum.rs: Block until we see the expected HTTP status on a URL ---
#[allow(dead_code)]
pub fn wait_for_status_blocking(
    client: &reqwest::blocking::Client,
    url: &str,
    expected_status: u16,
    max_attempts: usize,
    delay_ms: u64,
) {
    for _ in 0..max_attempts {
        if let Ok(resp) = client.get(url).send() {
            if resp.status().as_u16() == expected_status {
                return;
            }
        }
        sleep(Duration::from_millis(delay_ms));
    }
    panic!(
        "Did not get status {} from {} after {} tries",
        expected_status, url, max_attempts
    );
}

/// --- Added for auto_cluster_quorum.rs: Wait until a closure returns true, polling/blocking ---
#[allow(dead_code)]
pub fn wait_until_blocking<F: Fn() -> bool>(
    predicate: F,
    max_attempts: usize,
    delay: Duration,
) -> bool {
    for _ in 0..max_attempts {
        if predicate() {
            return true;
        }
        sleep(delay);
    }
    false
}

/// Run eezo-node and capture its output without panicking on non-zero exit.
/// Useful for tests that expect the node to fail.
#[allow(dead_code)]
pub fn run_node_and_capture(node_args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let mut cmd = Command::new(BIN);

    // Ensure the child runs in the `crates/node` directory so relative paths line up
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.args(node_args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let child = cmd.spawn().expect("failed to spawn node");
    let output = child.wait_with_output().expect("failed to wait for node");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (output.status, stdout, stderr)
}

/// Poll /ready on the given port until success or timeout (milliseconds).
#[allow(dead_code)]
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

/// Poll /peers on the given port until expected count or timeout (milliseconds).
/// Returns true if the expected number of peers is found within timeout.
#[allow(dead_code)]
pub fn wait_until_peers_count(port: u16, expected_count: usize, timeout_ms: u64) -> bool {
    let start = Instant::now();
    let url = format!("http://127.0.0.1:{}/peers", port);
    println!(
        "Polling peers at: {}, expecting {} peers",
        url, expected_count
    );

    while start.elapsed() < Duration::from_millis(timeout_ms) {
        match reqwest::blocking::get(&url) {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(peers) = resp.json::<Vec<serde_json::Value>>() {
                        println!("Found {} peers", peers.len());
                        if peers.len() == expected_count {
                            return true;
                        }
                    }
                }
            }
            Err(e) => {
                println!("Request to /peers failed: {}", e);
            }
        }
        sleep(Duration::from_millis(200));
    }

    println!(
        "Timeout reached: did not find {} peers within {} ms",
        expected_count, timeout_ms
    );
    false
}

/// Poll /metrics on the given port until expected metric value or timeout.
/// Returns true if the metric matches expected value within timeout.
#[allow(dead_code)]
pub fn wait_until_metric_value(
    port: u16,
    metric_name: &str,
    expected_value: i64,
    timeout_ms: u64,
) -> bool {
    let start = Instant::now();
    let url = format!("http://127.0.0.1:{}/metrics", port);
    println!(
        "Polling metrics at: {}, expecting {} = {}",
        url, metric_name, expected_value
    );

    while start.elapsed() < Duration::from_millis(timeout_ms) {
        match reqwest::blocking::get(&url) {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text() {
                        for line in text.lines() {
                            if line.starts_with(metric_name) && !line.starts_with('#') {
                                if let Some(value_str) = line.split_whitespace().last() {
                                    if let Ok(value) = value_str.parse::<i64>() {
                                        println!("Found {} = {}", metric_name, value);
                                        if value == expected_value {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Request to /metrics failed: {}", e);
            }
        }
        sleep(Duration::from_millis(200));
    }

    println!(
        "Timeout reached: {} did not reach {} within {} ms",
        metric_name, expected_value, timeout_ms
    );
    false
}

/// Get the current value of a metric. Returns None if not found.
#[allow(dead_code)]
pub fn get_metric_value(port: u16, metric_name: &str) -> Option<i64> {
    let url = format!("http://127.0.0.1:{}/metrics", port);
    
    let resp = reqwest::blocking::get(&url).ok()?;
    if !resp.status().is_success() {
        return None;
    }
    
    let text = resp.text().ok()?;
    for line in text.lines() {
        // Match exact metric name (followed by space or end of line)
        // e.g., "eezo_txs_included_total 42" should match "eezo_txs_included_total"
        if !line.starts_with('#') && line.starts_with(metric_name) {
            let after_name = &line[metric_name.len()..];
            // Ensure the next char is whitespace or nothing (exact match)
            if after_name.is_empty() || after_name.starts_with(' ') || after_name.starts_with('{') {
                // Handle labeled metrics like foo{label="value"} 123
                let value_str = if after_name.contains('}') {
                    after_name.split('}').nth(1)?.split_whitespace().next()?
                } else {
                    after_name.split_whitespace().next()?
                };
                return value_str.parse().ok();
            }
        }
    }
    None
}

/// Poll /metrics on the given port until metric value >= expected, or timeout.
/// Returns true if the metric reaches or exceeds the expected value within timeout.
#[allow(dead_code)]
pub fn wait_until_metric_gte(
    port: u16,
    metric_name: &str,
    min_value: i64,
    timeout_ms: u64,
) -> bool {
    let start = Instant::now();
    println!(
        "Polling metrics at port {}, expecting {} >= {}",
        port, metric_name, min_value
    );

    while start.elapsed() < Duration::from_millis(timeout_ms) {
        if let Some(value) = get_metric_value(port, metric_name) {
            println!("Found {} = {}", metric_name, value);
            if value >= min_value {
                return true;
            }
        }
        sleep(Duration::from_millis(200));
    }

    println!(
        "Timeout reached: {} did not reach >= {} within {} ms",
        metric_name, min_value, timeout_ms
    );
    false
}

/// Poll /metrics on the given port until metric value > 0, or timeout.
/// Returns true if the metric is greater than 0 within timeout.
#[allow(dead_code)]
pub fn wait_until_metric_gt_zero(
    port: u16,
    metric_name: &str,
    timeout_ms: u64,
) -> bool {
    wait_until_metric_gte(port, metric_name, 1, timeout_ms)
}

#[allow(dead_code)]
pub fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Helper function to kill a ChildGuard (wrapper around Child)
#[allow(dead_code)]
pub fn kill_child_guard(guard: &mut ChildGuard) {
    let _ = guard.child.kill();
    let _ = guard.child.wait();
}

/// Helper function to read stdout from a child process.
/// If the child is still alive, return empty string to avoid blocking.
#[allow(dead_code)]
pub fn read_stdout(child: &mut Child) -> String {
    use std::io::Read;
    let mut output = String::new();
    if child.try_wait().ok().flatten().is_none() {
        // Child still running, don't block
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
        // Child still running, don't block
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

/// Compose EEZO_PEERS as comma-separated base URLs from ports.
/// Example: [18001,18002] -> "http://127.0.0.1:18001,http://127.0.0.1:18002"
#[allow(dead_code)]
pub fn peers_env_from_ports(ports: &[u16]) -> (String, String) {
    let list = ports
        .iter()
        .map(|p| format!("http://127.0.0.1:{p}"))
        .collect::<Vec<_>>()
        .join(",");
    ("EEZO_PEERS".to_string(), list)
}

/// Spawn a node with EEZO_PEERS set from the given ports.
/// This is just a convenience wrapper around your existing spawn_node_with_env.
#[allow(dead_code)]
pub fn spawn_node_with_peers(
    node_args: &[&str],
    _port: u16,
    peer_ports: &[u16],
    extra_env: &[(&str, &str)],
) -> ChildGuard {
    let (k, v) = peers_env_from_ports(peer_ports);
    // Merge env: [EEZO_PEERS] + extra_env
    let mut kvs = vec![(k.as_str(), v.as_str())];
    for (ek, ev) in extra_env {
        kvs.push((ek, ev));
    }
    spawn_node_with_env(node_args, &kvs)
}

/// Guard struct to ensure cleanup of child process and datadir
pub struct ChildGuard {
    child: std::process::Child,
    datadir: String,
}

impl ChildGuard {
    #[allow(dead_code)]
    pub fn new(child: std::process::Child, datadir: String) -> Self {
        Self { child, datadir }
    }

    /// Get a mutable reference to the child process
    #[allow(dead_code)]
    pub fn child(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Kill the child process
    #[allow(dead_code)]
    pub fn kill(&mut self) {
        let _ = self.child.kill();
    }

    #[allow(dead_code)]
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    pub fn read_stderr(&mut self) -> String {
        read_stderr(&mut self.child)
    }

    /// Block until the child exits (wrapper so tests can call child.wait()).
    #[allow(dead_code)]
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }

    /// Read and return all currently available stdout (wrapper used by several tests).
    pub fn read_stdout(&mut self) -> String {
        read_stdout(&mut self.child)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Kill the child process
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Clean up the datadir
        let _ = std::fs::remove_dir_all(&self.datadir);
        println!("Cleaned up datadir: {}", self.datadir);
    }
}