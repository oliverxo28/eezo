use std::env;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

/// A guard to ensure the child process is killed when the guard is dropped.
struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Path to the compiled node binary for this test run.
fn bin() -> String {
    env!("CARGO_BIN_EXE_eezo-node").into()
}

/// Poll a URL until it returns a 2xx status.
fn wait_http_ok(url: &str, timeout_ms: u64) -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(800))
        .build()
        .unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(timeout_ms) {
        if let Ok(resp) = client.get(url).send() {
            if resp.status().is_success() {
                return true;
            }
        }
        sleep(Duration::from_millis(200));
    }
    false
}

/// Spawn a node and continuously collect stdout/stderr into a shared buffer.
fn spawn_node_with_logs(
    datadir: &str,
    listen: &str,
    envs: &[(&str, &str)],
    args: &[&str],
    name: &str,
) -> (Child, Arc<Mutex<String>>) {
    // Clean residual data from previous runs of this test.
    let _ = std::fs::remove_dir_all(datadir);

    let mut cmd = Command::new(bin());
    cmd.arg("--datadir")
        .arg(datadir)
        .arg("--listen")
        .arg(listen)
        .args(args)
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn eezo-node");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr = child.stderr.take().expect("child stderr");

    let buf = Arc::new(Mutex::new(String::new()));

    // Copy stdout
    {
        let buf = Arc::clone(&buf);
        let name = name.to_string();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("{} STDOUT: {}", name, line);
                    let mut s = buf.lock().unwrap();
                    s.push_str(&line);
                    s.push('\n');
                }
            }
        });
    }

    // Copy stderr
    {
        let buf = Arc::clone(&buf);
        let name = name.to_string();
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{} STDERR: {}", name, line);
                    let mut s = buf.lock().unwrap();
                    s.push_str(&line);
                    s.push('\n');
                }
            }
        });
    }

    (child, buf)
}

#[test]
fn flags_override_env_and_readiness_flips() {
    // ── Step 1: Start SERVER node (no bootstrap) ─────────────
    let server_port = 39111u16;
    let server_datadir = "test-ops-server";
    let server_listen = format!("127.0.0.1:{server_port}");
    let server_base = format!("http://{server_listen}");

    let (server_child, _server_logs) = spawn_node_with_logs(
        server_datadir,
        &server_listen,
        &[("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001")],
        &[],
        "SERVER",
    );
    let _server = ChildGuard(Some(server_child));

    assert!(
        wait_http_ok(&format!("{server_base}/health"), 15_000),
        "Server /health endpoint never became available"
    );

    // Seed a dev-only checkpoint anchor and verify /state/anchor is now available.
    {
        let client = reqwest::blocking::Client::new();
        let seed_resp = client
            .get(format!("{server_base}/_admin/seed_anchor"))
            .send()
            .expect("seed_anchor request failed");
        assert!(
            seed_resp.status().is_success(),
            "failed to seed anchor on server: {}",
            seed_resp.status()
        );

        let anchor_resp = client
            .get(format!("{server_base}/state/anchor"))
            .send()
            .expect("anchor GET failed");
        assert!(
            anchor_resp.status().is_success(),
            "/state/anchor still not available after seeding: {}",
            anchor_resp.status()
        );
    }

    // ── Step 2: Start CLIENT node with bootstrap; CLI overrides env ─────────
    let client_port = 39112u16;
    let client_datadir = "test-ops-client";
    let client_listen = format!("127.0.0.1:{client_port}");
    let client_base = format!("http://{client_listen}");

    // Env sets page limit to 16 (losing), resume=true (works with either flag style).
    // CLI sets page limit to 48 (winning). We do NOT pass --sync-resume on CLI to
    // avoid the "unexpected argument 'true'" case when the binary uses SetTrue.
    let (client_child, client_logs) = spawn_node_with_logs(
        client_datadir,
        &client_listen,
        &[
            ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
            ("EEZO_BOOTSTRAP_URL", &server_base),
            ("EEZO_BOOTSTRAP_PAGE_LIMIT", "16"), // should be overridden by CLI 48
            ("EEZO_SYNC_RESUME", "true"),        // set via env only (compatible either way)
        ],
        &["--bootstrap-page-limit", "48"],
        "CLIENT",
    );
    let _client = ChildGuard(Some(client_child));

    // Health must come up quickly.
    assert!(
        wait_http_ok(&format!("{client_base}/health"), 15_000),
        "Client /health endpoint never became available"
    );

    // Ready should flip to 200 after bootstrap completes.
    assert!(
        wait_http_ok(&format!("{client_base}/ready"), 25_000),
        "Client /ready endpoint never flipped to 200 OK"
    );

    // ── Step 3: Assert CLI-overrides-env via client logs ─────────────────────
    // state_sync.rs logs on startup:
    //   "bootstrap: starting process with config: base_url=..., page_limit=48, delta_span=..."
    let logs = client_logs.lock().unwrap().to_string();
    assert!(
        logs.contains("bootstrap: starting process with config:")
            && logs.contains("page_limit=48"),
        "Expected client logs to show page_limit=48 from CLI override.\n--- CLIENT LOGS ---\n{}",
        logs
    );
    assert!(
        !logs.contains("page_limit=16"),
        "Logs show page_limit=16 (env) was used, but CLI should override.\n--- CLIENT LOGS ---\n{}",
        logs
    );

    // Cleanup data directories (processes are killed by guards).
    let _ = std::fs::remove_dir_all(client_datadir);
    let _ = std::fs::remove_dir_all(server_datadir);
}
