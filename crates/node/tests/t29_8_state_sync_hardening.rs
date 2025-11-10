use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn bin() -> String {
    env!("CARGO_BIN_EXE_eezo-node").into()
}

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

fn spawn_node(datadir: &str, listen: &str, envs: &[(&str, &str)], args: &[&str]) -> Child {
    let _ = std::fs::remove_dir_all(datadir);

    let mut cmd = Command::new(bin());
    cmd.arg("--datadir").arg(datadir)
        .arg("--listen").arg(listen)
        .args(args)
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().expect("failed to spawn eezo-node")
}

/// 1) Retry/backoff: start CLIENT first; start SERVER later and seed anchor.
/// Client should retry and eventually become ready.
#[test]
fn t29_8_retry_until_server_up() {
    let server_port = 39211u16;
    let server_listen = format!("127.0.0.1:{server_port}");
    let server_base  = format!("http://{server_listen}");

    let client_port = 39212u16;
    let client_listen = format!("127.0.0.1:{client_port}");
    let client_base  = format!("http://{client_listen}");

    let _client = ChildGuard(Some(spawn_node(
        "t29_8-retry-client",
        &client_listen,
        &[
            ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
            ("EEZO_BOOTSTRAP_URL", &server_base),
            ("EEZO_BOOTSTRAP_PAGE_LIMIT", "48"),
            ("EEZO_SYNC_RESUME", "true"),
            ("EEZO_SYNC_BACKOFF_MS", "150"),
            ("EEZO_SYNC_BACKOFF_CAP_MS", "1200"),
            ("EEZO_SYNC_MAX_RETRIES", "20"),
            ("EEZO_SYNC_BOOTSTRAP_TIMEOUT_MS", "0"),
        ],
        &[],
    )));

    assert!(wait_http_ok(&format!("{client_base}/health"), 15_000));

    // Start server after a short delay to force client retries
    sleep(Duration::from_millis(900));
    let _server = ChildGuard(Some(spawn_node(
        "t29_8-retry-server",
        &server_listen,
        &[("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001")],
        &[],
    )));
    assert!(wait_http_ok(&format!("{server_base}/health"), 15_000));

    // Seed anchor
    {
        let client = reqwest::blocking::Client::new();
        let r = client.get(format!("{server_base}/_admin/seed_anchor")).send().unwrap();
        assert!(r.status().is_success(), "seed_anchor failed: {}", r.status());
        let a = client.get(format!("{server_base}/state/anchor")).send().unwrap();
        assert!(a.status().is_success(), "anchor not available after seed");
    }

    // Client should flip ready -> 200
    assert!(wait_http_ok(&format!("{client_base}/ready"), 25_000));
}

/// 2) Watchdog timeout: dead endpoint + small watchdog keeps node unready.
#[test]
fn t29_8_watchdog_timeout_leaves_unready() {
    let client_port = 39222u16;
    let client_listen = format!("127.0.0.1:{client_port}");
    let client_base  = format!("http://{client_listen}");

    let _client = ChildGuard(Some(spawn_node(
        "t29_8-watchdog-client",
        &client_listen,
        &[
            ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
            ("EEZO_BOOTSTRAP_URL", "http://127.0.0.1:39999"),
            ("EEZO_SYNC_BOOTSTRAP_TIMEOUT_MS", "1500"),
            ("EEZO_SYNC_BACKOFF_MS", "100"),
            ("EEZO_SYNC_BACKOFF_CAP_MS", "500"),
            ("EEZO_SYNC_MAX_RETRIES", "50"),
        ],
        &[],
    )));

    assert!(wait_http_ok(&format!("{client_base}/health"), 10_000));

    // /ready should not become 200 within a reasonable window
    let start = Instant::now();
    let http = reqwest::blocking::Client::new();
    let mut ok_seen = false;
    while start.elapsed() < Duration::from_millis(4000) {
        if let Ok(r) = http.get(format!("{client_base}/ready")).send() {
            if r.status().is_success() {
                ok_seen = true;
                break;
            }
        }
        sleep(Duration::from_millis(200));
    }
    assert!(!ok_seen, "client became ready despite watchdog timeout");
}

/// 3) 404 (no anchor) is NOT retried: client stays unready.
#[test]
fn t29_8_notfound_is_not_retried() {
    let server_port = 39231u16;
    let server_listen = format!("127.0.0.1:{server_port}");
    let server_base  = format!("http://{server_listen}");

    let client_port = 39232u16;
    let client_listen = format!("127.0.0.1:{client_port}");
    let client_base  = format!("http://{client_listen}");

    let _server = ChildGuard(Some(spawn_node(
        "t29_8-404-server",
        &server_listen,
        &[("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001")],
        &[],
    )));
    assert!(wait_http_ok(&format!("{server_base}/health"), 15_000));

    // Do NOT seed anchor

    let _client = ChildGuard(Some(spawn_node(
        "t29_8-404-client",
        &client_listen,
        &[
            ("EEZO_CHAIN_ID", "0000000000000000000000000000000000000001"),
            ("EEZO_BOOTSTRAP_URL", &server_base),
            ("EEZO_SYNC_BACKOFF_MS", "100"),
            ("EEZO_SYNC_BACKOFF_CAP_MS", "500"),
            ("EEZO_SYNC_MAX_RETRIES", "10"),
            ("EEZO_SYNC_BOOTSTRAP_TIMEOUT_MS", "0"),
        ],
        &[],
    )));
    assert!(wait_http_ok(&format!("{client_base}/health"), 10_000));

    // /ready should remain 503 (404 should not be retried)
    let start = Instant::now();
    let http = reqwest::blocking::Client::new();
    let mut ok_seen = false;
    while start.elapsed() < Duration::from_millis(4000) {
        if let Ok(r) = http.get(format!("{client_base}/ready")).send() {
            if r.status().is_success() {
                ok_seen = true;
                break;
            }
        }
        sleep(Duration::from_millis(200));
    }
    assert!(!ok_seen, "client became ready without an anchor (404 must not be retried)");
}
