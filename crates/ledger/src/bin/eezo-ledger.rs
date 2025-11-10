// eezo-ledger: tiny helper to stage a crypto-suite rotation via env vars.
// Usage examples:
//   eezo-ledger show
//   eezo-ledger schedule --next-suite 2 --dual-until 12345
//   eezo-ledger activate --suite 2
//   eezo-ledger schedule --next-suite 2 --dual-until 12345 --write-env ./rotation.env

use std::{fs, io::Write, path::PathBuf};

#[derive(Debug, Clone, Copy)]
enum Cmd {
    Show,
    Schedule,
    Activate,
}

#[derive(Debug)]
struct Args {
    cmd: Cmd,
    suite: Option<u8>,
    next_suite: Option<u8>,
    dual_until: Option<u64>,
    write_env: Option<PathBuf>,
}

fn parse_args() -> Args {
    // ultra-light parser (avoids adding a new dependency). Flags:
    //   show
    //   schedule --next-suite <u8> [--dual-until <u64>] [--write-env <path>]
    //   activate --suite <u8> [--write-env <path>]
    let mut it = std::env::args().skip(1);
    let cmd = match it.next().as_deref() {
        Some("show") => Cmd::Show,
        Some("schedule") => Cmd::Schedule,
        Some("activate") => Cmd::Activate,
        other => {
            eprintln!("Usage:
  eezo-ledger show
  eezo-ledger schedule --next-suite <u8> [--dual-until <u64>] [--write-env <path>]
  eezo-ledger activate --suite <u8> [--write-env <path>]");
            std::process::exit(if other.is_none() {0} else {2});
        }
    };

    let mut suite = None;
    let mut next_suite = None;
    let mut dual_until = None;
    let mut write_env = None;

    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--suite" => {
                suite = it.next().and_then(|s| s.parse::<u8>().ok());
            }
            "--next-suite" => {
                next_suite = it.next().and_then(|s| s.parse::<u8>().ok());
            }
            "--dual-until" => {
                dual_until = it.next().and_then(|s| s.parse::<u64>().ok());
            }
            "--write-env" => {
                write_env = it.next().map(PathBuf::from);
            }
            _ => {
                eprintln!("Unknown flag: {flag}");
                std::process::exit(2);
            }
        }
    }

    Args { cmd, suite, next_suite, dual_until, write_env }
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();

    match args.cmd {
        Cmd::Show => {
            let active = std::env::var("EEZO_ACTIVE_SUITE").unwrap_or_else(|_| "1".into());
            let next = std::env::var("EEZO_NEXT_SUITE").unwrap_or_else(|_| "".into());
            let until = std::env::var("EEZO_DUAL_ACCEPT_UNTIL").unwrap_or_else(|_| "".into());

            println!("Current policy:");
            println!("  EEZO_ACTIVE_SUITE={}", active);
            println!("  EEZO_NEXT_SUITE={}", if next.is_empty() { "(empty)" } else { &next });
            println!("  EEZO_DUAL_ACCEPT_UNTIL={}", if until.is_empty() { "(empty)" } else { &until });
        }

        Cmd::Schedule => {
            let next = args.next_suite.expect("--next-suite <u8> is required");
            if next == 0 { anyhow::bail!("suite id must be >= 1"); }
            if next > 2 { anyhow::bail!("unsupported suite id {next} (expected 1..=2)"); }
            if let Some(0) = args.dual_until { anyhow::bail!("--dual-until must be > 0 or omitted"); }
            let env_blob = format!(
                "EEZO_NEXT_SUITE={}\nEEZO_DUAL_ACCEPT_UNTIL={}\n",
                next,
                args.dual_until.map(|v| v.to_string()).unwrap_or_default()
            );

            println!("# Staged rotation (restart node with these set):");
            print!("{}", env_blob);

            if let Some(path) = args.write_env {
                let mut f = fs::File::create(&path)?;
                f.write_all(env_blob.as_bytes())?;
                println!("# Wrote {}", path.display());
            }
            // NOTE: Metrics counter (EEZO_SUITE_ROTATION_total) is bumped inside the node
            // when it _applies_ a new policy; this CLI only stages values.
        }

        Cmd::Activate => {
            let suite = args.suite.expect("--suite <u8> is required");
            if suite == 0 { anyhow::bail!("suite id must be >= 1"); }
            if suite > 2 { anyhow::bail!("unsupported suite id {suite} (expected 1..=2)"); }
            let env_blob = format!(
                "EEZO_ACTIVE_SUITE={}\nEEZO_NEXT_SUITE=\nEEZO_DUAL_ACCEPT_UNTIL=\n",
                suite
            );

            println!("# Activate new suite (restart node with these set):");
            print!("{}", env_blob);

            if let Some(path) = args.write_env {
                let mut f = fs::File::create(&path)?;
                f.write_all(env_blob.as_bytes())?;
                println!("# Wrote {}", path.display());
            }
        }
    }

    Ok(())
}
