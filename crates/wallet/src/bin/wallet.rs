use clap::{Parser, Subcommand};
use eezo_wallet::{
    cmd_address, cmd_balance, cmd_new_ex, cmd_pubkey, cmd_send, cmd_sign, cmd_verify,
};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "wallet", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet (keypair in keystore)
    New {
        /// Output keystore path
        #[arg(long, default_value = "keystore.json")]
        out: String,
        /// Provide password on the command line (unsafe for shared shells)
        #[arg(long)]
        password: Option<String>,
        /// Read password from file (first line is used)
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Securely prompt for password (recommended)
        #[arg(long, default_value_t = true)]
        prompt: bool,
        /// Argon2 time cost (iterations)
        #[arg(long, value_name = "N", default_value_t = 3)]
        kdf_time: u32,
        /// Argon2 memory (MiB)
        #[arg(long, value_name = "MiB", default_value_t = 256)]
        kdf_mem_mib: u32,
        /// Argon2 lanes (parallelism)
        #[arg(long, value_name = "N", default_value_t = 1)]
        kdf_lanes: u32,
    },
    /// Query balance of an address
    Balance {
        #[arg(short, long)]
        addr: String,
    },
    /// Send a transfer transaction
    Send {
        #[arg(short = 'f', long)]
        from: String,
        #[arg(short = 't', long)]
        to: String,
        #[arg(short = 'a', long)]
        amount: u128,
        #[arg(short = 'F', long)]
        fee: u64,
        #[arg(short = 'n', long)]
        nonce: Option<u64>,
    },
    /// Sign an arbitrary message using the keystore (ML-DSA-44)
    Sign {
        #[arg(long)]
        keystore: String,
        /// Provide password on the command line (unsafe for shared shells)
        #[arg(long)]
        password: Option<String>,
        /// Read password from file (first line is used)
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
        /// Securely prompt for password (recommended)
        #[arg(long, default_value_t = false)]
        prompt: bool,
        #[arg(long)]
        msg: String,
    },
    /// Print the keystore's public key as hex
    Pubkey {
        #[arg(long)]
        keystore: String,
    },
    /// Print the wallet address derived from the keystore's public key
    Address {
        #[arg(long)]
        keystore: String,
    },
    /// Verify a hex signature against the keystore's public key and message
    Verify {
        #[arg(long)]
        keystore: String,
        #[arg(long)]
        msg: String,
        #[arg(long, value_name = "HEX")]
        sig: String,
    },
    /// T33.2: Create a stub "bridge proof" artifact from inputs (no ZK/STARK).
    ///
    /// Writes JSON to proof/bridge/<height>_<leafprefix>.json
    ProveBridge {
        /// Block height this proof refers to
        #[arg(long)]
        height: u64,
        /// 32-byte leaf (0x-prefixed hex) for the bridge mint
        #[arg(long, value_name = "0x...64hex")]
        leaf: String,
        /// Merkle root (0x-prefixed hex)
        #[arg(long, value_name = "0x...64hex")]
        root: String,
        /// Branch as comma-separated 0x32-byte hex siblings (bottom→top)
        #[arg(long, value_name = "0x..,0x..", conflicts_with = "branch_file")]
        branch: Option<String>,
        /// Or: path to a file with one 0x32-byte hex per line
        #[arg(long, value_name = "PATH")]
        branch_file: Option<PathBuf>,
        /// Optional: path to checkpoint header JSON (we won’t parse; embedded verbatim or referenced)
        #[arg(long, value_name = "PATH")]
        header: Option<PathBuf>,
        /// Output directory (default: proof/bridge)
        #[arg(long, value_name = "DIR", default_value = "proof/bridge")]
        out_dir: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::New {
            out,
            password,
            password_file,
            prompt,
            kdf_time,
            kdf_mem_mib,
            kdf_lanes,
        } => {
            let pw_file_str = password_file
                .as_ref()
                .map(|p| p.as_path().to_string_lossy().into_owned());
            cmd_new_ex(
                Some(&out),
                password.as_deref(),
                prompt,
                pw_file_str.as_deref(),
                Some(kdf_time),
                Some(kdf_mem_mib),
                Some(kdf_lanes),
            )?
        }
        Command::Balance { addr } => cmd_balance(&addr)?,
        Command::Send {
            from,
            to,
            amount,
            fee,
            nonce,
        } => cmd_send(&from, &to, amount, fee, nonce)?,
        Command::Sign {
            keystore,
            password,
            password_file,
            prompt,
            msg,
        } => {
            let pw = match (password, password_file, prompt) {
                (Some(p), _, _) => p,
                (None, Some(pf), _) => {
                    let s = fs::read_to_string(pf)?;
                    s.trim_end_matches(&['\r', '\n'][..]).to_owned()
                }
                (None, None, true) => rpassword::prompt_password("Keystore password: ")?,
                (None, None, false) => {
                    anyhow::bail!(
                        "no password provided; pass --password, --password-file, or --prompt"
                    )
                }
            };
            cmd_sign(&keystore, &pw, &msg)?
        }
        Command::Pubkey { keystore } => cmd_pubkey(&keystore)?,
        Command::Address { keystore } => cmd_address(&keystore)?,
        Command::Verify { keystore, msg, sig } => cmd_verify(&keystore, &msg, &sig)?,
        Command::ProveBridge {
            height,
            leaf,
            root,
            branch,
            branch_file,
            header,
            out_dir,
        } => {
            // Normalize inputs
            let leaf_norm = norm_hex32(&leaf)
                .ok_or_else(|| anyhow::anyhow!("invalid --leaf (expect 0x + 64 hex)"))?;
            let root_norm = norm_hex32(&root)
                .ok_or_else(|| anyhow::anyhow!("invalid --root (expect 0x + 64 hex)"))?;

            let siblings = if let Some(bcsv) = branch {
                parse_branch_csv(&bcsv)?
            } else if let Some(p) = branch_file {
                parse_branch_file(&p)?
            } else {
                Vec::new()
            };

            // Prepare JSON string without adding serde deps
            let leaf_short = &leaf_norm[2..10.min(leaf_norm.len())]; // first 8 hex chars after 0x
            let out_path = format!("{}/{}_{}.json", out_dir, height, leaf_short);
            fs::create_dir_all(&out_dir)?;

            let mut header_json_embedded = String::new();
            let mut header_path_field = String::new();
            if let Some(hp) = header {
                let path_str = hp.to_string_lossy().into_owned();
                header_path_field = path_str.clone();
                // Best-effort read; if unreadable, we still write a reference path.
                if let Ok(mut f) = fs::File::open(&hp) {
                    f.read_to_string(&mut header_json_embedded).ok();
                }
            }

            let branch_array_json = if siblings.is_empty() {
                "[]".to_string()
            } else {
                format!("[{}]", siblings.join(","))
            };

            let header_field_json = if header_json_embedded.trim().is_empty() {
                "null".to_string()
            } else {
                header_json_embedded
            };

            let json = format!(
                "{{\
                   \"type\":\"EEZO_BRIDGE_PROOF_V1\",\
                   \"height\":{},\
                   \"leaf\":\"{}\",\
                   \"root\":\"{}\",\
                   \"branch\":{},\
                   \"header_file\":{},\
                   \"header_inline\":{}\
                 }}",
                height,
                leaf_norm,
                root_norm,
                branch_array_json,
                if header_path_field.is_empty() {
                    "null".to_string()
                } else {
                    format!("\"{}\"", escape_json_str(&header_path_field))
                },
                header_field_json
            );

            fs::write(&out_path, json)?;
            println!("{}", out_path);
        }
    }
    Ok(())
}

// ───────────────── helpers (no extra deps) ─────────────────

fn norm_hex32(s: &str) -> Option<String> {
    let ss = s.trim();
    if !(ss.len() == 66 && (ss.starts_with("0x") || ss.starts_with("0X"))) {
        return None;
    }
    let hex = &ss[2..];
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", hex.to_ascii_lowercase()))
}

fn parse_branch_csv(csv: &str) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for part in csv.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        out.push(norm_hex32(part).ok_or_else(|| anyhow::anyhow!("bad branch item: {}", part))?);
    }
    Ok(out)
}

fn parse_branch_file(p: &PathBuf) -> anyhow::Result<Vec<String>> {
    let s = fs::read_to_string(p)?;
    parse_branch_csv(&s.replace('\n', ","))
}

fn escape_json_str(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            _ => std::iter::once(c).collect(),
        })
        .collect()
}
