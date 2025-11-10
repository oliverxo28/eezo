use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Default, Clone)]
pub struct Accounts {
    inner: Arc<RwLock<HashMap<String, (u64, u64)>>>, // addr -> (balance, nonce)
}

impl Accounts {
    pub fn new() -> Self { Self::default() }

    pub async fn get(&self, addr: &str) -> (u64, u64) {
        self.inner.read().await.get(addr).cloned().unwrap_or((0, 0))
    }

    pub async fn mint(&self, to: &str, amount: u64) {
        let mut w = self.inner.write().await;
        let entry = w.entry(normalize_addr(to)).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(amount);
    }

    pub async fn consume_nonce_and_debit(&self, from: &str, amount_plus_fee: u64) -> Result<u64, String> {
        let mut w = self.inner.write().await;
        let key = normalize_addr(from);
        let (bal, nonce) = w.get(&key).cloned().unwrap_or((0, 0));
        if bal < amount_plus_fee { return Err("insufficient funds".into()); }
        let new_bal = bal - amount_plus_fee;
        let new_nonce = nonce + 1;
        w.insert(key, (new_bal, new_nonce));
        Ok(new_nonce)
    }

    /// Normalize an address exactly like our internal map keys do.
    pub fn normalize(addr: &str) -> String {
        let mut t = addr.trim().to_ascii_lowercase();
        if !t.starts_with("0x") { t = format!("0x{}", t); }
        t
    }
}

fn normalize_addr(s: &str) -> String {
    let mut t = s.trim().to_ascii_lowercase();
    if !t.starts_with("0x") { t = format!("0x{}", t); }
    t
}

#[derive(Serialize)]
pub struct AccountView { pub balance: String, pub nonce: String }

#[derive(Deserialize)]
pub struct FaucetReq { pub to: String, pub amount: String }