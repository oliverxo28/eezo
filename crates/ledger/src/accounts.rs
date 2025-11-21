use crate::block::Block;
use crate::{Address, SignedTx};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(feature = "eth-ssz")]
use crate::serde::eth::{Encode, SerdeError};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
}

/// Simple in-memory map (backed storage comes later)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Accounts {
    inner: HashMap<Address, Account>,
}

impl Accounts {
    #[inline]
    pub fn get(&self, addr: &Address) -> Account {
        self.inner.get(addr).cloned().unwrap_or_default()
    }

    #[inline]
    pub fn put(&mut self, addr: Address, acct: Account) {
        self.inner.insert(addr, acct);
    }

    /// Ensure an account exists and return a mutable ref.
    fn ensure_mut(&mut self, who: Address) -> &mut Account {
        self.inner.entry(who).or_default()
    }
	
	/// Dev-only faucet helper: used by the node in EEZO_DEV mode to
	/// credit ledger accounts directly from /faucet.
	#[inline]
	pub fn dev_faucet_credit(&mut self, who: Address, amount: u128) {
		self.credit(who, amount);
	}

    /// +balance (saturating)
    pub fn credit(&mut self, who: Address, amount: u128) {
        let a = self.ensure_mut(who);
        a.balance = a.balance.saturating_add(amount);
    }

    // ─────────────────────────────────────────────────────────────
    // Test-only helpers: enabled for unit tests or with the
    // "testing" cargo feature (so integration tests can use them).
    // These NEVER ship in production/mainnet builds.
    // ─────────────────────────────────────────────────────────────
    #[cfg(any(test, feature = "dev-tools"))]
    #[inline]
    pub fn credit_unchecked_for_testing(&mut self, who: Address, amount: u128) {
        let a = self.ensure_mut(who);
        a.balance = a.balance.saturating_add(amount);
    }

    #[cfg(any(test, feature = "dev-tools"))]
    #[inline]
    pub fn set_nonce_unchecked_for_testing(&mut self, who: Address, nonce: u64) {
        let a = self.ensure_mut(who);
        a.nonce = nonce;
    }
    // ─────────────────────────────────────────────────────────────

    /// Read-only helpers (handy for future invariants)
    pub fn balance_of(&self, who: Address) -> u128 {
        self.inner.get(&who).map(|a| a.balance).unwrap_or(0)
    }

    pub fn nonce_of(&self, who: Address) -> u64 {
        self.inner.get(&who).map(|a| a.nonce).unwrap_or(0)
    }

    /// Advance nonce and return the previous value (optional, but useful)
    pub fn bump_nonce(&mut self, who: Address) -> u64 {
        let a = self.ensure_mut(who);
        let n = a.nonce;
        a.nonce = a.nonce.saturating_add(1);
        n
    }

    /// Apply a transaction to the accounts state.
    pub fn apply_tx(&mut self, tx: &SignedTx) -> Result<(), StateError> {
        // 1) Who is sending?
        let sender: Address = crate::sender_from_pubkey_first20(tx).ok_or(StateError::InvalidTx)?;

        // 2) What are we transferring?
        let receiver: Address = tx.core.to;
        let amount: u128 = tx.core.amount;
        let fee: u128 = tx.core.fee;

        // 3) Read-only check of sender state
        let sender_account = self.get(&sender);
        if sender_account.nonce != tx.core.nonce {
            return Err(StateError::BadNonce);
        }
        // amount + fee must be available
        let total_debit = amount.saturating_add(fee);
        if sender_account.balance < total_debit {
            return Err(StateError::InsufficientFunds);
        }

        // 4) Apply debits/credits
        {
            let s = self.ensure_mut(sender);
            s.balance = s.balance.saturating_sub(total_debit);
            s.nonce = s.nonce.saturating_add(1);
        }
        {
            let r = self.ensure_mut(receiver);
            r.balance = r.balance.saturating_add(amount);
        }

        // NOTE: burning the fee is handled in `tx.rs::apply_tx` via Supply::apply_burn.
        Ok(())
    }

    /// Apply all transactions in a block to the accounts state.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), StateError> {
        for tx in &block.txs {
            self.apply_tx(tx)?;
        }
        Ok(())
    }

    /// Iterate over account entries (address, account).
    /// NOTE: HashMap has no deterministic order; callers should sort if needed.
    pub fn iter(&self) -> impl Iterator<Item = (&Address, &Account)> {
        self.inner.iter()
    }

    /// Deterministic, simplified encoding for Accounts.
    /// - Sorts entries by address bytes to ensure stable order.
    /// - Uses simple byte concatenation instead of complex SSZ structures.
    #[cfg(feature = "eth-ssz")]
    pub fn to_ssz_bytes_safe(&self) -> Result<Vec<u8>, SerdeError> {
        // Collect via public iterator and sort deterministically by raw address bytes.
        let mut pairs: Vec<(&Address, &Account)> = self.iter().collect();
        pairs.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

        // Handle empty case - return 4 zero bytes for empty list count
        if pairs.is_empty() {
            return Ok(vec![0u8; 4]); // 4 zero bytes to encode empty list count
        }

        // Create a simple byte concatenation
        let mut result = Vec::new();
        
        // Write count first (4 bytes, little endian)
        result.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
        
        for (addr, acc) in pairs {
            // Address (20 bytes)
            result.extend_from_slice(addr.as_bytes());
            // Balance (16 bytes, little endian)
            result.extend_from_slice(&acc.balance.to_le_bytes());
            // Nonce (8 bytes, little endian)
            result.extend_from_slice(&acc.nonce.to_le_bytes());
        }

        Ok(result)
    }
}

#[cfg(feature = "eth-ssz")]
impl Encode for Account {
    fn ssz_write(&self, out: &mut Vec<u8>) {
        self.balance.ssz_write(out);
        self.nonce.ssz_write(out);
    }
}

#[derive(thiserror::Error, Debug)]
pub enum StateError {
    #[error("invalid transaction")]
    InvalidTx,
    #[error("invalid nonce")]
    BadNonce,
    #[error("insufficient funds")]
    InsufficientFunds,
}