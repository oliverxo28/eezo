use crate::{block::Block, Accounts, Address, SignedTx};
use serde::{Deserialize, Serialize};
#[cfg(feature = "eth-ssz")]
use crate::serde::eth::SerdeError;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Supply {
    /// Sum of all native issuance (e.g., block rewards or manual ops) – NOT including bridge mints
    pub native_mint_total: u128,
    /// Sum of all mints that came from external chains via the bridge (burn on source → mint on EEZO)
    pub bridge_mint_total: u128,
    /// Total burns on EEZO (both user burns and any redemption flows)
    pub burn_total: u128,
}

impl Supply {
    #[inline]
    pub fn circulating(&self) -> u128 {
        self.native_mint_total
            .saturating_add(self.bridge_mint_total)
            .saturating_sub(self.burn_total)
    }

    #[inline]
    pub fn can_mint(&self, amount: u128, hard_cap: u128) -> bool {
        self.circulating().saturating_add(amount) <= hard_cap
    }

    /// Enforce cap before adding a mint (returns Err if it would exceed cap).
    pub fn apply_mint_checked(
        &mut self,
        amount: u128,
        hard_cap: u128,
        source: MintSource,
    ) -> Result<(), SupplyError> {
        if !self.can_mint(amount, hard_cap) {
            return Err(SupplyError::CapExceeded);
        }
        match source {
            MintSource::Native => {
                self.native_mint_total = self.native_mint_total.saturating_add(amount)
            }
            MintSource::Bridge => {
                self.bridge_mint_total = self.bridge_mint_total.saturating_add(amount)
            }
        }
        Ok(())
    }

    /// Burn always decreases circulating supply (no cap check needed).
    pub fn apply_burn(&mut self, amount: u128) {
        self.burn_total = self.burn_total.saturating_add(amount);
    }

    /// Credit `who` and update native totals.
    pub fn mint_native(
        &mut self,
        accts: &mut Accounts,
        who: Address,
        amount: u128,
    ) -> Result<(), SupplyError> {
        let cap = u128::MAX;
        self.apply_mint_checked(amount, cap, MintSource::Native)?;
        accts.credit(who, amount);

        #[cfg(feature = "metrics")]
        crate::metrics::SUPPLY_NATIVE_MINT_TOTAL.inc_by(amount as u64);

        Ok(())
    }

    /// Credit `who` and update bridge totals.
    pub fn mint_bridge(
        &mut self,
        accts: &mut Accounts,
        who: Address,
        amount: u128,
    ) -> Result<(), SupplyError> {
        let cap = u128::MAX;
        self.apply_mint_checked(amount, cap, MintSource::Bridge)?;
        accts.credit(who, amount);

        #[cfg(feature = "metrics")]
        crate::metrics::SUPPLY_BRIDGE_MINT_TOTAL.inc_by(amount as u64);

        Ok(())
    }

    /// Observe a transaction (no-op for standard transfers).
    pub fn observe_tx(&mut self, _tx: &SignedTx) {
        // No-op: standard transfers don't change supply here.
        // Fees are burned in tx.rs::apply_tx. Mints/burns use explicit APIs.
    }

    /// Apply all transactions in a block to the supply state.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), StateError> {
        for tx in &block.txs {
            self.observe_tx(tx);
        }
        Ok(())
    }


    /// Fallible SSZ-like encoding (panic-free) with fixed field ordering.
    /// Layout: native_mint_total[u128 LE] || bridge_mint_total[u128 LE] || burn_total[u128 LE]
    #[cfg(feature = "eth-ssz")]
    pub fn to_ssz_bytes_safe(&self) -> Result<Vec<u8>, SerdeError> {
        let mut out = Vec::with_capacity(16 * 3);
        out.extend_from_slice(&self.native_mint_total.to_le_bytes());
        out.extend_from_slice(&self.bridge_mint_total.to_le_bytes());
        out.extend_from_slice(&self.burn_total.to_le_bytes());
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MintSource {
    Native,
    Bridge,
}

#[derive(thiserror::Error, Debug)]
pub enum StateError {
    #[error("invalid transaction")]
    InvalidTx,
    #[error("supply error: {0}")]
    Supply(SupplyError),
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyError {
    #[error("mint would exceed hard cap")]
    CapExceeded,
}

impl From<SupplyError> for StateError {
    fn from(e: SupplyError) -> Self {
        StateError::Supply(e)
    }
}