//! executor/stm.rs — T54.1.3 Phase-A
//! Safe baseline executor: serial apply with metrics.
//! Next patch will upgrade this to MVCC workers (true Block-STM).

use std::time::Instant;

use crate::{
    executor::{ExecInput, ExecOutcome},
    metrics::{
        EEZO_EXEC_STM_ABORTS_TOTAL,
        EEZO_EXEC_STM_APPLY_BLOCK_MS,
        EEZO_EXEC_STM_COMMIT_MS,
    },
};

use eezo_ledger::{
    Accounts, Supply, Address,
    tx::{validate_tx_stateful, apply_tx},
    sender_from_pubkey_first20,
};

/// Get dev sender from env for fallback when pubkey is empty
fn get_dev_sender_fallback() -> Address {
    std::env::var("EEZO_DEV_FROM")
        .ok()
        .and_then(|s| {
            let trimmed = s.trim().trim_start_matches("0x");
            hex::decode(trimmed).ok()
        })
        .and_then(|bytes| {
            if bytes.len() >= 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes[bytes.len()-20..]);
                Some(Address(arr))
            } else {
                None
            }
        })
        .unwrap_or_else(|| Address([0u8; 20]))
}

/// Synchronous STM executor - can be called from any context.
/// Uses std::sync::Mutex for state access (no async needed).
pub fn apply_block_stm(_threads: usize, input: ExecInput) -> ExecOutcome {
    let start = Instant::now();

    // Context (accounts/supply) is mandatory.
    let ctx = input.ctx;
    
    // Get dev sender fallback once for this block
    let dev_sender_fallback = get_dev_sender_fallback();

    // Lock state synchronously
    let mut accounts_guard = match ctx.accounts.lock() {
        Ok(g) => g,
        Err(e) => {
            EEZO_EXEC_STM_ABORTS_TOTAL.inc();
            return ExecOutcome::new(
                Err(format!("Failed to lock accounts: {e}")),
                start.elapsed(),
                0,
            );
        }
    };
    let mut supply_guard = match ctx.supply.lock() {
        Ok(g) => g,
        Err(e) => {
            EEZO_EXEC_STM_ABORTS_TOTAL.inc();
            return ExecOutcome::new(
                Err(format!("Failed to lock supply: {e}")),
                start.elapsed(),
                0,
            );
        }
    };

    let accounts: &mut Accounts = &mut *accounts_guard;
    let supply:   &mut Supply   = &mut *supply_guard;

    let mut applied_count = 0usize;
    let mut skipped_insufficient_funds = 0usize;
    let mut skipped_bad_nonce = 0usize;
    let mut skipped_other = 0usize;

    // Serial apply preserves correctness and determinism today.
    for tx in &input.txs {
        // derive sender from tx.pubkey (first 20 bytes)
        // For dev mode with empty pubkeys, use EEZO_DEV_FROM or zero address
        let sender: Address = sender_from_pubkey_first20(tx)
            .unwrap_or(dev_sender_fallback);

        // stateful validation (check nonce, balance, etc.)
        if let Err(e) = validate_tx_stateful(accounts, sender, &tx.core) {
            let err_str = format!("{:?}", e);
            if err_str.contains("InsufficientFunds") {
                skipped_insufficient_funds += 1;
                #[cfg(feature = "metrics")]
                crate::metrics::EEZO_TX_SKIPPED_INSUFFICIENT_FUNDS.inc();
            } else if err_str.contains("BadNonce") {
                skipped_bad_nonce += 1;
                #[cfg(feature = "metrics")]
                crate::metrics::EEZO_TX_SKIPPED_BAD_NONCE.inc();
            } else {
                skipped_other += 1;
                #[cfg(feature = "metrics")]
                crate::metrics::EEZO_TX_SKIPPED_OTHER.inc();
            }
            log::warn!("STM: skipping tx with validation error: {:?} (sender=0x{})", 
                       e, hex::encode(&sender.0));
            continue; // Skip invalid txs instead of aborting block
        }
        
        // apply uses (&mut Accounts, &mut Supply, sender, &TxCore)
        if let Err(e) = apply_tx(accounts, supply, sender, &tx.core) {
            log::warn!("STM: skipping tx with apply error: {:?} (sender=0x{})", 
                       e, hex::encode(&sender.0));
            skipped_other += 1;
            #[cfg(feature = "metrics")]
            crate::metrics::EEZO_TX_SKIPPED_OTHER.inc();
            continue; // Skip failed txs instead of aborting block
        }
        
        applied_count += 1;
        
        // Increment the tx included metric for each successfully applied tx
        #[cfg(feature = "metrics")]
        crate::metrics::EEZO_TXS_INCLUDED_TOTAL.inc();
    }

    let elapsed = start.elapsed();
    EEZO_EXEC_STM_APPLY_BLOCK_MS.observe(elapsed.as_secs_f64() * 1000.0);
    // No distinct commit phase yet; keep metric continuity for dashboards.
    EEZO_EXEC_STM_COMMIT_MS.observe(0.0);

    let total_skipped = skipped_insufficient_funds + skipped_bad_nonce + skipped_other;
    log::info!(
        "STM: applied {}/{} txs ({} skipped: {} insufficient_funds, {} bad_nonce, {} other) in {:?}",
        applied_count,
        input.txs.len(),
        total_skipped,
        skipped_insufficient_funds,
        skipped_bad_nonce,
        skipped_other,
        elapsed
    );

    // we only mutate state here; block assembly happens in the shim
    ExecOutcome::new(Ok(()), elapsed, applied_count)
}

/// Async version for compatibility (just calls sync version)
pub async fn apply_block_stm_async(input: ExecInput) -> ExecOutcome {
    apply_block_stm(0, input)
}