//! sigpool.rs — T51.5a
//!
//! Multi-threaded signature verification / intake pipeline.
//! For now, it operates on raw tx bytes and acts as a parallel
//! staging area before mempool.submit(). Later we can extend it
//! to decode and verify real SignedTx structures.

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task;

#[cfg(feature = "metrics")]
use crate::metrics::{
    EEZO_SIGPOOL_QUEUED_TOTAL,
    EEZO_SIGPOOL_VERIFIED_TOTAL,
    EEZO_SIGPOOL_FAILED_TOTAL,
    EEZO_SIGPOOL_ACTIVE_THREADS,
};

/// Request sent into the sigpool worker queue.
pub struct VerifyRequest {
    /// Canonical raw tx bytes (e.g. JSON-encoded envelope).
    pub raw: Vec<u8>,
    pub resp: oneshot::Sender<Result<Vec<u8>, ()>>,
}

/// Thread-pool for multi-threaded verification / preprocessing.
///
/// The sigpool only guarantees:
/// ✔ Accept raw tx bytes
/// ✔ Optionally verify/process them in background
/// ✔ Return either the (possibly transformed) bytes or an error
/// ✔ Bounded queue
/// ✔ Configurable worker count
///
/// It does **not** insert into mempool — that is done by the caller.
pub struct SigPool {
    tx: mpsc::Sender<VerifyRequest>,
}

impl SigPool {
    /// Create a new sigpool.
    /// `threads` = number of worker tasks
    /// `queue`   = max outstanding requests
    pub fn new(threads: usize, queue: usize) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<VerifyRequest>(queue);
        let active = Arc::new(Semaphore::new(threads));

        #[cfg(feature = "metrics")]
        EEZO_SIGPOOL_ACTIVE_THREADS.set(threads as i64);

        let pool = Arc::new(Self { tx });

        // spawn worker loop
        let pool_clone = pool.clone();
        task::spawn(async move {
            loop {
                let Some(req) = rx.recv().await else { break; };

                // Acquire worker slot
                let permit = match active.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = req.resp.send(Err(()));
                        continue;
                    }
                };

                // Verify/process in separate Tokio task
                task::spawn(async move {
                    #[cfg(feature = "metrics")]
                    {
                        EEZO_SIGPOOL_QUEUED_TOTAL.inc();
                    }

                    // TODO(T51.5a+): decode and perform real ML-DSA
                    // signature verification here. For now, treat all
                    // inputs as "ok" and return the bytes unchanged so
                    // behaviour stays identical to the pre-sigpool path.
                    let ok = true;

                    if ok {
                        #[cfg(feature = "metrics")]
                        EEZO_SIGPOOL_VERIFIED_TOTAL.inc();
                        let _ = req.resp.send(Ok(req.raw));
                    } else {
                        #[cfg(feature = "metrics")]
                        EEZO_SIGPOOL_FAILED_TOTAL.inc();
                        let _ = req.resp.send(Err(()));
                    }

                    drop(permit); // release slot
                });
            }
        });

        pool_clone
    }

    /// Submit raw bytes for verification / preprocessing.
    /// Returns: future resolving to Result<raw_bytes, ()>.
    pub async fn verify(&self, raw: Vec<u8>) -> Result<Vec<u8>, ()> {
        let (resp_tx, resp_rx) = oneshot::channel();

        let req = VerifyRequest { raw, resp: resp_tx };

        if self.tx.send(req).await.is_err() {
            return Err(());
        }

        resp_rx.await.unwrap_or(Err(()))
    }
}
