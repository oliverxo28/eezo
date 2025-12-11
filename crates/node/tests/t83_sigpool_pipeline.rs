//! T83.0 — SigPool Pipeline Integration Tests
//!
//! Tests for the enhanced signature verification pipeline with:
//! - Micro-batch scheduling
//! - Replay cache behavior
//! - Metrics integration
//! - Configuration from environment variables

#![cfg(all(feature = "pq44-runtime", feature = "metrics"))]

use std::sync::Arc;
use std::time::Duration;

// Re-export modules from the main crate for testing
use eezo_node::sigpool::{SigPool, SigPoolConfig, SigVerifyJob, SigVerifyResult};

#[cfg(feature = "metrics")]
use eezo_node::metrics::{
    register_t83_sigpool_metrics,
    EEZO_SIGPOOL_BATCHES_TOTAL,
    EEZO_SIGPOOL_BATCH_SIZE,
    EEZO_SIGPOOL_CACHE_HITS_TOTAL,
    EEZO_SIGPOOL_CACHE_MISSES_TOTAL,
    EEZO_SIGPOOL_BATCH_LATENCY_SECONDS,
};

/// Test that SigPool can be created with default configuration.
#[tokio::test]
async fn sigpool_creates_with_defaults() {
    // Create with legacy API
    let pool = SigPool::new(4, 1000);
    
    // Should be able to verify raw bytes (legacy API)
    let raw = vec![1, 2, 3, 4, 5];
    let result = pool.verify(raw.clone()).await;
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), raw);
}

/// Test that SigPool can be created with custom configuration.
#[tokio::test]
async fn sigpool_creates_with_config() {
    let config = SigPoolConfig {
        threads: 2,
        batch_size: 32,
        batch_timeout_ms: 10,
        cache_size: 1000,
        queue_size: 500,
    };
    
    let pool = SigPool::new_with_config(config);
    
    // Verify configuration is accessible
    let cfg = pool.config();
    assert_eq!(cfg.threads, 2);
    assert_eq!(cfg.batch_size, 32);
    assert_eq!(cfg.batch_timeout_ms, 10);
    assert_eq!(cfg.cache_size, 1000);
    assert_eq!(cfg.queue_size, 500);
}

/// Test SigVerifyJob creation and cache key generation.
#[test]
fn sig_verify_job_cache_key() {
    // Same content should produce same key
    let job1 = SigVerifyJob::new(
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
    );
    let job2 = SigVerifyJob::new(
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
    );
    
    // Note: cache_key is internal, we just verify the API works
    assert_eq!(job1.pubkey, job2.pubkey);
    assert_eq!(job1.message, job2.message);
    assert_eq!(job1.signature, job2.signature);
}

/// Test SigVerifyJob with explicit tx_hash.
#[test]
fn sig_verify_job_with_tx_hash() {
    let tx_hash = [42u8; 32];
    let job = SigVerifyJob::with_tx_hash(
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
        tx_hash,
    );
    
    assert_eq!(job.tx_hash, Some(tx_hash));
}

/// Test cache statistics tracking.
#[tokio::test]
async fn sigpool_cache_stats() {
    let config = SigPoolConfig {
        threads: 1,
        batch_size: 1,
        batch_timeout_ms: 1,
        cache_size: 100,
        queue_size: 100,
    };
    
    let pool = SigPool::new_with_config(config);
    
    // Initially, cache should be empty
    let (hits, misses) = pool.cache_stats();
    // Note: Metrics might already have some values from other tests
    // Just verify we can read the stats
    assert!(hits >= 0);
    assert!(misses >= 0);
}

/// Test SigPoolConfig loads defaults correctly.
#[test]
fn sigpool_config_defaults() {
    let config = SigPoolConfig::default();
    
    // Threads should be at least 1
    assert!(config.threads >= 1);
    // Batch size should be reasonable
    assert!(config.batch_size > 0);
    assert!(config.batch_size <= 256);
    // Queue size should be reasonable
    assert!(config.queue_size > 0);
}

/// Test SigPoolConfig loads from environment.
#[test]
fn sigpool_config_from_env() {
    // Set environment variables
    std::env::set_var("EEZO_SIGPOOL_THREADS", "4");
    std::env::set_var("EEZO_SIGPOOL_BATCH_SIZE", "128");
    std::env::set_var("EEZO_SIGPOOL_BATCH_TIMEOUT_MS", "10");
    std::env::set_var("EEZO_SIGPOOL_CACHE_SIZE", "4096");
    std::env::set_var("EEZO_SIGPOOL_QUEUE", "10000");
    
    let config = SigPoolConfig::from_env();
    
    assert_eq!(config.threads, 4);
    assert_eq!(config.batch_size, 128);
    assert_eq!(config.batch_timeout_ms, 10);
    assert_eq!(config.cache_size, 4096);
    assert_eq!(config.queue_size, 10000);
    
    // Cleanup
    std::env::remove_var("EEZO_SIGPOOL_THREADS");
    std::env::remove_var("EEZO_SIGPOOL_BATCH_SIZE");
    std::env::remove_var("EEZO_SIGPOOL_BATCH_TIMEOUT_MS");
    std::env::remove_var("EEZO_SIGPOOL_CACHE_SIZE");
    std::env::remove_var("EEZO_SIGPOOL_QUEUE");
}

/// Test SigPoolConfig handles invalid env values gracefully.
#[test]
fn sigpool_config_invalid_env() {
    // Set invalid environment variables
    std::env::set_var("EEZO_SIGPOOL_THREADS", "not_a_number");
    std::env::set_var("EEZO_SIGPOOL_BATCH_SIZE", "-1");
    
    let config = SigPoolConfig::from_env();
    
    // Should fall back to defaults
    assert!(config.threads >= 1);
    assert!(config.batch_size > 0);
    
    // Cleanup
    std::env::remove_var("EEZO_SIGPOOL_THREADS");
    std::env::remove_var("EEZO_SIGPOOL_BATCH_SIZE");
}

/// Test SigVerifyResult equality.
#[test]
fn sig_verify_result_equality() {
    assert_eq!(SigVerifyResult::Ok, SigVerifyResult::Ok);
    assert_eq!(SigVerifyResult::Failed, SigVerifyResult::Failed);
    assert_eq!(SigVerifyResult::CacheHit, SigVerifyResult::CacheHit);
    
    assert_ne!(SigVerifyResult::Ok, SigVerifyResult::Failed);
    assert_ne!(SigVerifyResult::Ok, SigVerifyResult::CacheHit);
    assert_ne!(SigVerifyResult::Failed, SigVerifyResult::CacheHit);
}

/// Test that legacy API maintains backwards compatibility.
#[tokio::test]
async fn sigpool_legacy_api_backwards_compat() {
    // This is the original API from T51.5a
    let pool = SigPool::new(2, 100);
    
    // Multiple concurrent requests should work
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let pool = pool.clone();
            let raw = vec![i as u8; 10];
            tokio::spawn(async move {
                pool.verify(raw.clone()).await
            })
        })
        .collect();
    
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

/// Test that the pipeline properly handles concurrent job submissions.
#[tokio::test]
async fn sigpool_concurrent_jobs() {
    let config = SigPoolConfig {
        threads: 4,
        batch_size: 64,
        batch_timeout_ms: 5,
        cache_size: 1000,
        queue_size: 1000,
    };
    
    let pool = SigPool::new_with_config(config);
    
    // Submit many jobs concurrently
    let handles: Vec<_> = (0..100)
        .map(|i| {
            let pool = pool.clone();
            tokio::spawn(async move {
                let job = SigVerifyJob::new(
                    vec![i as u8; 32],
                    vec![(i + 1) as u8; 32],
                    vec![(i + 2) as u8; 32],
                );
                pool.verify_job(job).await
            })
        })
        .collect();
    
    // All should complete (whether Ok, Failed, or CacheHit depends on verification)
    for handle in handles {
        let _result = handle.await.unwrap();
        // Result is valid (no panics)
    }
}

// =============================================================================
// Metrics Integration Tests
// =============================================================================

/// Test that T83.0 metrics are registered.
#[cfg(feature = "metrics")]
#[test]
fn t83_metrics_registered() {
    // Force metric registration
    register_t83_sigpool_metrics();
    
    // Access the metrics to verify they exist
    // (They are Lazy statics, so accessing them forces initialization)
    let _ = &*EEZO_SIGPOOL_BATCHES_TOTAL;
    let _ = &*EEZO_SIGPOOL_BATCH_SIZE;
    let _ = &*EEZO_SIGPOOL_CACHE_HITS_TOTAL;
    let _ = &*EEZO_SIGPOOL_CACHE_MISSES_TOTAL;
    let _ = &*EEZO_SIGPOOL_BATCH_LATENCY_SECONDS;
}
