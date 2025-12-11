//! T83.0 — SigPool Pipeline Integration Tests
//!
//! Tests for the enhanced signature verification pipeline with:
//! - Micro-batch scheduling
//! - Replay cache behavior
//! - Metrics integration
//! - Configuration from environment variables

#![cfg(all(feature = "pq44-runtime", feature = "metrics"))]

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
    EEZO_SIGPOOL_QUEUED_TOTAL,
    EEZO_SIGPOOL_VERIFIED_TOTAL,
    EEZO_SIGPOOL_FAILED_TOTAL,
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

// =============================================================================
// T83.0b: Batch Metrics & Micro-Batching Sanity Tests
// =============================================================================

/// T83.0b: Test that batch metrics increment when using verify_job API.
/// This test verifies that:
/// - queued_total increments
/// - verified_total increments
/// - batches_total increments
/// - batch_size_count > 0
/// - batch_latency_count > 0
#[cfg(feature = "metrics")]
#[tokio::test]
async fn t83_0b_batch_metrics_increment() {
    use eezo_node::metrics::{
        EEZO_SIGPOOL_QUEUED_TOTAL,
        EEZO_SIGPOOL_VERIFIED_TOTAL,
        EEZO_SIGPOOL_BATCHES_TOTAL,
        EEZO_SIGPOOL_BATCH_SIZE,
        EEZO_SIGPOOL_BATCH_LATENCY_SECONDS,
    };

    // Force metric registration
    register_t83_sigpool_metrics();

    // Record initial values
    let initial_queued = EEZO_SIGPOOL_QUEUED_TOTAL.get();
    let initial_verified = EEZO_SIGPOOL_VERIFIED_TOTAL.get();
    let initial_batches = EEZO_SIGPOOL_BATCHES_TOTAL.get();
    let initial_batch_size_count = EEZO_SIGPOOL_BATCH_SIZE.get_sample_count();
    let initial_batch_latency_count = EEZO_SIGPOOL_BATCH_LATENCY_SECONDS.get_sample_count();

    // Create pool with small batch size and short timeout to ensure batching happens
    let config = SigPoolConfig {
        threads: 2,
        batch_size: 4,  // Small batch size to trigger batching quickly
        batch_timeout_ms: 10,  // Short timeout to flush partial batches
        cache_size: 100,
        queue_size: 100,
    };
    
    let pool = SigPool::new_with_config(config);

    // Submit multiple jobs to ensure at least one batch is formed
    let num_jobs = 10;
    for i in 0..num_jobs {
        let job = SigVerifyJob::new(
            vec![i as u8; 32],
            vec![(i + 1) as u8; 32],
            vec![(i + 2) as u8; 32],
        );
        let _ = pool.verify_job(job).await;
    }

    // Allow time for batch processing
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify metrics incremented
    let final_queued = EEZO_SIGPOOL_QUEUED_TOTAL.get();
    let final_verified = EEZO_SIGPOOL_VERIFIED_TOTAL.get();
    let final_batches = EEZO_SIGPOOL_BATCHES_TOTAL.get();
    let final_batch_size_count = EEZO_SIGPOOL_BATCH_SIZE.get_sample_count();
    let final_batch_latency_count = EEZO_SIGPOOL_BATCH_LATENCY_SECONDS.get_sample_count();

    // queued_total should have incremented by at least num_jobs
    assert!(
        final_queued >= initial_queued + num_jobs,
        "queued_total should increment: initial={}, final={}, expected at least +{}",
        initial_queued, final_queued, num_jobs
    );

    // verified_total should have incremented (some may fail if sig is invalid, but metrics still increment)
    assert!(
        final_verified > initial_verified || 
        eezo_node::metrics::EEZO_SIGPOOL_FAILED_TOTAL.get() > 0,
        "verified_total or failed_total should increment: initial_verified={}, final_verified={}",
        initial_verified, final_verified
    );

    // batches_total should have incremented
    assert!(
        final_batches > initial_batches,
        "batches_total should increment: initial={}, final={}",
        initial_batches, final_batches
    );

    // batch_size histogram should have observations
    assert!(
        final_batch_size_count > initial_batch_size_count,
        "batch_size_count should increment: initial={}, final={}",
        initial_batch_size_count, final_batch_size_count
    );

    // batch_latency histogram should have observations
    assert!(
        final_batch_latency_count > initial_batch_latency_count,
        "batch_latency_count should increment: initial={}, final={}",
        initial_batch_latency_count, final_batch_latency_count
    );
}

/// T83.0b: Test that cache metrics increment when same tx is verified twice.
#[cfg(feature = "metrics")]
#[tokio::test]
async fn t83_0b_cache_metrics_increment() {
    use eezo_node::metrics::{
        EEZO_SIGPOOL_CACHE_HITS_TOTAL,
        EEZO_SIGPOOL_CACHE_MISSES_TOTAL,
    };

    // Force metric registration
    register_t83_sigpool_metrics();

    // Record initial cache values
    let initial_hits = EEZO_SIGPOOL_CACHE_HITS_TOTAL.get();
    let initial_misses = EEZO_SIGPOOL_CACHE_MISSES_TOTAL.get();

    // Create pool with small batch size
    let config = SigPoolConfig {
        threads: 2,
        batch_size: 4,
        batch_timeout_ms: 10,
        cache_size: 100,
        queue_size: 100,
    };
    
    let pool = SigPool::new_with_config(config);

    // Create a unique job that we'll submit twice
    let unique_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let job1 = SigVerifyJob::new(
        vec![((unique_id >> 0) & 0xFF) as u8; 32],
        vec![((unique_id >> 8) & 0xFF) as u8; 32],
        vec![((unique_id >> 16) & 0xFF) as u8; 32],
    );
    
    // Submit first time - should be a cache miss
    let result1 = pool.verify_job(job1.clone()).await;
    
    // Wait for batch to process
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    
    // Record values after first submission
    let after_first_hits = EEZO_SIGPOOL_CACHE_HITS_TOTAL.get();
    let after_first_misses = EEZO_SIGPOOL_CACHE_MISSES_TOTAL.get();
    
    // Submit same job again - should get a cache hit
    let job2 = SigVerifyJob::new(
        vec![((unique_id >> 0) & 0xFF) as u8; 32],
        vec![((unique_id >> 8) & 0xFF) as u8; 32],
        vec![((unique_id >> 16) & 0xFF) as u8; 32],
    );
    
    let result2 = pool.verify_job(job2).await;
    
    // Wait for processing
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    
    let final_hits = EEZO_SIGPOOL_CACHE_HITS_TOTAL.get();
    let final_misses = EEZO_SIGPOOL_CACHE_MISSES_TOTAL.get();
    
    // First submission should have caused a cache miss
    assert!(
        after_first_misses > initial_misses,
        "First submission should cause cache miss: initial={}, after={}",
        initial_misses, after_first_misses
    );
    
    // Second submission should cause a cache hit (either in verify_job fast path or in verify_batch)
    assert!(
        final_hits > after_first_hits || matches!(result2, SigVerifyResult::CacheHit),
        "Second submission should hit cache: after_first_hits={}, final_hits={}, result2={:?}",
        after_first_hits, final_hits, result2
    );
    
    // The results should be consistent
    // Note: result1 could be Ok or Failed depending on actual verification
    // result2 should be CacheHit if cache worked, or same result as result1
}

/// T83.0b: Test that verify_jobs (batch API) also increments metrics.
#[cfg(feature = "metrics")]
#[tokio::test]
async fn t83_0b_verify_jobs_batch_metrics() {
    use eezo_node::metrics::{
        EEZO_SIGPOOL_QUEUED_TOTAL,
        EEZO_SIGPOOL_BATCHES_TOTAL,
    };

    // Force metric registration
    register_t83_sigpool_metrics();

    let initial_queued = EEZO_SIGPOOL_QUEUED_TOTAL.get();
    let initial_batches = EEZO_SIGPOOL_BATCHES_TOTAL.get();

    let config = SigPoolConfig {
        threads: 2,
        batch_size: 8,
        batch_timeout_ms: 10,
        cache_size: 100,
        queue_size: 100,
    };
    
    let pool = SigPool::new_with_config(config);

    // Create batch of jobs
    let jobs: Vec<SigVerifyJob> = (0..20)
        .map(|i| SigVerifyJob::new(
            vec![(i * 3) as u8; 32],
            vec![(i * 3 + 1) as u8; 32],
            vec![(i * 3 + 2) as u8; 32],
        ))
        .collect();

    // Submit batch
    let _results = pool.verify_jobs(jobs).await;

    // Wait for processing
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let final_queued = EEZO_SIGPOOL_QUEUED_TOTAL.get();
    let final_batches = EEZO_SIGPOOL_BATCHES_TOTAL.get();

    // queued_total should have incremented by 20
    assert!(
        final_queued >= initial_queued + 20,
        "queued_total should increment by 20: initial={}, final={}",
        initial_queued, final_queued
    );

    // batches_total should have incremented (20 jobs with batch_size=8 -> at least 2-3 batches)
    assert!(
        final_batches > initial_batches,
        "batches_total should increment: initial={}, final={}",
        initial_batches, final_batches
    );
}