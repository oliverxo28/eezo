//! Integration tests for consensus-dag
//!
//! Tests the full DAG consensus pipeline:
//! 1. Create vertices
//! 2. Store in DAG
//! 3. Order deterministically
//! 4. Handle payloads via DA

use consensus_dag::*;

#[test]
fn test_full_dag_pipeline() {
    // Initialize the system
    let (mut store, engine, _worker) = initialize();
    
    // Create some test vertices for round 1
    let author1 = AuthorId([1u8; 32]);
    let author2 = AuthorId([2u8; 32]);
    let payload1 = PayloadId([10u8; 32]);
    let payload2 = PayloadId([20u8; 32]);
    
    // Round 1: Genesis vertices (no parents)
    let v1 = DagNode::new(Round(1), vec![], payload1, author1, 1000);
    let v2 = DagNode::new(Round(1), vec![], payload2, author2, 1000);
    
    store.put_node(&v1);
    store.put_node(&v2);
    
    // Verify storage
    assert!(store.have_node(&v1.id));
    assert!(store.have_node(&v2.id));
    assert_eq!(store.node_count(), 2);
    
    // Try to order round 1 (with threshold=1, should succeed)
    let bundle = engine.try_order_round(&store, Round(1));
    assert!(bundle.is_some());
    
    let bundle = bundle.unwrap();
    assert_eq!(bundle.round, Round(1));
    assert_eq!(bundle.vertices.len(), 2);
    
    // Round 2: Build on round 1
    let v3 = DagNode::new(Round(2), vec![v1.id, v2.id], PayloadId([30u8; 32]), author1, 2000);
    store.put_node(&v3);
    
    // Verify parent relationships
    let missing = store.missing_parents(&v3.id);
    assert_eq!(missing.len(), 0); // All parents present
    
    // Get ready nodes for round 2
    let ready = store.get_ready_round(Round(2));
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].id, v3.id);
}

#[test]
fn test_dag_ordering_determinism() {
    // Create two separate stores and add vertices in different orders
    let mut store1 = DagStore::new();
    let mut store2 = DagStore::new();
    let engine = OrderingEngine::new();
    
    // Create test vertices
    let vertices: Vec<DagNode> = (0..10).map(|i| {
        DagNode::new(
            Round(1),
            vec![],
            PayloadId([(i * 10) as u8; 32]),
            AuthorId([i as u8; 32]),
            1000,
        )
    }).collect();
    
    // Add to store1 in order
    for v in vertices.iter() {
        store1.put_node(v);
    }
    
    // Add to store2 in reverse order
    for v in vertices.iter().rev() {
        store2.put_node(v);
    }
    
    // Both should produce identical ordering
    let bundle1 = engine.try_order_round(&store1, Round(1)).unwrap();
    let bundle2 = engine.try_order_round(&store2, Round(1)).unwrap();
    
    assert_eq!(bundle1.round, bundle2.round);
    assert_eq!(bundle1.vertices, bundle2.vertices);
    assert_eq!(bundle1.tx_count, bundle2.tx_count);
}

#[test]
fn test_dag_gc_removes_old_rounds() {
    let mut store = DagStore::new();
    
    // Add vertices for rounds 1-50
    for round in 1..=50 {
        let node = DagNode::new(
            Round(round),
            vec![],
            PayloadId([(round % 256) as u8; 32]),
            AuthorId([1u8; 32]),
            round * 1000,
        );
        store.put_node(&node);
    }
    
    assert_eq!(store.node_count(), 50);
    
    // Commit round 30 and trigger GC
    store.gc(Round(30));
    
    // Nodes below round 20 (30 - 10 safety margin) should be GCed
    let remaining = store.node_count();
    assert!(remaining < 50);
    assert!(remaining >= 30); // Rounds 20-50 should remain
    
    // Verify recent rounds still accessible
    assert_eq!(store.round_count(Round(30)), 1);
    assert_eq!(store.round_count(Round(40)), 1);
    assert_eq!(store.round_count(Round(50)), 1);
}

#[test]
fn test_payload_chunking_and_reassembly() {
    let worker = DAWorker::new();
    
    // Create a large payload
    let payload = vec![42u8; 1_000_000]; // 1MB
    let payload_id = PayloadId::compute(&payload);
    
    // Chunk it
    let chunks = worker.chunk_payload(&payload);
    assert!(chunks.len() > 1);
    
    // Reassemble
    let reassembled = worker.reassemble_chunks(&chunks);
    assert_eq!(reassembled, payload);
    
    // Verify
    assert!(worker.verify_payload(&payload_id, &reassembled));
}

#[test]
fn test_missing_parents_blocking() {
    let mut store = DagStore::new();
    
    // Create a child vertex WITHOUT adding its parents
    let parent1_id = VertexId([1u8; 32]);
    let parent2_id = VertexId([2u8; 32]);
    
    let child = DagNode::new(
        Round(2),
        vec![parent1_id, parent2_id],
        PayloadId([10u8; 32]),
        AuthorId([5u8; 32]),
        2000,
    );
    
    store.put_node(&child);
    
    // Child should NOT be ready (missing parents)
    let ready = store.get_ready_round(Round(2));
    assert_eq!(ready.len(), 0);
    
    // Check which parents are missing
    let missing = store.missing_parents(&child.id);
    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&parent1_id));
    assert!(missing.contains(&parent2_id));
    
    // Add first parent
    let parent1 = DagNode::new(
        Round(1),
        vec![],
        PayloadId([11u8; 32]),
        AuthorId([6u8; 32]),
        1000,
    );
    // Manually set ID to match expected parent
    let parent1 = DagNode {
        id: parent1_id,
        ..parent1
    };
    store.put_node(&parent1);
    
    // Still not ready (one parent missing)
    let ready = store.get_ready_round(Round(2));
    assert_eq!(ready.len(), 0);
    
    let missing = store.missing_parents(&child.id);
    assert_eq!(missing.len(), 1);
    assert!(missing.contains(&parent2_id));
    
    // Add second parent
    let parent2 = DagNode::new(
        Round(1),
        vec![],
        PayloadId([12u8; 32]),
        AuthorId([7u8; 32]),
        1000,
    );
    let parent2 = DagNode {
        id: parent2_id,
        ..parent2
    };
    store.put_node(&parent2);
    
    // Now child should be ready
    let ready = store.get_ready_round(Round(2));
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].id, child.id);
    
    let missing = store.missing_parents(&child.id);
    assert_eq!(missing.len(), 0);
}

/// Test for A11 requirement: order_is_total_ok
/// Verifies that DAG ordering is deterministic and total across multiple runs
#[test]
fn order_is_total_ok() {
    use std::env;
    
    // Use seed from environment if available (for determinism testing)
    let seed = env::var("EEZO_TEST_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(42);
    
    // Create multiple stores with same data added in different orders
    let mut stores = vec![DagStore::new(), DagStore::new(), DagStore::new()];
    let engine = OrderingEngine::new();
    
    // Create vertices
    let vertices: Vec<DagNode> = (0..20).map(|i| {
        DagNode::new(
            Round(1),
            vec![],
            PayloadId([((i * seed) % 256) as u8; 32]),
            AuthorId([(i % 10) as u8; 32]),
            1000 + i * 100,
        )
    }).collect();
    
    // Add vertices in different orders to each store
    // Store 0: forward order
    for v in vertices.iter() {
        stores[0].put_node(v);
    }
    
    // Store 1: reverse order
    for v in vertices.iter().rev() {
        stores[1].put_node(v);
    }
    
    // Store 2: "random" order (based on seed)
    let mut indices: Vec<usize> = (0..vertices.len()).collect();
    for i in (1..indices.len()).rev() {
        let j = ((i as u64 * seed * 31) % (i as u64 + 1)) as usize;
        indices.swap(i, j);
    }
    for &idx in &indices {
        stores[2].put_node(&vertices[idx]);
    }
    
    // All stores should produce identical ordering
    let bundles: Vec<_> = stores.iter()
        .map(|store| engine.try_order_round(store, Round(1)).unwrap())
        .collect();
    
    // Verify all bundles are identical
    for i in 1..bundles.len() {
        assert_eq!(bundles[0].round, bundles[i].round, 
                   "Round mismatch between store 0 and {}", i);
        assert_eq!(bundles[0].vertices, bundles[i].vertices,
                   "Vertex ordering mismatch between store 0 and {}", i);
        assert_eq!(bundles[0].tx_count, bundles[i].tx_count,
                   "Tx count mismatch between store 0 and {}", i);
    }
    
    println!("✅ order_is_total_ok: DAG ordering is deterministic across {} stores with seed={}", 
             stores.len(), seed);
}
