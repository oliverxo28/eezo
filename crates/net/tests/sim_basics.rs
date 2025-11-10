#![cfg(feature = "t16-sim")]

use eezo_net::sim::{NetworkSimulator, NodeId};
use std::time::Duration;

#[test]
fn sim_latency_and_partition_basics() {
    let mut sim = NetworkSimulator::new();

    // two nodes
    let rx1 = sim.add_node(1);
    let rx2 = sim.add_node(2);

    // set latency to a small, deterministic value
    sim.set_latency(Duration::from_millis(10));

    // 1 -> 2 should deliver
    let ok = sim.send(1, 2, b"hello".to_vec());
    assert!(ok);
    let msg = rx2
        .recv_timeout(Duration::from_millis(100))
        .expect("must arrive");
    assert_eq!(msg, b"hello");

    // introduce partition: {1} | {2}
    sim.set_partition(&[1], &[2]);

    // 1 -> 2 should now be blocked
    let ok = sim.send(1, 2, b"blocked".to_vec());
    assert!(!ok);
    assert!(
        rx2.recv_timeout(Duration::from_millis(50)).is_err(),
        "no delivery under partition"
    );

    // heal and send again
    sim.heal_partition();
    let ok = sim.send(1, 2, b"post-heal".to_vec());
    assert!(ok);
    let msg = rx2
        .recv_timeout(Duration::from_millis(100))
        .expect("must arrive after heal");
    assert_eq!(msg, b"post-heal");

    // 2 -> 1 also works
    let ok = sim.send(2, 1, b"echo".to_vec());
    assert!(ok);
    let msg = rx1
        .recv_timeout(Duration::from_millis(100))
        .expect("must arrive");
    assert_eq!(msg, b"echo");
}
