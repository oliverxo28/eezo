#[cfg(feature = "metrics")]
#[tokio::test]
async fn metrics_includes_core_names() {
    use eezo_node::http::state::router; // adjust if your router path differs
    use axum::http::Request;
    use tower::ServiceExt;

    let app = router().await;
    let res = app
        .oneshot(Request::builder().uri("/metrics").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
    let s = String::from_utf8(body.to_vec()).unwrap();

    // Schema names (lower-case) we require to exist once instrumented
    for needle in &[
        "eezo_block_e2e_latency_seconds",
        "eezo_tx_verify_seconds",
        "eezo_mempool_bytes_gauge",
        "eezo_kemtls_handshake_seconds",
    ] {
        assert!(s.contains(needle), "missing metric: {needle}");
    }
}

// If 'metrics' feature is off, the route still exists (shim) — just ensure 200 OK
#[cfg(not(feature = "metrics"))]
#[tokio::test]
async fn metrics_route_exists_without_feature() {
    use eezo_node::http::state::router;
    use axum::http::Request;
    use tower::ServiceExt;
    let app = router().await;
    let res = app
        .oneshot(Request::builder().uri("/metrics").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(res.status().is_success());
}
