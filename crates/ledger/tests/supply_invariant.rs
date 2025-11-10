use eezo_ledger::{MintSource, Supply, SupplyError};

#[test]
fn cap_is_enforced_for_native_and_bridge() {
    let hard_cap: u128 = 1_000;
    let mut s = Supply::default();

    // Native mint within cap
    s.apply_mint_checked(400, hard_cap, MintSource::Native)
        .unwrap();
    assert_eq!(s.circulating(), 400);

    // Bridge mint within remaining cap
    s.apply_mint_checked(500, hard_cap, MintSource::Bridge)
        .unwrap();
    assert_eq!(s.circulating(), 900);

    // Burn frees capacity
    s.apply_burn(100);
    assert_eq!(s.circulating(), 800);

    // Now another 200 mint fits (→ 1000)
    s.apply_mint_checked(200, hard_cap, MintSource::Native)
        .unwrap();
    assert_eq!(s.circulating(), 1000);

    // Any further mint should exceed cap
    let err = s
        .apply_mint_checked(1, hard_cap, MintSource::Bridge)
        .unwrap_err();
    assert_eq!(err, SupplyError::CapExceeded);
}

#[test]
fn burn_expands_capacity_across_sources() {
    let hard_cap: u128 = 500;
    let mut s = Supply::default();

    // Fill the cap entirely via Native.
    s.apply_mint_checked(500, hard_cap, MintSource::Native).unwrap();
    assert_eq!(s.circulating(), 500);

    // Further minting from any source should fail until we burn.
    let err = s
        .apply_mint_checked(1, hard_cap, MintSource::Bridge)
        .unwrap_err();
    assert_eq!(err, SupplyError::CapExceeded);

    // Burn some supply…
    s.apply_burn(250);
    assert_eq!(s.circulating(), 250);

    // …and confirm the freed capacity can be filled by a *different* source.
    s.apply_mint_checked(250, hard_cap, MintSource::Bridge).unwrap();
    assert_eq!(s.circulating(), 500);

    // Past the hard cap still fails.
    let err = s
        .apply_mint_checked(1, hard_cap, MintSource::Native)
        .unwrap_err();
    assert_eq!(err, SupplyError::CapExceeded);
}
