#![cfg(feature = "persistence")]
use eezo_ledger::{
    build_genesis_block, genesis::ensure_genesis, persistence::Persistence, Address,
    ConsensusParams, GenesisConfig, Supply, ValidatorEntry,
};
use tempfile::TempDir;

#[test]
fn genesis_build_and_persist() {
    let cfg = GenesisConfig {
        chain_id: [7u8; 20],
        initial_validators: vec![ValidatorEntry {
            address: Address([1u8; 20]),
            stake: 1_000_000,
        }],
        initial_accounts: vec![(Address([2u8; 20]), 500), (Address([3u8; 20]), 700)],
        initial_supply: Supply {
            native_mint_total: 1_001_200, // 500 + 700 + 1_000_000 stake
            bridge_mint_total: 0,
            burn_total: 0,
        },
        consensus_params: ConsensusParams {
            max_txs_per_block: 1000,
            block_bytes_budget: 100_000,
        },
    };

    let g = build_genesis_block(cfg);
    // Print the new state_root for inspection
    eprintln!("NEW_STATE_ROOT = {:02x?}", g.state_root);
    // quick sanity: non-empty state_root and block height 0
    assert_eq!(g.block.header.height, 0);
    assert_ne!(g.state_root, [0u8; 32]);

    let dir = TempDir::new().unwrap();
    let p = Persistence::open_default(dir.path()).unwrap();
    ensure_genesis(&p, &g.config).unwrap();

    assert_eq!(p.get_tip().unwrap(), 0);
    let hdr0 = p.get_header(0).unwrap();
    assert_eq!(hdr0.height, 0);
    let snap = p
        .get_latest_snapshot_at_or_below(0)
        .unwrap()
        .expect("snap0");
    assert_eq!(snap.height, 0);
    assert_eq!(snap.state_root, g.state_root);

    // --- New: Chain ID invariant ---
    assert_eq!(
        g.config.chain_id,
        [7u8; 20],
        "genesis chain_id must match the config"
    );

    // --- New: Supply invariant ---
    let declared_sum: u128 = g
        .config
        .initial_accounts
        .iter()
        .map(|(_, bal)| *bal as u128)
        .sum::<u128>()
        + g.config
            .initial_validators
            .iter()
            .map(|v| v.stake as u128)
            .sum::<u128>();

    // Genesis supply should at least cover initial accounts + validator stakes
    let minted_total = g.config.initial_supply.native_mint_total;
    assert!(
        minted_total >= declared_sum,
        "minted supply {} must cover declared balances {}",
        minted_total,
        declared_sum
    );
}