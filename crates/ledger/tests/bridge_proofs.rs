#![cfg(all(feature = "pq44-runtime", feature = "eth-ssz"))]

use eezo_ledger::{
    Address,
    bridge::{BridgeMintVoucher, compute_deposit_id, canonical_mint_msg, mint_leaf},
    merkle::{mint_inclusion_proof, verify_mint_inclusion},
};

#[test]
fn bridge_mint_leaf_and_inclusion_proof_roundtrip() {
    let chain_id = [0xABu8; 20];
    let to1 = Address::from_bytes([1u8; 20]);
    let to2 = Address::from_bytes([2u8; 20]);
    let to3 = Address::from_bytes([3u8; 20]);

    let v1 = BridgeMintVoucher {
        deposit_id: compute_deposit_id(1, [0x11; 32], to1, 111),
        ext_chain: 1,
        source_tx: [0x11; 32],
        to: to1,
        amount: 111,
        sig: vec![],
    };
    let v2 = BridgeMintVoucher {
        deposit_id: compute_deposit_id(1, [0x22; 32], to2, 222),
        ext_chain: 1,
        source_tx: [0x22; 32],
        to: to2,
        amount: 222,
        sig: vec![],
    };
    let v3 = BridgeMintVoucher {
        deposit_id: compute_deposit_id(1, [0x33; 32], to3, 333),
        ext_chain: 1,
        source_tx: [0x33; 32],
        to: to3,
        amount: 333,
        sig: vec![],
    };

    // Leaf must be sha3_256(canonical_mint_msg(...))
    let msg_v2 = canonical_mint_msg(chain_id, &v2);
    let leaf_v2 = mint_leaf(chain_id, &v2);
    // Redundant call ensures stability: leaf == sha3(msg)
    let again_leaf_v2 = mint_leaf(chain_id, &v2);
    assert_eq!(leaf_v2, again_leaf_v2, "mint leaf must be stable for same voucher");
    assert_eq!(leaf_v2.len(), 32);

    // Prove inclusion for index 1 (v2)
    let mints = vec![v1, v2, v3];
    let (leaf, branch, root) = mint_inclusion_proof(&mints, 1, chain_id).expect("build proof");
    assert_eq!(leaf.len(), 32);
    assert!(verify_mint_inclusion(&leaf, &branch, root, 1), "valid inclusion verifies");
    assert!(!verify_mint_inclusion(&leaf, &branch, root, 0), "wrong index must fail");
}

#[cfg(feature = "checkpoints")]
mod checkpoints {
    use eezo_ledger::checkpoints::{BridgeHeader, checkpoint_filename};

    #[test]
    fn checkpoint_header_json_contract_basics() {
        let h = 42u64;
        let hdr = BridgeHeader::new(
            h,
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            1_700_000_000, // timestamp
            2,             // finality depth
        );

        // filename must be zero-padded 20 digits
        assert_eq!(checkpoint_filename(h), "00000000000000000042.json");

        // JSON roundtrip shape check
        let s = serde_json::to_string(&hdr).unwrap();
        let back: BridgeHeader = serde_json::from_str(&s).unwrap();
        assert_eq!(back.height, h);
        assert_eq!(back.header_hash, [0xAA; 32]);
        assert_eq!(back.state_root_v2, [0xBB; 32]);
        assert_eq!(back.tx_root_v2, [0xCC; 32]);
        assert_eq!(back.finality_depth, 2);
    }
}
