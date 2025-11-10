use eezo_ledger::{
    header_domain_bytes, header_hash, validate_header, verify_cache::VerifyCache, BlockHeader,
    HeaderErr,
};

#[cfg(feature = "pq44-runtime")]
use pqcrypto_mldsa::mldsa44::{detached_sign, keypair};
#[cfg(feature = "pq44-runtime")]
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

fn sample_header() -> BlockHeader {
    BlockHeader {
        height: 42,
        prev_hash: [1u8; 32],
        tx_root: [2u8; 32],
        #[cfg(feature = "eth-ssz")]
        tx_root_v2: [0u8; 32],
        fee_total: 12345,
        tx_count: 7,
        timestamp_ms: 1_725_000_000_000,
        #[cfg(feature = "checkpoints")]
        qc_hash: [0u8; 32],
    }
}

#[test]
fn header_happy_path_and_replay() {
    let chain_id = [9u8; 20];
    let hdr = sample_header();
    let expected = header_hash(&hdr);

    // Build a valid signature
    #[cfg(feature = "pq44-runtime")]
    let (pk, sk) = keypair();
    #[cfg(feature = "pq44-runtime")]
    let sig = {
        let msg = header_domain_bytes(chain_id, &hdr);
        detached_sign(&msg, &sk)
    };

    const CACHE_CAP: usize = 1024;
    let cache = VerifyCache::new(CACHE_CAP);

    // OK the first time
    #[cfg(feature = "pq44-runtime")]
    {
        let ok_hash = validate_header(
            chain_id,
            expected,
            &hdr,
            pk.as_bytes(),
            sig.as_bytes(),
            Some(&cache),
        )
        .expect("valid header");
        assert_eq!(ok_hash, expected);
    }

    // Replay should be rejected
    #[cfg(feature = "pq44-runtime")]
    {
        let err = validate_header(
            chain_id,
            expected,
            &hdr,
            pk.as_bytes(),
            sig.as_bytes(),
            Some(&cache),
        )
        .unwrap_err();
        assert_eq!(err, HeaderErr::Replay);
    }
}

#[test]
fn header_bad_sig_and_hash_mismatch() {
    let chain_id = [7u8; 20];
    let hdr = sample_header();
    let expected = header_hash(&hdr);

    #[cfg(feature = "pq44-runtime")]
    let (pk, sk) = keypair();

    // Bad signature
    #[cfg(feature = "pq44-runtime")]
    {
        let msg = header_domain_bytes(chain_id, &hdr);
        let mut bad = detached_sign(&msg, &sk).as_bytes().to_vec();
        bad[0] ^= 0x01;

        let err = validate_header(chain_id, expected, &hdr, pk.as_bytes(), &bad, None).unwrap_err();
        assert_eq!(err, HeaderErr::BadSig);
    }

    // Hash mismatch (wrong expected hash)
    #[cfg(feature = "pq44-runtime")]
    {
        let msg = header_domain_bytes(chain_id, &hdr);
        let sig = detached_sign(&msg, &sk);

        let wrong = [0u8; 32];
        let err = validate_header(chain_id, wrong, &hdr, pk.as_bytes(), sig.as_bytes(), None)
            .unwrap_err();
        assert_eq!(err, HeaderErr::HashMismatch);
    }
}

// Note:
// Currently, `validate_header` only checks for Replay, BadSig, and HashMismatch.
// Height / PrevHash / Oversize validation is not yet enforced at this layer.
// If those error variants are added later, restore the tests here.