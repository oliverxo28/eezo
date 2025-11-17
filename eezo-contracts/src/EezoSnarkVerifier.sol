// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EezoSnarkVerifier (adapter)
/// @notice optional on-chain SNARK path: verifies a PLONK-KZG proof
///         binds it to a canonical EEZO piDigest, then stores it via LC.
/// @dev this is a minimal, testable skeleton. real verifier wiring is T39.4.
///      solidity style is kept simple; comments lowercase as per your preference.
interface IEezoLightClient {
    function expectedChainId20() external view returns (bytes20);
    function latestHeight() external view returns (uint64);
    function setPiDigest(uint64 height, bytes32 piDigest) external; // already exists per T38.7
    function isCircuitAllowed(uint32 cv) external view returns (bool);
}

contract EezoSnarkVerifier {
    /// @dev immutable lc we write into (must be set to your deployed EezoLightClient)
    IEezoLightClient public immutable lc;

    /// @dev circuit version for gating (matches your LC’s allowed circuit versions)
    uint32 public immutable circuitVersion;

    /// @dev basic toggles for safety in tests/devnets
    bool public snarkRequired; // if true, only SNARK path is accepted (tests)
    bytes20 public expectedChainId20Cache;

    /// errors
    error ErrChainIdMismatch(bytes20 expected, bytes20 got);
    error ErrCircuitNotAllowed(uint32 cv);
    error ErrReorgOrPastHeight(uint64 req, uint64 latest);
    error ErrProofInvalid();

    /// events
    event SnarkVerifiedAndStored(uint64 indexed height, bytes32 piDigest, uint32 circuitVersion, uint256 proofLen);

    constructor(address _lc, uint32 _circuitVersion, bool _snarkRequired) {
        require(_lc != address(0), "lc=0");
        lc = IEezoLightClient(_lc);
        circuitVersion = _circuitVersion;
        snarkRequired = _snarkRequired;

        // cache chain id for a cheap first check; we still read from lc on call
        expectedChainId20Cache = IEezoLightClient(_lc).expectedChainId20();
    }

    /// @notice flip requirement in tests/devnet; keep ownerless for now (simple)
    function setSnarkRequired(bool v) external {
        snarkRequired = v;
    }

    /// @notice main entry: verify SNARK and store the canonical piDigest into LC.
    /// @param height target eezo height for this digest
    /// @param piDigest canonical 32-byte digest (already defined by your T38.x)
    /// @param snarkProof plonk-kzg proof bytes (placeholder rule for now: 32-byte commitment)
    function verifyAndStorePiDigest(
        uint64 height,
        bytes32 piDigest,
        bytes calldata snarkProof
    ) external {
        // 1) chain id check
        bytes20 got = lc.expectedChainId20();
        bytes20 exp = expectedChainId20Cache;
        if (got != exp) revert ErrChainIdMismatch(exp, got);

        // 2) circuit allowed
        if (!lc.isCircuitAllowed(circuitVersion)) revert ErrCircuitNotAllowed(circuitVersion);

        // 3) monotonic height (no reorgs/past writes here)
        uint64 latest = lc.latestHeight();
        if (height <= latest) revert ErrReorgOrPastHeight(height, latest);

        // 4) verify proof (T39.3 skeleton):
        //    accept only if proof equals the 32-byte digest commitment,
        //    matching your current eezo-snark placeholder behavior.
        //    T39.4: swap with real verifier precompile / contract call.
        if (snarkProof.length != 32) revert ErrProofInvalid();
        bytes32 proofDigest;
        assembly {
            // snarkProof points to ABI bytes layout: [len (32)][data...]
            proofDigest := calldataload(snarkProof.offset)
        }
        if (proofDigest != piDigest) revert ErrProofInvalid();

        // 5) write digest into LC (authoritative store lives in LC)
        lc.setPiDigest(height, piDigest);

        emit SnarkVerifiedAndStored(height, piDigest, circuitVersion, snarkProof.length);
    }
}
