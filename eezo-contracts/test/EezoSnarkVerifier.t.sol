// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import {EezoSnarkVerifier, IEezoLightClient} from "../src/EezoSnarkVerifier.sol";

/// simple mock for the Eezo Light Client interface used by the verifier
contract MockLightClient is IEezoLightClient {
    bytes20 private _expectedChainId20;
    uint64 private _latestHeight;
    mapping(uint32 => bool) private _allowedCircuit;
    mapping(uint64 => bytes32) public piDigestOf;

    // admin helpers for tests
    function setExpectedChainId20(bytes20 v) external {
        _expectedChainId20 = v;
    }

    function setLatestHeight(uint64 v) external {
        _latestHeight = v;
    }

    function setCircuitAllowed(uint32 cv, bool v) external {
        _allowedCircuit[cv] = v;
    }

    // IEezoLightClient impl
    function expectedChainId20() external view override returns (bytes20) {
        return _expectedChainId20;
    }

    function latestHeight() external view override returns (uint64) {
        return _latestHeight;
    }

    function isCircuitAllowed(uint32 cv) external view override returns (bool) {
        return _allowedCircuit[cv];
    }

    function setPiDigest(uint64 height, bytes32 piDigest) external override {
        // store digest; do NOT advance latestHeight here (LC logic owns that)
        piDigestOf[height] = piDigest;
    }
}

contract EezoSnarkVerifierTest is Test {
    MockLightClient lc;
    EezoSnarkVerifier verifier;

    // test constants
    uint32 constant CV = 2; // circuit version gate
    // simple, legal way to express a 20-byte chain id
    bytes20 constant CHAIN_ID20 = bytes20(uint160(1));

    function setUp() public {
        lc = new MockLightClient();
        lc.setExpectedChainId20(CHAIN_ID20);
        lc.setCircuitAllowed(CV, true);
        lc.setLatestHeight(0);

        // snarkRequired=false for flexibility; can flip in tests
        verifier = new EezoSnarkVerifier(address(lc), CV, false);
    }

    function test_happy_path_verify_and_store() public {
        uint64 height = 1;
        bytes32 pi = keccak256("eezo_pi_digest_v1");
        bytes memory proof = abi.encodePacked(pi); // placeholder rule: proof == digest bytes

        uint256 gasBefore = gasleft();
        vm.recordLogs();

        verifier.verifyAndStorePiDigest(height, pi, proof);

        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("gas_used_verifyAndStorePiDigest", gasUsed);
        emit log_named_uint("proof_len", proof.length);

        // state written into LC
        assertEq(lc.piDigestOf(height), pi, "piDigest not stored in LC");

        // event emitted
        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool saw = false;
        for (uint256 i = 0; i < entries.length; i++) {
            // topic0 = keccak("SnarkVerifiedAndStored(uint64,bytes32,uint32,uint256)")
            if (
                entries[i].topics.length > 0 &&
                entries[i].topics[0] == keccak256("SnarkVerifiedAndStored(uint64,bytes32,uint32,uint256)")
            ) {
                saw = true;
                break;
            }
        }
        assertTrue(saw, "missing SnarkVerifiedAndStored event");
    }

    function test_tamper_one_byte_reverts() public {
        uint64 height = 1;
        bytes32 pi = keccak256("eezo_pi_digest_v1");
        bytes memory proof = abi.encodePacked(pi);

        // tamper: flip the first byte of the proof
        proof[0] = bytes1(uint8(proof[0]) ^ 0x01);

        vm.expectRevert(EezoSnarkVerifier.ErrProofInvalid.selector);
        verifier.verifyAndStorePiDigest(height, pi, proof);
    }

    function test_chain_id_mismatch_reverts() public {
        uint64 height = 1;
        bytes32 pi = keccak256("eezo_pi_digest_v1");
        bytes memory proof = abi.encodePacked(pi);

        // change LC's reported chain id after verifier construction to trigger mismatch
        bytes20 newChainId20 = bytes20(uint160(2));
        lc.setExpectedChainId20(newChainId20);

        // match selector + both args exactly
        vm.expectRevert(
            abi.encodeWithSelector(
                EezoSnarkVerifier.ErrChainIdMismatch.selector,
                CHAIN_ID20,
                newChainId20
            )
        );
        verifier.verifyAndStorePiDigest(height, pi, proof);
    }

    function test_circuit_not_allowed_reverts() public {
        uint64 height = 1;
        bytes32 pi = keccak256("eezo_pi_digest_v1");
        bytes memory proof = abi.encodePacked(pi);

        lc.setCircuitAllowed(CV, false);

        vm.expectRevert(
            abi.encodeWithSelector(
                EezoSnarkVerifier.ErrCircuitNotAllowed.selector,
                CV
            )
        );
        verifier.verifyAndStorePiDigest(height, pi, proof);
    }

    function test_height_not_monotonic_reverts() public {
        // set latest to 5; requesting height 5 should fail (must be strictly greater)
        lc.setLatestHeight(5);

        uint64 height = 5;
        bytes32 pi = keccak256("eezo_pi_digest_v1");
        bytes memory proof = abi.encodePacked(pi);

        vm.expectRevert(
            abi.encodeWithSelector(
                EezoSnarkVerifier.ErrReorgOrPastHeight.selector,
                uint64(5),
                uint64(5)
            )
        );
        verifier.verifyAndStorePiDigest(height, pi, proof);
    }
}
