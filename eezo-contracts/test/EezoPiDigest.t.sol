// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { EezoLightClient } from "../src/EezoLightClient.sol";
import { MockVerifier } from "../src/MockVerifier.sol"; // <--- FIX: Crucial Import

contract EezoPiDigestTest is Test {
    EezoLightClient lc;
    MockVerifier mv; // <--- FIX: MockVerifier state variable
    address admin = address(0xA11CE);
    // Consistent Chain ID for V2 header construction
    bytes20 constant CHAIN = bytes20(uint160(uint256(keccak256("eezo-test"))));

    function setUp() public {
        vm.startPrank(admin);
        
        mv = new MockVerifier(); // <--- FIX: Instantiate the mock verifier
        // FIX: Initialize the Light Client with the mock contract address
        lc = new EezoLightClient(address(mv)); 
        
        // Admin setup
        lc.setCircuitAllowed(2, true);
        lc.setExpectedChainId(CHAIN);
        vm.stopPrank();
    }

    // Helper to construct a minimal, valid V2 public input blob
    function _v2(uint64 h) internal pure returns (bytes memory) {
        return abi.encode(
            EezoLightClient.HeaderV2({
                circuitVersion: 2,
                height: h,
                txRootV2: keccak256("txroot"),
                stateRootV2: keccak256("stroot"),
                sigBatchDigest: bytes32(uint256(1)),
                batchLen: 4,
                chainId20: CHAIN,
                suiteId: 1 // default active
            })
        );
    }

    // This test confirms the 'Header First' submission flow (immediate commit)
    function testStorePiDigest_headerFirst_thenDigest_ok() public {
        vm.startPrank(admin);
        uint64 h = 42;
        bytes32 pi = keccak256("pi42_header_first");

        // 1) Store header at h=42. This now passes the external call check.
        bytes memory headerV2 = _v2(h);
        lc.verifyAndStore("", headerV2);

        // 2) Now store digest (should commit immediately)
        lc.storePiDigest(h, pi);

        assertEq(lc.piDigestOf(h), pi, "piDigest not stored");
        vm.stopPrank();
    }

    // This test confirms the 'Digest First' submission flow (staging and auto-commit)
    function testStorePiDigest_digestFirst_thenHeader_autoCommit_ok() public {
        vm.startPrank(admin);
        uint64 h = 50;
        bytes32 pi = keccak256("pi50_digest_first");

        // 1) Digest arrives first → staged
        lc.storePiDigest(h, pi);
        assertEq(lc.piDigestOf(h), bytes32(0), "digest should be staged, not committed yet");

        // 2) Now header arrives → should auto-commit staged digest
        bytes memory headerV2 = _v2(h);
        lc.verifyAndStore("", headerV2); // This now passes

        assertEq(lc.piDigestOf(h), pi, "staged piDigest not committed after header");
        vm.stopPrank();
    }
}