// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { EezoLightClient } from "../src/EezoLightClient.sol";
import { MockVerifier } from "../src/MockVerifier.sol";

contract EezoLightClientTest is Test {
    EezoLightClient lc;
    MockVerifier mv;
    // keep lowercase preference in the label; value is just bytes
    bytes20 constant CHAIN = bytes20(uint160(uint256(keccak256("eezo-test"))));

    function setUp() public {
        mv = new MockVerifier();
        lc = new EezoLightClient(address(mv));
        lc.setCircuitAllowed(2, true);
        lc.setExpectedChainId(CHAIN);
    }

    function _v2(
        uint64 h,
        bytes32 txr,
        bytes32 st,
        bytes32 sigdig,
        uint32 bl,
        uint32 suite
    ) internal pure returns (bytes memory) {
        // IMPORTANT: include chainId20 (field 7) and suiteId (field 8)
        return abi.encode(
            EezoLightClient.HeaderV2({
                circuitVersion: 2,
                height: h,
                txRootV2: txr,
                stateRootV2: st,
                sigBatchDigest: sigdig,
                batchLen: bl,
                chainId20: CHAIN,
                suiteId: suite   // 1 = ml-dsa-44 (active by default)
            })
        );
    }

    function test_store_header_success() public {
        bytes32 txr = keccak256("txroot");
        bytes32 st  = keccak256("stroot");
        lc.verifyAndStore("", _v2(42, txr, st, bytes32(uint256(1)), 4, 1));
        assertTrue(lc.hasHeader(42));
    }

    function test_guards_zero_root_reverts() public {
        vm.expectRevert(bytes("zero root"));
        lc.verifyAndStore("", _v2(1, keccak256("t"), bytes32(0), bytes32(uint256(2)), 4, 1));
    }

    // --- T34: rotation window behavior ---

    function test_next_suite_within_window_ok() public {
        // open dual-accept window for next suite (2) until height 100
        lc.scheduleSuiteRotation(1, 2, 100);
        bytes32 txr = keccak256("txroot2");
        bytes32 st  = keccak256("stroot2");
        // encode header using next suite (2) at height 50 (inside window)
        bytes memory pi = _v2(50, txr, st, bytes32(uint256(3)), 4, 2);
        lc.verifyAndStore("", pi);
        assertTrue(lc.hasHeader(50));
        // suiteOf mapping should reflect the header's suite
        assertEq(lc.suiteOf(50), 2);
    }

    function test_next_suite_after_window_reverts() public {
        // window only until height 10
        lc.scheduleSuiteRotation(1, 2, 10);
        bytes32 txr = keccak256("txroot3");
        bytes32 st  = keccak256("stroot3");
        // height 11 (outside window) with suiteId=2 should revert
        bytes memory pi = _v2(11, txr, st, bytes32(uint256(4)), 4, 2);
        vm.expectRevert(bytes("suite not accepted"));
        lc.verifyAndStore("", pi);
    }

    function test_suiteOf_is_recorded_for_active() public {
        // store an active-suite header and check mapping
        bytes32 txr = keccak256("txrootA");
        bytes32 st  = keccak256("strootA");
        lc.verifyAndStore("", _v2(77, txr, st, bytes32(uint256(5)), 4, 1));
        assertTrue(lc.hasHeader(77));
        assertEq(lc.suiteOf(77), 1);
    }

    function test_after_activate_next_old_suite_rejected() public {
        // simulate rotation complete: activate 2, clear window
        lc.activateSuite(2);
        bytes32 txr = keccak256("txroot4");
        bytes32 st  = keccak256("stroot4");
        // old suiteId=1 should be rejected now
        vm.expectRevert(bytes("suite not accepted"));
        lc.verifyAndStore("", _v2(200, txr, st, bytes32(uint256(6)), 4, 1));
    }
}
