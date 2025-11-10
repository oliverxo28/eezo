// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { EezoLightClient } from "../src/EezoLightClient.sol";
import { EezoBridge } from "../src/EezoBridge.sol";

contract EezoBridgeTest is Test {
    EezoLightClient lc;
    EezoBridge bridge;
    // test-only chain id (lowercase label as you prefer)
    bytes20 constant CHAIN = bytes20(uint160(uint256(keccak256("eezo-test"))));

    function setUp() public {
        lc = new EezoLightClient(address(0));
        // T33.6: allow circuit v2 and (optionally) bind chain id
        lc.setCircuitAllowed(2, true);
        lc.setExpectedChainId(CHAIN);

        bridge = new EezoBridge(address(lc));
        EezoLightClient.HeaderV2 memory h = EezoLightClient.HeaderV2({
            circuitVersion: 2,
            height: 42,
            txRootV2: bytes32(uint256(0x11)),
            stateRootV2: bytes32(uint256(0x22)),
            sigBatchDigest: bytes32(uint256(0x33)),
            batchLen: 4,
            chainId20: CHAIN,
            suiteId: 1
        });
        lc.verifyAndStore(hex"020000002a00000000000000", abi.encode(h));
    }

    function testClaimOnce() public {
        bytes32 dep = keccak256("dep1");
        bridge.claim(dep, address(0xBEEF), 100, 42);
        assertTrue(bridge.processed(dep));
        vm.expectRevert(bytes("already processed"));
        bridge.claim(dep, address(0xBEEF), 100, 42);
    }

    function testRejectNoHeader() public {
        bytes32 dep = keccak256("dep2");
        vm.expectRevert(bytes("no header"));
        bridge.claim(dep, address(1), 1, 99);
    }
}
