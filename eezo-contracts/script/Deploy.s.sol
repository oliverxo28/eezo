// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import {EezoLightClient} from "../src/EezoLightClient.sol";

/// @notice Deploys EezoLightClient with a real verifier and applies safety guards.
/// Required env:
///   VERIFIER          = 0x...   (address of verifier contract)
///   CHAIN_ID_20       = 0x...   (20-byte chain id; e.g., 0x...01)
///   CIRCUIT_VER       = uint    (zk circuit version to allow; 1 or 2)
/// Optional (allowlist another circuit version too):
///   NEXT_CIRCUIT_VER  = uint    (additional circuit version to allow)  [optional]
/// T34 rotation (suite ids, not circuit versions):
///   ACTIVE_SUITE_ID   = uint    (1 = ml-dsa-44, 2 = sphincs+)
///   NEXT_SUITE_ID     = uint    (0 to disable; otherwise upcoming suite id)
///   DUAL_ACCEPT_UNTIL = uint    (header height inclusive; 0 to disable)
contract Deploy is Script {
    function run() external {
        // --- read env ---
        address verifier   = vm.envAddress("VERIFIER");
        // we read CHAIN_ID_20 as address then cast to bytes20 (same 20 bytes)
        bytes20 chainId20  = bytes20(vm.envAddress("CHAIN_ID_20"));
        uint32 circuitVer  = uint32(vm.envUint("CIRCUIT_VER"));
        // Optional: pre-allow another circuit version (not the same as suite id)
        uint32 nextCircuit = uint32(vm.envOr("NEXT_CIRCUIT_VER", uint(0)));
        // T34 rotation envs (suite ids)
        uint8  activeSuite = uint8(vm.envOr("ACTIVE_SUITE_ID", uint(1)));
        uint8  nextSuite   = uint8(vm.envOr("NEXT_SUITE_ID", uint(0)));
        uint64 dualUntil   = uint64(vm.envOr("DUAL_ACCEPT_UNTIL", uint(0)));

        vm.startBroadcast(); // uses --private-key passed to forge script

        // deploy with real verifier wired
        EezoLightClient lc = new EezoLightClient(verifier);

        // apply safety guards (chain binding + circuit allow-list)
        lc.setExpectedChainId(chainId20);
        lc.setCircuitAllowed(circuitVer, true);
        if (nextCircuit != 0 && nextCircuit != circuitVer) {
            lc.setCircuitAllowed(nextCircuit, true);
        }

        // T34: schedule suite rotation (or just set active suite), if provided
        if (nextSuite != 0 || dualUntil != 0) {
            lc.scheduleSuiteRotation(activeSuite, nextSuite, dualUntil);
        } else {
            // ensure active suite is set explicitly and window closed
            lc.activateSuite(activeSuite);
        }

        vm.stopBroadcast();

        // logs
        console2.log("EezoLightClient:", address(lc));
        console2.log("Verifier:", verifier);
        console2.log("ChainId20:", address(chainId20));
        console2.log("CircuitVer allowed:", circuitVer);
        if (nextCircuit != 0 && nextCircuit != circuitVer) {
            console2.log("CircuitVer also allowed:", nextCircuit);
        }
        console2.log("Suite rotation:");
        console2.log("  activeSuiteId:", activeSuite);
        console2.log("  nextSuiteId:", nextSuite);
        console2.log("  dualAcceptUntil:", dualUntil);
    }
}

