// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal interface for the Eezo Light Client rotation controls & views.
/// Adjust function names if your LC differs (but these match what we planned in T37.3).
interface IEezoLightClient {
    // views
    function latestHeight() external view returns (uint64);
    function activeSuiteId() external view returns (uint32);
    function nextSuiteId() external view returns (uint32);
    function dualAcceptUntil() external view returns (uint64);
    function allowedCircuit(uint32 cv) external view returns (bool);

    // admin/ops
    function setCircuitAllowed(uint32 cv, bool allowed) external;
    function scheduleSuiteRotation(uint32 activeSuite, uint32 nextSuite, uint64 dualAcceptUntilHeight) external;
    function activateSuite(uint32 suiteId) external;
}

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";

/// @title RotateSuite
/// @notice Foundry script to (1) allow cv=2, (2) open a dual-accept window (1→2),
///         and later (3) close by activating suite-2.
/// @dev Usage:
///   1) open window now using a delta (e.g., +96 blocks):
///      forge script script/RotateSuite.s.sol:RotateSuite --rpc-url $RPC_URL \
///        --private-key $DEPLOY_KEY --sig "open(address,uint32,uint32,uint64,bool)" \
///        $LC_ADDR 1 2 96 true --broadcast
///
///   2) close window (activate 2):
///      forge script script/RotateSuite.s.sol:RotateSuite --rpc-url $RPC_URL \
///        --private-key $DEPLOY_KEY --sig "close(address,uint32)" \
///        $LC_ADDR 2 --broadcast
contract RotateSuite is Script {
    /// @notice Open a dual-accept window from `activeSuite` → `nextSuite`.
    /// @param lcAddr           Light client address
    /// @param activeSuite      current active suite id (e.g., 1)
    /// @param nextSuite        next suite id (e.g., 2)
    /// @param dualUntilDelta   how many heights after current on-chain height to keep window open (e.g., 96)
    /// @param ensureCv2Allowed if true, call setCircuitAllowed(2,true) first
    function open(
        address lcAddr,
        uint32 activeSuite,
        uint32 nextSuite,
        uint64 dualUntilDelta,
        bool ensureCv2Allowed
    ) external {
        vm.startBroadcast();
        IEezoLightClient lc = IEezoLightClient(lcAddr);

        uint64 onchain = lc.latestHeight();
        uint64 dualUntil = onchain + dualUntilDelta;

        if (ensureCv2Allowed) {
            // one-time preflight to avoid relay reverts on "circuit not allowed"
            if (!lc.allowedCircuit(2)) {
                lc.setCircuitAllowed(2, true);
            }
        }

        // (re)open/adjust the window explicitly to the desired params
        lc.scheduleSuiteRotation(activeSuite, nextSuite, dualUntil);

        // helpful logs
        console2.log("rotate/open:");
        console2.log("  onchain height           =", onchain);
        console2.log("  activeSuite (requested)  =", activeSuite);
        console2.log("  nextSuite   (requested)  =", nextSuite);
        console2.log("  dualAcceptUntil (target) =", dualUntil);

        // read back
        console2.log("readback:");
        console2.log("  activeSuiteId    =", lc.activeSuiteId());
        console2.log("  nextSuiteId      =", lc.nextSuiteId());
        console2.log("  dualAcceptUntil  =", lc.dualAcceptUntil());
        console2.log("  allowedCircuit(2)=", lc.allowedCircuit(2));

        vm.stopBroadcast();
    }

    /// @notice Close the window by activating `suiteId` (e.g., 2). Optionally you can later disallow 1 manually.
    /// @param lcAddr   Light client address
    /// @param suiteId  suite to activate (e.g., 2)
    function close(address lcAddr, uint32 suiteId) external {
        vm.startBroadcast();
        IEezoLightClient lc = IEezoLightClient(lcAddr);

        lc.activateSuite(suiteId);

        console2.log("rotate/close:");
        console2.log("  activated suite =", suiteId);

        // read back
        console2.log("readback:");
        console2.log("  activeSuiteId    =", lc.activeSuiteId());
        console2.log("  nextSuiteId      =", lc.nextSuiteId());
        console2.log("  dualAcceptUntil  =", lc.dualAcceptUntil());
        console2.log("  allowedCircuit(2)=", lc.allowedCircuit(2));

        vm.stopBroadcast();
    }
}
