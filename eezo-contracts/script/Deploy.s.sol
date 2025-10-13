// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {EezoLightClient} from "src/EezoLightClient.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast(); // uses --private-key passed to forge script
        new EezoLightClient(address(0));
        vm.stopBroadcast();
    }
}
