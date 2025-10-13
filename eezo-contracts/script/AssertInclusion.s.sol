// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

// minimal iface to the light client
interface LC {
    function assertInclusion(
        uint64 height,
        bytes32 leaf,
        uint256 index,
        bytes32[] calldata branch
    ) external;
}

contract AssertInclusion is Script {
    function run() external {
        address lc = vm.envAddress("LC_ADDR");

        // default json path can be overridden via TX_PROOF_JSON
        string memory jsonPath = vm.envOr("TX_PROOF_JSON", string("./proof/tx_proof.json"));
        string memory json = vm.readFile(jsonPath);

        // decode json fields (expects hex for leaf/branch; number for height/index)
        uint64 height = abi.decode(vm.parseJson(json, ".height"), (uint64));
        bytes32 leaf = abi.decode(vm.parseJson(json, ".leaf"), (bytes32));
        uint256 index = abi.decode(vm.parseJson(json, ".index"), (uint256));
        bytes32[] memory branch = abi.decode(vm.parseJson(json, ".branch"), (bytes32[]));

        vm.startBroadcast();
        LC(lc).assertInclusion(height, leaf, index, branch);
        vm.stopBroadcast();
    }
}
