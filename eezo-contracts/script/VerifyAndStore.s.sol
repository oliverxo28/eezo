// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

// minimal iface to the light client
interface LC {
    function verifyAndStore(bytes calldata proof, bytes calldata publicInputs) external;
}

contract VerifyAndStore is Script {
    function run() external {
        // allow overrides via env if you want: LC_ADDR, PUBIN_HEX, PROOF_HEX
        address lc = vm.envAddress("LC_ADDR");

        // default paths; keep them as small hex files like: 0xabc...
        string memory pubinPath = vm.envOr("PUBIN_HEX", string("./proof/public_inputs.hex"));
        string memory proofPath = vm.envOr("PROOF_HEX", string("./proof/proof.hex"));

        // read hex -> bytes
        bytes memory pubin = vm.parseBytes(vm.readFile(pubinPath));
        bytes memory proof = vm.parseBytes(vm.readFile(proofPath));

        vm.startBroadcast();
        LC(lc).verifyAndStore(proof, pubin);
        vm.stopBroadcast();
    }
}
