// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";

// expanded interface to the light client
interface LC {
    function verifyAndStore(bytes calldata proof, bytes calldata publicInputs) external;
    function storePiDigest(uint64 height, bytes32 digest) external;
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
        console2.log("verifyAndStore ok (pubin=%s, proof=%s)", pubinPath, proofPath);
        
        // optional canonical PI digest (0x.. hex32). If provided, we store it.
        string memory pidPath = vm.envOr("PI_DIGEST_HEX", string(""));
        bool digestRequired = vm.envOr("PI_DIGEST_REQUIRED", false);
        if (bytes(pidPath).length == 0 && digestRequired) {
            revert("PI_DIGEST_REQUIRED=1 but PI_DIGEST_HEX not provided");
        }
        if (bytes(pidPath).length > 0) {
            bytes memory pid = vm.parseBytes(vm.readFile(pidPath));
            require(pid.length == 32, "pi_digest must be 32 bytes");
            bytes32 d;
            assembly { d := mload(add(pid, 32)) }

            // height must be provided when submitting digest
            uint64 height = uint64(vm.envOr("HEIGHT", uint256(0)));
            require(height != 0, "HEIGHT required for storePiDigest");

            LC(lc).storePiDigest(height, d);
            console2.log("storePiDigest ok (height=%s, digest=0x%s)", height, vm.toString(d));
        }
        
        vm.stopBroadcast();
    }
}