// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";

interface LC_PI {
    function storePiDigest(uint64 height, bytes32 digest) external;
}

/// Usage:
///   LC_ADDR=<lc address> HEIGHT=<h>
///   (one of)
///     PI_DIGEST_HEX=path/to/pi_digest.hex   # file containing 0x<64-hex>
///     PI_DIGEST=0x<64-hex>                  # direct hex string
///   [optional] PI_DIGEST_REQUIRED=true      # enforce presence of digest (strict)
///
/// Examples:
///   forge script script/StorePiDigest.s.sol:StorePiDigest \
///     --rpc-url $RPC --private-key $PK \
///     -vvvv --broadcast \
///     --sig "run()" \
///     --env LC_ADDR=$LC_ADDR HEIGHT=42 PI_DIGEST_HEX=/tmp/h42/pi_digest.hex
///
///   forge script script/StorePiDigest.s.sol:StorePiDigest \
///     --rpc-url $RPC --private-key $PK \
///     -vvvv --broadcast \
///     --sig "run()" \
///     --env LC_ADDR=$LC_ADDR HEIGHT=42 PI_DIGEST=0xdead...beef PI_DIGEST_REQUIRED=true
contract StorePiDigest is Script {
    function run() external {
        address lc = _envAddr("LC_ADDR");
        uint64 height = _envU64("HEIGHT");
        require(lc != address(0), "LC_ADDR is required");
        require(height != 0, "HEIGHT is required");

        // strict toggle mirrors relay: default off
        bool required = vm.envOr("PI_DIGEST_REQUIRED", false);

        // source 1: file path containing 32-byte 0x-hex
        string memory pidPath = vm.envOr("PI_DIGEST_HEX", string(""));
        // source 2: direct 0x-hex string
        string memory pidHex  = vm.envOr("PI_DIGEST", string(""));

        bytes32 digest;
        bool have = false;

        if (bytes(pidPath).length > 0) {
            bytes memory raw = vm.parseBytes(vm.readFile(pidPath));
            require(raw.length == 32, "PI_DIGEST_HEX must decode to 32 bytes");
            assembly { digest := mload(add(raw, 32)) }
            have = true;
            console2.log("loaded digest from file:", pidPath);
        } else if (bytes(pidHex).length > 0) {
            // parseBytes handles 0x… hex → bytes
            bytes memory raw2 = vm.parseBytes(pidHex);
            require(raw2.length == 32, "PI_DIGEST must decode to 32 bytes");
            assembly { digest := mload(add(raw2, 32)) }
            have = true;
            console2.log("loaded digest from PI_DIGEST env");
        } else {
            // nothing provided
            if (required) revert("PI_DIGEST_REQUIRED=1 but no PI_DIGEST[_HEX] provided");
            console2.log("no digest provided (optional mode) - nothing to submit");
            return;
        }

        vm.startBroadcast();
        LC_PI(lc).storePiDigest(height, digest);
        vm.stopBroadcast();

        console2.log("storePiDigest ok: height=%s, digest=0x%s", height, vm.toString(digest));
    }

    // --- helpers ---
    function _envAddr(string memory k) internal view returns (address) {
        // forge supports vm.envAddress since v1. Foundry also supports envOr for address.
        // Use envOr for compatibility.
        return vm.envOr(k, address(0));
    }
    function _envU64(string memory k) internal view returns (uint64) {
        // vm.envOr returns uint256 by default; cast explicitly to uint64
        return uint64(vm.envOr(k, uint256(0)));
    }
}
