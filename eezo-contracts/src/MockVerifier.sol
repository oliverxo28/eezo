// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Use the existing interface declared inside EezoLightClient.sol
import { IVerifier } from "./EezoLightClient.sol";

contract MockVerifier is IVerifier {
    function verify(bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
