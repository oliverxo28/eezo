// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IVerifier {
    function verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
}

contract MockVerifier is IVerifier {
    function verify(bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
