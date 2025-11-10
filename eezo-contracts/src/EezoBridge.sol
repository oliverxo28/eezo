// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IEezoLightClient {
    function headers(uint64 h) external view
        returns (uint32 circuitVersion, uint64 height, bytes32 txRootV2, bytes32 stateRootV2, bytes32 sigBatchDigest, uint32 batchLen);
    function hasHeader(uint64 h) external view returns (bool);
}

contract EezoBridge {
    IEezoLightClient public lc;
    address public admin;
    mapping(bytes32 => bool) public processed;

    event Claimed(bytes32 indexed depositId, address indexed to, uint256 amount, uint64 height);

    constructor(address _lc) {
        admin = msg.sender;
        lc = IEezoLightClient(_lc);
    }
    function setLightClient(address _lc) external {
        require(msg.sender == admin, "only admin");
        lc = IEezoLightClient(_lc);
    }
    function claim(bytes32 depositId, address to, uint256 amount, uint64 height) external {
        require(!processed[depositId], "already processed");
        require(lc.hasHeader(height), "no header");
        processed[depositId] = true;
        emit Claimed(depositId, to, amount, height);
    }
}
