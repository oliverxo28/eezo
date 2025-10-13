// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {EezoLightClient} from "../src/EezoLightClient.sol";

// --- Test Harness ---
contract EezoLightClientHarness is EezoLightClient {
    constructor() EezoLightClient(address(0)) {}

    function __setHeader(HeaderV2 memory h) external {
        headers[h.height] = h;
    }

    function __merkleUp(bytes32 leaf, uint256 index, bytes32[] memory branch)
        external
        pure
        returns (bytes32)
    {
        return _merkleUp(leaf, index, branch);
    }
}
// --------------------

contract EezoLightClientInclusionTest is Test {
    EezoLightClientHarness lc;

    function setUp() public {
        lc = new EezoLightClientHarness();
    }

    function test_MerkleInclusion_4leaf_tree() public {
        // --- Leaves
        bytes32 l0 = keccak256("L0");
        bytes32 l1 = keccak256("L1");
        bytes32 l2 = keccak256("L2");
        bytes32 l3 = keccak256("L3");

        // --- Parents + root
        bytes32 p01 = keccak256(bytes.concat(l0, l1));
        bytes32 p23 = keccak256(bytes.concat(l2, l3));
        bytes32 root = keccak256(bytes.concat(p01, p23));

        // --- Header install
        EezoLightClient.HeaderV2 memory h = EezoLightClient.HeaderV2({
            circuitVersion: 2,
            height: 42,
            txRootV2: root,
            stateRootV2: bytes32(0),
            sigBatchDigest: bytes32(0),
            batchLen: 4
        });
        lc.__setHeader(h);

        // --- Merkle branch for leaf2 (index=2 = 0b10)
        bytes32[] memory branch = new bytes32[](2);
        branch[0] = l3; // level 0
        branch[1] = p01; // level 1

        // --- Positive case
        bool ok = lc.verifyInclusion(42, l2, 2, branch);
        assertTrue(ok, "expected inclusion ok for l2/index=2");

        // --- Negative index
        bool badIdx = lc.verifyInclusion(42, l2, 0, branch);
        assertFalse(badIdx);

        // --- Negative branch
        bytes32[] memory badBranch = new bytes32[](2);
        badBranch[0] = l0;
        badBranch[1] = p01;
        bool badBr = lc.verifyInclusion(42, l2, 2, badBranch);
        assertFalse(badBr);

        // --- Merkle recompute direct check
        bytes32 recomputed = lc.__merkleUp(l2, 2, branch);
        assertEq(recomputed, root, "recomputed root mismatch");
    }
}

