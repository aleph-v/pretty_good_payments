// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @title ZeroTree
/// @notice Library for computing the root of an empty merkle tree
/// @dev Uses Poseidon hashing consistent with PredictableMerkleLib
library ZeroTree {
    uint256 constant TREE_DEPTH = 44;

    /// @notice Computes the root of an empty merkle tree (all zero leaves)
    /// @dev Zero leaf = 0 (constant), then recursively hash up the tree
    /// @return The root hash of an empty tree with depth 44
    function computeZeroTreeRoot() internal pure returns (bytes32) {
        // Start with constant 0 as the leaf value (not a hash of zero leaf)
        bytes32 currentHash = bytes32(0);

        // For each level, hash(currentHash, currentHash) to get the next level
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            uint256[2] memory nodeInputs = [uint256(currentHash), uint256(currentHash)];
            currentHash = bytes32(PoseidonT3.hash(nodeInputs));
        }

        return currentHash;
    }
}
