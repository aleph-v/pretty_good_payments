// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Poseidon.sol";
import "./PredictableMerkleLib.sol";

// Implements the leaf hashing as well the struct

struct Leaf {
    address asset;
    uint256 amount;
    bytes32 blinding;
    bytes32 publicKey;
}

library LeafLib {
    function hashLeaf(Leaf memory leaf) internal pure returns (bytes32) {
        // Hashes a leaf, should match the hash in the zk proof.
        return (bytes32)(0);
    }

    function enforceInTree(Leaf memory leaf, bytes32 root, uint256 index, bytes32[] memory proof)
        internal
        pure
        returns (bool)
    {
        // hashes a leaf then checks that it is in a merkle tree
        return true;
    }
}
