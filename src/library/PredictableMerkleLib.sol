// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Poseidon.sol";

// Implements verification functions for an append only merkle tree addition verification

library PredictableMerkleLib {
    // NOTE we can use predictable sized arrays here

    /// @dev Computes a root from an index, proof, and leaf
    function computeRoot(bytes32 leaf, uint256 index, bytes32[] memory path) internal pure returns (bytes32) {
        // Uses the binary format of the index to do left and right.
        // We do not check higher order index bits here, caller must check.
        return (bytes32)(0);
    }

    /// TODO - Just use multi point opening algo plus paths. Need for the multi update anyway

    /// @dev This predictably updates a single field from zero to nonzero.
    /// We call this with a proof opening the zero leaf
    function predictableUpdate(bytes32 rootBefore, bytes32 newLeaf, uint256 index, bytes32[] memory path)
        internal
        pure
        returns (bytes32)
    {
        // First compute the root
        require(computeRoot((bytes32)(0), index, path) == rootBefore);

        // Then we add a check that either we are the first element in a block or that the nodes to the left are nonzero
        // TODO - add constants for the sizes then compute block position by zeroing those bits in index
        // TODO - Multi case: if block position is zero we pass, if block position is odd check first element of path !=, if even hash left nodes check that the hash is equal to first element of path and nonzero

        return computeRoot(newLeaf, index, path);
    }
}
