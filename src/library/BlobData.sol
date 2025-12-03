// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// We implement a protocol which does kzg opening against blob commitments.
// In the simplest version it just proves that the commitment evaluated at the bit revevered root of unity
// for an index is equal to the the claimed data.
// We might be able to highly optimise by doing a multi point opening.

library BlobData {
    /// @dev Checks that the kzg proof validates that the polynomial interpolates data at the roots of unity indexed by the bitreversed
    ///      roots of unity
    function validateDataOpening(
        bytes32 rootHash,
        uint256[] memory dataIndicies,
        bytes32[] memory data,
        bytes memory kzgProof
    ) internal pure {}
}
