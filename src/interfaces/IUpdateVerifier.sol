// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/// @title IUpdateVerifier
/// @notice Interface for Groth16 verifier of merkle tree update proofs
/// @dev Generated from predictableUpdate circom circuit. Verifies 3-element batch insertions.

interface IUpdateVerifier {
    /// @notice Verifies a Groth16 proof for a merkle tree update
    /// @param _pA First elliptic curve point (2 uint256 coordinates)
    /// @param _pB Second elliptic curve point (2x2 uint256 coordinates)
    /// @param _pC Third elliptic curve point (2 uint256 coordinates)
    /// @param _pubSignals Public inputs: [anchorBefore, blockIndex, update0, update1, update2, anchorAfter]
    /// @return True if the proof is valid
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[6] calldata _pubSignals
    ) external view returns (bool);
}
