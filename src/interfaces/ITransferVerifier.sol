// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @title ITransferVerifier
/// @notice Interface for Groth16 verifier of transfer transaction proofs
/// @dev Generated from transfer circom circuit. Verifies 2-input 3-output transactions.

interface ITransferVerifier {
    /// @notice Verifies a Groth16 proof for a transfer transaction
    /// @param _pA First elliptic curve point (2 uint256 coordinates)
    /// @param _pB Second elliptic curve point (2x2 uint256 coordinates)
    /// @param _pC Third elliptic curve point (2 uint256 coordinates)
    /// @param _pubSignals Public inputs: [null0, null1, leaf0, leaf1, leaf2, anchor, ethKey]
    /// @return True if the proof is valid
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[7] calldata _pubSignals
    ) external view returns (bool);
}
