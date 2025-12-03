// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Should implement a version of the hash which matches the hash used in the zk proofs
// Will be inherited by withdraws, deposits, and merkle tree lib

library PoseidonHashLib {
    /// @dev Should match the hash done in the zk lib
    function hash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return (bytes32)(0);
    }
}
