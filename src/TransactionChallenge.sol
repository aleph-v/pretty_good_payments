// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./SequencerRegistry.sol";
import "./library/BlobData.sol";
import "./library/PredictableMerkleLib.sol";
import "./library/ZKVerifier.sol";

// The component of the challange system which enforces deposits are done properly

contract TransactionChallenge is Spine, SequencerRegistry {
    function challangeTxZK(
        uint256 blockNumber,
        uint256 txNumber,
        bytes32[] memory merkleProof,
        bytes32[] memory leaves
    ) external {
        // First calls validate TX data
        // Then forwards the public inputs from the blob data and the zk proof to the zk verification lib.
    }
}
