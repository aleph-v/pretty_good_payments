// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./SequencerRegistry.sol";
import "./library/BlobData.sol";
import "./library/PredictableMerkleLib.sol";
import "./library/ZKVerifier.sol";

// The component of the challange system which enforces deposits are done properly

contract TransactionChallenge is Spine, SequencerRegistry {
    // A solidity version of the transaction struct
    // TODO we might want to turn this into a raw bytes32 array
    struct Transaction {
        bytes32 anchor;
        bytes32[2] leaves;
        bytes32[3] nullifiers;
        bytes zkProof;
        bytes32 newRoot;
    }

    function challangeTxState(
        uint256 blockNumber,
        uint256 txNumber,
        Transaction memory transaction,
        bytes32[] memory merkleProof,
        bytes32[] memory leaves
    ) external {
        // First calls validate TX data
        // Then checks if the anchor is in state, if it not we have proved fraud.
        // Then calls the merkle tree lib to validate the state update using the multi update validator
        // The root after updating the leaves should mismatch and we have proved fraud
    }

    function challangeTxZK(
        uint256 blockNumber,
        uint256 txNumber,
        Transaction memory transaction,
        bytes32[] memory merkleProof,
        bytes32[] memory leaves
    ) external {
        // First calls validate TX data
        // Then forwards the public inputs from the blob data and the zk proof to the zk verification lib.
    }

    function validateTxData(
        bytes32 blobhashClaimed,
        Transaction memory transaction,
        uint256 txIndex,
        bytes32 priorRoot
    ) internal {
        // We have two options for the prior root, one if this is the start of a blob or two if this is mid blob
        // If this is mid blob we load the bytes exactly prior to the tx (works for both deposit and tx)
        // If this the first tx blob need to solve later (I prefer to not record each intermediary root but this adds complexity)
    }
}
