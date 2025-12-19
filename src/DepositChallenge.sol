// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Deposits.sol";
import "./SequencerRegistry.sol";
import "./library/BlobData.sol";
import "./library/PredictableMerkleLib.sol";

// The component of the challange system which enforces deposits are done properly

contract DepositChallenge is Deposits, SequencerRegistry {
    // We load the block data and we get the expected deposit at a deposits index provided. The challanger
    // provides a predictable merkle tree update data and also a blob opening proof.
    function challangeDeposit(
        uint256 blockNumber,
        uint256 depositNumber,
        bytes32[] memory blobData,
        bytes memory kzgProof,
        bytes32[] memory merkleProof,
        uint256 merkleIndex
    ) external {
        // BlockData memory blockData = blockdata[roots[blockNumber]];
        // checkDepositChallange(blockNumber, depositNumber, blobData, kzgProof, merkleProof, merkleIndex);
        // TODO - Other checks.
        // slash(blockData.sequencer, blockNumber);
        // rollback(blockNumber - 1);
    }

    // This proceeds to check each case in order (1) that the number of deposits doesn't match (2) that the n th
    // deposit leaf in blob doesn't match and (3) that the predictable merkle update is wrong, we can exit at any step.
    function checkDepositChallange(
        uint256 blockNumber,
        uint256 depositNumber,
        bytes32[] memory blobData,
        bytes memory kzgProof,
        bytes32[] memory merkleProof,
        uint256 merkleIndex
    ) internal returns (bool) {
        return (false);
    }
}
