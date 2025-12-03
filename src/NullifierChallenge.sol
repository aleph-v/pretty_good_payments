// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./SequencerRegistry.sol";
import "./library/BlobData.sol";

// The component of the challange system which enforces that nullifiers are not repeated

contract NullifierChallenge is Spine, SequencerRegistry {
    // Enforces that we do not have nullifier reuse.
    // Since we have commitments to the kzg data structure at each block we can just open and compare
    // the entries in two former blobs, and if they are equal then we can slash the proposer
    // TODO - LOTS of code reuse and repition, do with a struct plus method for nullifier loading
    function challengeNullifier(
        uint256 blockNumberChallanged,
        uint256 blockNumberPrior,
        uint256 txNumberChallanged,
        uint256 nullifierIndexChallanged,
        uint256 txNumberPrior,
        uint256 nullifierIndexPrior,
        bytes32[] memory nullifier,
        bytes memory kzgProofChallanged,
        bytes memory kzgProofPrior
    ) external {
        uint256[] memory index = new uint256[](1);
        require(nullifier.length == 1);
        // We challange only the newer block, but they can be equal if the nullifier is reused
        require(blockNumberChallanged >= blockNumberPrior);
        // But if the two are in the same block we cannot have them be literally the same tx.
        if (blockNumberChallanged == blockNumberPrior) {
            require(txNumberChallanged != txNumberPrior);
        }

        bytes32 rootChallanged = roots[blockNumberChallanged];
        ProposedBlock memory blockDataChallanged = blockdata[roots[blockNumberChallanged]];
        bytes32 rootPrior = roots[blockNumberChallanged];
        ProposedBlock memory blockDataPrior = blockdata[roots[blockNumberPrior]];
        // TODO specify the blob to load for both

        // Load the blob roots then
        // index[0] = computeBlobOffsetNullifier(blockNumberChallanged, txNumberChallanged, nullifierIndexChallanged);
        //BlobData.validateDataOpening(rootHashChallanged, index, nullifier, kzgProofChallanged);
        // index[0] = computeBlobOffsetNullifier(blockNumberPrior, txNumberPrior, nullifierIndexPrior);
        //BlobData.validateDataOpening(rootHashPrior, index, nullifier, kzgProofPrior);

        // This means then that both of the blobs have a nullifier which is equal so then we do
        // TODO - Other checks.
        slash(blockDataChallanged.sequencer, blockNumberChallanged);
        rollback(blockNumberChallanged - 1);
    }

    function computeBlobOffsetNullifier(uint256 blockNumber, uint256 txNumber, uint256 nullifierNumber)
        internal
        returns (uint256)
    {
        // Loads the number of tx and deposits in block number then computes the memory offset using the determistic sizes
        return (0);
    }
}

