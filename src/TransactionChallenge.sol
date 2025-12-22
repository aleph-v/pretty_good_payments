// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./SequencerRegistry.sol";
import "./library/BlobData.sol";
import "./library/PredictableMerkleLib.sol";

// The component of the challange system which enforces deposits are done properly

contract TransactionChallenge is Spine, SequencerRegistry {
    function challangeTxZK(
        BlockData memory data,
        uint256 txNr,
        Region calldata region,
        Region calldata extensionRegion,
        bytes calldata priorAnchorCommitment,
        bytes calldata priorAnchorProof,
        uint256 priorRootBlock,
        uint256 priorRootTx
    ) external {
        // Check the block is in the tree
        require(isBlockIncluded(data));

        // Get the absolute memory address implied by the number of TX
        uint256 memoryAddress = txMemoryAddress(txNr, data.numDeposits);

        // Validate the first region
        assert(region.length != 0);
        uint256 firstBlobNumber = memoryAddress / 4096;
        require(region.hash == data.blobhashes[firstBlobNumber]);
        require(region.memoryAddress == (memoryAddress % 4096));
        validateRegionOpening(region);
        // Because tx are 15 elements we can have them aligned at memory region boundries.
        // We check for length 14 because we don't need to open the anchor after (very last in mem)
        if (region.length != 14) {
            // We still want 4 in total
            assert(region.length + extensionRegion.length == 4);
            // We enforce that this actually at the end of the blob.
            assert(region.memoryAddress + region.length + 1 == 4096);
            require(extensionRegion.hash == data.blobhashes[firstBlobNumber + 1]);
            require(extensionRegion.memoryAddress == 0);
            validateRegionOpening(extensionRegion);
        }

        bytes32[14] memory raw;
        raw[0] = region.data[0];
        uint256 relativeLocation = region.memoryAddress;
        for (uint256 i = 1; i < 14; i++) {
            relativeLocation++;
            raw[i] = relativeLocation >= 4096 ? region.data[i] : extensionRegion.data[relativeLocation % 4096];
        }

        // TODO - Could do this fully no copy with assembly
        uint256[2] memory _pA = [uint256(raw[0]), uint256(raw[1])];
        uint256[2][2] memory _pB;
        _pB[0] = [uint256(raw[2]), uint256(raw[3])];
        _pB[1] = [uint256(raw[4]), uint256(raw[5])];
        uint256[2] memory _pC = [uint256(raw[6]), uint256(raw[7])];
        uint256[6] memory publicInputs =
            [uint256(raw[8]), uint256(raw[9]), uint256(raw[10]), uint256(raw[11]), uint256(raw[12]), uint256(raw[13])];

        // TODO - We want a more comprehensive system for prior roots with IDs, now we just check that the anchor was included
        bool anchorIncluded = isAnchorIncluded(raw[8]);
        // TODO - Is it possible to break the system by including a tx with a ref to a future anchor? (I think it would then include a hash of itself making it upredictable)
        bool proofVerifies = transactionZkVerifier.verifyProof(_pA, _pB, _pC, publicInputs);

        // Either the anchor is not included or
        require((!anchorIncluded) || (!proofVerifies), "No Fraud");

        slash(data.sequencer, data.blockNr);
        rollback(data.blockNr);
    }
}
