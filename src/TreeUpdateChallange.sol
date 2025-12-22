// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./library/PredictableMerkleLib.sol";
import {Proof} from "./library/ZKVerifier.sol";
import "./Spine.sol";
import "./SequencerRegistry.sol";

// The component of the challange system which enforces deposits are done properly

contract TreeUpdateChallange is Spine, SequencerRegistry {
    using PredictableMerkleLib for IUpdateVerifier;

    // Note- the updateNr corresponds to which group of three elements plus root is challanged
    // TODO - This function is requiring us to use via-ir, we could just get better structs, see whats
    //        natural after the other challange protocols
    function challangeTreeUpdate(
        BlockData memory data,
        uint256 updateNr,
        bool isTx,
        Region calldata region,
        Region calldata extensionRegion,
        bytes32 priorAnchor,
        bytes calldata priorAnchorCommitment,
        bytes calldata priorAnchorProof,
        bytes32 trueAnchor,
        Proof memory zk
    ) external {
        uint256 blockNr = data.blockNr;
        // Check the block is in the tree
        require(isBlockIncluded(data));

        uint256 memoryAddress;
        if (isTx) {
            memoryAddress = txMemoryAddress(updateNr, data.numDeposits) + 12;
        } else {
            memoryAddress = updateNr * 4;
        }

        // Validate the first region
        assert(region.length != 0);
        uint256 firstBlobNumber = memoryAddress / 4096;
        require(region.hash == data.blobhashes[firstBlobNumber]);
        require(region.memoryAddress == (memoryAddress % 4096));
        validateRegionOpening(region);
        // Because tx are 15 elements we can have them aligned at memory region boundries.
        if (region.length != 4) {
            // We still want 4 in total
            assert(region.length + extensionRegion.length == 4);
            // We enforce that this actually at the end of the blob.
            assert(region.memoryAddress + region.length + 1 == 4096);
            require(extensionRegion.hash == data.blobhashes[firstBlobNumber + 1]);
            require(extensionRegion.memoryAddress == 0);
            validateRegionOpening(extensionRegion);
        }

        // Now we have validated that the positions that the seqeuncer submitted are equal to claimed seqeuncerSubmittedData
        // So we have to check that the prior anchor when updated is not equal to seqeuncerSubmittedData[3] which is the new root
        validatePriorAnchor(priorAnchor, data, updateNr, true, priorAnchorCommitment, priorAnchorProof);

        // Now we can prove that the update from priorAnchor to current anchor is not correct using the zk update proof
        // TODO - Fix block index in tree
        bytes32[6] memory zkProofInputs =
            [priorAnchor, bytes32(uint256(0)), region.data[0], bytes32(uint256(0)), bytes32(uint256(0)), trueAnchor];
        zkProofInputs[3] = region.memoryAddress + 1 == 4096 ? extensionRegion.data[0] : region.data[1];
        uint256 absoluteIndex = region.memoryAddress + 2;
        zkProofInputs[4] = absoluteIndex >= 4096 ? extensionRegion.data[absoluteIndex % 4096] : region.data[2];
        absoluteIndex = region.memoryAddress + 3;
        bytes32 seqeuncerSubmitedRoot =
            absoluteIndex >= 4096 ? extensionRegion.data[absoluteIndex % 4096] : region.data[3];

        // This call validates a zk update proof that the update of the prior anchor with the three new leaves equals
        // the "true anchor" provided by the caller.
        require(predictableUpdateVerifier.verfiyPredictableUpdate(zkProofInputs, zk), "Invalid ZK update proof");

        // We have two options (1) that the seqeuncer has not added the correct root to the blob
        // (2) that if this is the last tx in the block that the seqeuncer has set their "anchor" field correctly
        if (trueAnchor == seqeuncerSubmitedRoot) {
            bool isLast =
                (updateNr == data.numTransactions) || (data.numTransactions == 0 && updateNr == data.numDeposits);
            require(isLast && trueAnchor != data.anchor, "No Fraud");
        } // the else here is just that you should be slashed

        // Since the seqeuncer submitted the wrong deposit leaf at this index we slash and roll back.
        slash(data.sequencer, blockNr);
        rollback(data.blockNr - 1);
    }
}

