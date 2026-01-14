// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./library/PredictableMerkleLib.sol";
import "./Spine.sol";
import "./SequencerRegistry.sol";

// The component of the challenge system which enforces deposits are done properly

contract TreeUpdateChallenge is Spine, SequencerRegistry {
    using PredictableMerkleLib for IUpdateVerifier;

    // Note- The update NR for deposits is the nth field
    // TODO - This function is requiring us to use via-ir, we could just get better structs, see whats
    //        natural after the other challenge protocols
    function challengeTreeUpdate(
        BlockData memory data,
        uint256 updateNr,
        bool isTx,
        Region calldata region,
        Region calldata extensionRegion,
        bytes32 priorAnchor,
        bytes calldata priorAnchorCommitment,
        bytes calldata priorAnchorProof,
        bytes32 trueAnchor,
        Proof memory zk,
        BlockData memory rollbackTargetBlock
    ) external {
        // Check the block is in the tree
        require(isBlockIncluded(data));

        uint256 memoryAddress;
        if (isTx) {
            require(updateNr < data.numTransactions);
            memoryAddress = txMemoryAddress(updateNr, data.numDeposits) + 11;
        } else {
            require(updateNr < (data.numDeposits + 2) / 3);
            // Points to the start of each group of three updates
            memoryAddress = updateNr * 4;
        }

        // Validate the first region
        assert(region.length != 0);
        uint256 firstBlobNumber = memoryAddress / 4096;
        require(region.hash == data.blobhashes[firstBlobNumber]);
        require(region.memoryAddress == (memoryAddress % 4096));
        validateRegionOpening(region);
        // This check is critical even with an empty extension region as it forces an empty region
        // to have empty data.
        validateRegionOpening(extensionRegion);
        require(region.length + extensionRegion.length == 4, "Not enough data");

        // Because tx are 4 elements we can have them aligned at memory region boundaries.
        if (extensionRegion.length != 0) {
            // We enforce that this actually at the end of the blob.
            assert(region.memoryAddress + region.length == 4096);
            require(extensionRegion.hash == data.blobhashes[firstBlobNumber + 1]);
            require(extensionRegion.memoryAddress == 0);
            validateRegionOpening(extensionRegion);
        }

        // Now we have validated that the positions that the sequencer submitted are equal to claimed sequencerSubmittedData
        // So we have to check that the prior anchor when updated is not equal to sequencerSubmittedData[3] which is the new root
        validatePriorAnchor(priorAnchor, data, updateNr, !isTx, priorAnchorCommitment, priorAnchorProof);

        // We calculate the actual block index as the day*blocksPerDay + blockIndex
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Now we can prove that the update from priorAnchor to current anchor is not correct using the zk update proof
        bytes32[6] memory zkProofInputs =
            [priorAnchor, bytes32(treeIndex), region.data[0], bytes32(uint256(0)), bytes32(uint256(0)), trueAnchor];
        zkProofInputs[3] = region.memoryAddress + 1 == 4096 ? extensionRegion.data[0] : region.data[1];
        uint256 absoluteIndex = region.memoryAddress + 2;
        zkProofInputs[4] = absoluteIndex >= 4096 ? extensionRegion.data[absoluteIndex % 4096] : region.data[2];
        absoluteIndex = region.memoryAddress + 3;
        bytes32 sequencerSubmittedRoot =
            absoluteIndex >= 4096 ? extensionRegion.data[absoluteIndex % 4096] : region.data[3];

        // This call validates a zk update proof that the update of the prior anchor with the three new leaves equals
        // the "true anchor" provided by the caller.
        require(predictableUpdateVerifier.verifyPredictableUpdate(zkProofInputs, zk), "Invalid ZK update proof");

        // We have two options (1) that the sequencer has not added the correct root to the blob
        // (2) that if this is the last tx in the block that the sequencer has set their "anchor" field correctly
        if (trueAnchor == sequencerSubmittedRoot) {
            // We underflow here if both numTransactions and numDeposits == 0 but this case cannot happen because add block reverts
            // Note that since updateNr is zero indexed data.numDeposits/3 does give the correct last update nr group
            bool isLast =
                data.numTransactions == 0 ? updateNr == data.numDeposits / 3 : updateNr == data.numTransactions - 1;
            require(isLast && trueAnchor != data.anchor, "No Fraud");
        } // the else here is just that you should be slashed

        // Since the sequencer submitted the wrong deposit leaf at this index we slash and roll back.
        slash(data.sequencer, data.blockNr);
        rollback(data.blockNr, rollbackTargetBlock);
    }
}
