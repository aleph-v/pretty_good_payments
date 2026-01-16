// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PredictableMerkleLib, Proof} from "./library/PredictableMerkleLib.sol";
import {Spine} from "./Spine.sol";
import {SequencerRegistry} from "./SequencerRegistry.sol";
import {IUpdateVerifier} from "./interfaces/IUpdateVerifier.sol";
import {
    BlockNotIncluded,
    TxIndexOutOfBounds,
    UpdateIndexOutOfBounds,
    EmptyRegion,
    RegionBlobHashMismatch,
    RegionMemoryAddressMismatch,
    RegionLengthMismatch,
    RegionNotAtBlobBoundary,
    ExtensionMemoryNotZero,
    InvalidZKProof,
    NoFraud
} from "./library/Errors.sol";

/// @title TreeUpdateChallenge
/// @notice Fraud proof contract for challenging incorrect merkle tree updates in L2 blocks

contract TreeUpdateChallenge is Spine, SequencerRegistry {
    using PredictableMerkleLib for IUpdateVerifier;

    /// @notice Challenges an incorrect tree update (deposit group or transaction) in a submitted block
    /// @dev Verifies the challenger's claimed true anchor via ZK proof, then checks if sequencer's
    ///      submitted root differs. Slashes sequencer and rolls back chain if fraud is proven.
    /// @param data The block containing the allegedly fraudulent update
    /// @param updateNr Update index. For deposits: group index [0, ceil(numDeposits/3)).
    ///        For transactions: tx index [0, numTransactions).
    /// @param isTx True if challenging a transaction update, false for deposit group
    /// @param region KZG-proven blob region containing the 4 update fields (3 leaves + new root).
    ///        Must have length in [1,4] and match blob at calculated memory address.
    /// @param extensionRegion For cross-blob updates: continuation region from next blob. Empty if update fits in one blob.
    /// @param priorAnchor The merkle root before this update (validated via KZG or prior block anchor)
    /// @param priorAnchorCommitment KZG commitment for priorAnchor proof (if not first update in block)
    /// @param priorAnchorProof KZG proof for priorAnchor (if not first update in block)
    /// @param trueAnchor Challenger's claimed correct anchor after applying the update to priorAnchor
    /// @param zk Groth16 proof that priorAnchor + 3 leaves = trueAnchor
    /// @param rollbackTargetBlock Block data for the block before the fraudulent one (for chain rollback)
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
        if (!isBlockIncluded(data)) revert BlockNotIncluded();

        uint256 memoryAddress;
        if (isTx) {
            if (updateNr >= data.numTransactions) revert TxIndexOutOfBounds();
            memoryAddress = txMemoryAddress(updateNr, data.numDeposits) + 11;
        } else {
            if (updateNr >= (data.numDeposits + 2) / 3) revert UpdateIndexOutOfBounds();
            // Points to the start of each group of three updates
            memoryAddress = updateNr * 4;
        }

        // Validate the first region
        if (region.length == 0) revert EmptyRegion();
        uint256 firstBlobNumber = memoryAddress / 4096;
        if (region.hash != data.blobhashes[firstBlobNumber]) revert RegionBlobHashMismatch();
        if (region.memoryAddress != (memoryAddress % 4096)) revert RegionMemoryAddressMismatch();
        validateRegionOpening(region);
        // This check is critical even with an empty extension region as it forces an empty region
        // to have empty data.
        validateRegionOpening(extensionRegion);
        if (region.length + extensionRegion.length != 4) revert RegionLengthMismatch();

        // Because tx are 4 elements we can have them aligned at memory region boundaries.
        if (extensionRegion.length != 0) {
            // We enforce that this actually at the end of the blob.
            if (region.memoryAddress + region.length != 4096) revert RegionNotAtBlobBoundary();
            if (extensionRegion.hash != data.blobhashes[firstBlobNumber + 1]) revert RegionBlobHashMismatch();
            if (extensionRegion.memoryAddress != 0) revert ExtensionMemoryNotZero();
            validateRegionOpening(extensionRegion);
        }

        // Now we have validated that the positions that the sequencer submitted are equal to claimed sequencerSubmittedData
        // So we have to check that the prior anchor when updated is not equal to sequencerSubmittedData[3] which is the new root
        validatePriorAnchor(priorAnchor, data, updateNr, !isTx, priorAnchorCommitment, priorAnchorProof);

        // We calculate the actual block index as the day*blocksPerDay + blockIndex
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Now we can prove that the update from priorAnchor to current anchor is not correct using the zk update proof
        bytes32[6] memory zkProofInputs =
            [trueAnchor, priorAnchor, region.data[0], bytes32(uint256(0)), bytes32(uint256(0)), bytes32(treeIndex)];
        zkProofInputs[3] = region.memoryAddress + 1 == 4096 ? extensionRegion.data[0] : region.data[1];
        uint256 absoluteIndex = region.memoryAddress + 2;
        zkProofInputs[4] = absoluteIndex >= 4096 ? extensionRegion.data[absoluteIndex % 4096] : region.data[2];
        absoluteIndex = region.memoryAddress + 3;
        bytes32 sequencerSubmittedRoot =
            absoluteIndex >= 4096 ? extensionRegion.data[absoluteIndex % 4096] : region.data[3];

        // This call validates a zk update proof that the update of the prior anchor with the three new leaves equals
        // the "true anchor" provided by the caller.
        if (!predictableUpdateVerifier.verifyPredictableUpdate(zkProofInputs, zk)) revert InvalidZKProof();

        // We have two options (1) that the sequencer has not added the correct root to the blob
        // (2) that if this is the last tx in the block that the sequencer has set their "anchor" field correctly
        if (trueAnchor == sequencerSubmittedRoot) {
            // We underflow here if both numTransactions and numDeposits == 0 but this case cannot happen because add block reverts
            // Note that since updateNr is zero indexed (data.numDeposits-1)/3 does give the correct last update nr group
            bool isLast = data.numTransactions == 0
                ? updateNr == (data.numDeposits - 1) / 3
                : updateNr == data.numTransactions - 1;
            if (!(isLast && trueAnchor != data.anchor)) revert NoFraud();
        } // the else here is just that you should be slashed

        // Since the sequencer submitted the wrong deposit leaf at this index we slash and roll back.
        slash(data.sequencer, data.blockNr);
        rollback(data.blockNr, rollbackTargetBlock);
    }
}
