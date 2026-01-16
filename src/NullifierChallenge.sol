// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Spine} from "./Spine.sol";
import {SequencerRegistry} from "./SequencerRegistry.sol";
import {BlockNotIncluded, TxIndexOutOfBounds, SameNullifierLocation, InvalidNullifierOrder} from "./library/Errors.sol";

/// @title NullifierChallenge
/// @notice Fraud proof contract for challenging nullifier reuse (double-spend prevention)

contract NullifierChallenge is Spine, SequencerRegistry {
    /// @notice Data needed to prove a nullifier exists at a specific location in a block
    struct NullifierLoader {
        BlockData data;
        uint256 txNr;
        uint256 whichNullifier;
        bytes commitment;
        bytes proof;
    }

    /// @notice Challenges a double-spend by proving the same nullifier appears in two transactions
    /// @dev Both nullifier openings are validated via KZG proofs. The later occurrence is slashed.
    /// @param reusedNullifier The nullifier value that appears twice
    /// @param first First occurrence of the nullifier (must be in earlier or same block as second)
    /// @param second Second occurrence to be challenged (will trigger slash and rollback)
    /// @param rollbackTargetBlock Block data for rollback target (block before second.data.blockNr)
    function challengeNullifier(
        bytes32 reusedNullifier,
        NullifierLoader calldata first,
        NullifierLoader calldata second,
        BlockData memory rollbackTargetBlock
    ) external {
        // We cannot open the same nullifier to prove reuse
        if (first.data.blockNr == second.data.blockNr) {
            if (first.txNr == second.txNr) {
                if (first.whichNullifier == second.whichNullifier) revert SameNullifierLocation();
            }
        }
        // First must be the first time we see the nullifier
        if (first.data.blockNr > second.data.blockNr) revert InvalidNullifierOrder();

        validateNullifierOpening(first, reusedNullifier);
        validateNullifierOpening(second, reusedNullifier);

        // Rollback the second time we saw the nullifier
        slash(second.data.sequencer, second.data.blockNr);
        rollback(second.data.blockNr, rollbackTargetBlock);
    }

    /// @notice Validates that a nullifier exists at the specified location via KZG proof
    /// @dev Computes memory address from txNr and whichNullifier, then validates the KZG opening
    /// @param loader Contains block data, tx index, nullifier index, and KZG proof data
    /// @param nullifier The expected nullifier value at that location
    function validateNullifierOpening(NullifierLoader calldata loader, bytes32 nullifier) internal view {
        if (loader.txNr >= loader.data.numTransactions) revert TxIndexOutOfBounds();
        if (!isBlockIncluded(loader.data)) revert BlockNotIncluded();

        // We compute the absolute memory location
        // uint256 txNumber, uint256 numDeposits, uint256 which
        uint256 absoluteMemoryAddress =
            nullifierMemoryAddress(loader.txNr, loader.data.numDeposits, loader.whichNullifier);
        uint256 blob = absoluteMemoryAddress / 4096;
        uint256 relativeMemoryAddress = absoluteMemoryAddress % 4096;
        bytes32 memoryBlobHash = loader.data.blobhashes[blob];

        validateSingle(memoryBlobHash, loader.commitment, relativeMemoryAddress, nullifier, loader.proof);
    }
}
