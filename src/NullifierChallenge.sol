// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Spine} from "./Spine.sol";
import {SequencerRegistry} from "./SequencerRegistry.sol";
import {
    BlockNotIncluded,
    TxIndexOutOfBounds,
    SameNullifierLocation,
    InvalidNullifierOrder
} from "./library/Errors.sol";

// The component of the challenge system which enforces that nullifiers are not repeated

contract NullifierChallenge is Spine, SequencerRegistry {
    struct NullifierLoader {
        BlockData data;
        uint256 txNr;
        uint256 whichNullifier;
        bytes commitment;
        bytes proof;
    }

    // Enforces that we do not have nullifier reuse.
    // Since we have commitments to the kzg data structure at each block we can just open and compare
    // the entries in two former blobs, and if they are equal then we can slash the proposer
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
