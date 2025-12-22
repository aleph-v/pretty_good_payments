// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./SequencerRegistry.sol";

// The component of the challange system which enforces that nullifiers are not repeated

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
        NullifierLoader calldata second
    ) external {
        // We cannot open the same nullifier to prove reuse
        if (first.data.blockNr == second.data.blockNr) {
            if (first.txNr == second.txNr) {
                require(first.whichNullifier != second.whichNullifier);
            }
        }
        // First must be the first time we see the nullifier
        require(first.data.blockNr <= second.data.blockNr);

        validateNullifierOpening(first, reusedNullifier);
        validateNullifierOpening(second, reusedNullifier);

        // Rollback the second time we saw the nullifier
        slash(second.data.sequencer, second.data.blockNr);
        rollback(second.data.blockNr);
    }

    function validateNullifierOpening(NullifierLoader calldata loader, bytes32 nullifier) internal view {
        require(loader.txNr <= loader.data.numTransactions);
        require(isBlockIncluded(loader.data));

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

