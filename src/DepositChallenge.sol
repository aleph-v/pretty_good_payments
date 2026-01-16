// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Deposits} from "./Deposits.sol";
import {SequencerRegistry} from "./SequencerRegistry.sol";
import {PredictableMerkleLib} from "./library/PredictableMerkleLib.sol";
import {IUpdateVerifier} from "./interfaces/IUpdateVerifier.sol";
import {BlockNotIncluded, DepositIndexOutOfBounds, NoFraud} from "./library/Errors.sol";

// The component of the challenge system which enforces deposits are done properly

contract DepositChallenge is Deposits, SequencerRegistry {
    using PredictableMerkleLib for IUpdateVerifier;

    // We load the block data and we get the expected deposit at a deposits index provided. The challenger
    // provides a predictable merkle tree update data and also a blob opening proof.
    function challengeDepositWrongLeaf(
        BlockData memory data,
        uint256 depositNr,
        bytes32 sequencerSubmittedLeaf,
        bytes calldata commitment,
        bytes calldata proof,
        BlockData memory priorBlock
    ) external {
        uint256 blockNr = data.blockNr;
        // Check the block is in the tree
        if (!isBlockIncluded(data)) revert BlockNotIncluded();

        // If the block has a number of deposits mismatching the perBlockDeposits length then it is always fraud
        // so we can skip the other checks and go straight to rollback (plus avoid array indexing reverts)
        if (data.numDeposits == perBlockDeposits[blockNr].length) {
            if (depositNr >= data.numDeposits) revert DepositIndexOutOfBounds();
            uint256 leafAddress = leafMemoryAddress(depositNr, data.numDeposits, true, 0);
            // Deposits are Always in the first blob as the max deposits is small enough to fit all deposits in one blob
            // and deposits are always first.
            bytes32 l2blobhash = data.blobhashes[0];
            validateSingle(l2blobhash, commitment, leafAddress, sequencerSubmittedLeaf, proof);

            // We have established that the field at leafAddress is equal to seqeuncerSubmittedLeaf now we check that
            // this is the wrong value
            if (perBlockDeposits[blockNr][depositNr] == sequencerSubmittedLeaf) revert NoFraud();
        }

        // Since the sequencer submitted the wrong deposit leaf at this index we slash and roll back.
        slash(data.sequencer, blockNr);
        rollback(data.blockNr, priorBlock);
    }
}
