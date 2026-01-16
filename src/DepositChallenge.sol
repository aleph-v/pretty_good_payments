// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Deposits} from "./Deposits.sol";
import {SequencerRegistry} from "./SequencerRegistry.sol";
import {PredictableMerkleLib} from "./library/PredictableMerkleLib.sol";
import {IUpdateVerifier} from "./interfaces/IUpdateVerifier.sol";
import {BlockNotIncluded, DepositIndexOutOfBounds, NoFraud} from "./library/Errors.sol";

/// @title DepositChallenge
/// @notice Fraud proof contract for challenging incorrect deposit leaves in L2 blocks

contract DepositChallenge is Deposits, SequencerRegistry {
    using PredictableMerkleLib for IUpdateVerifier;

    /// @notice Challenges a deposit leaf that doesn't match the expected value from L1 deposits
    /// @dev Fraud exists if: (1) numDeposits != perBlockDeposits length, or (2) leaf at depositNr
    ///      doesn't match the expected deposit hash. Challenger must provide KZG proof of the blob value.
    /// @param data The block containing the allegedly fraudulent deposit
    /// @param depositNr Index of the deposit to challenge [0, numDeposits)
    /// @param sequencerSubmittedLeaf The value the sequencer put in the blob (proven via KZG)
    /// @param commitment 48-byte KZG commitment for the blob
    /// @param proof 48-byte KZG proof for the leaf at depositNr's memory address
    /// @param priorBlock Block data for rollback target (block before the fraudulent one)
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
