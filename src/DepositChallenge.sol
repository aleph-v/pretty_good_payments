// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Deposits.sol";
import "./SequencerRegistry.sol";
import "./library/PredictableMerkleLib.sol";

// The component of the challange system which enforces deposits are done properly

contract DepositChallenge is Deposits, SequencerRegistry {
    using PredictableMerkleLib for IUpdateVerifier;

    // We load the block data and we get the expected deposit at a deposits index provided. The challanger
    // provides a predictable merkle tree update data and also a blob opening proof.
    function challangeDepositWrongLeaf(
        BlockData memory data,
        uint256 depositNr,
        bytes32 seqeuncerSubmittedLeaf,
        bytes calldata commitment,
        bytes calldata proof
    ) external {
        uint256 blockNr = data.blockNr;
        // Check the block is in the tree
        require(isBlockIncluded(data));
        // Note - We don't check finality here but perhaps we should

        require(depositNr < data.numDeposits);
        uint256 leafAddress = leafMemoryAddress(depositNr, data.numDeposits, true, 0);
        // Deposits are Always in the first blob as the max deposits is small enough to fit all deposits in one blob
        // and deposits are always first.
        bytes32 l2blobhash = data.blobhashes[0];
        validateSingle(l2blobhash, commitment, leafAddress, seqeuncerSubmittedLeaf, proof);

        // We have established that the field at leafAddress is equal to seqeuncerSubmittedLeaf now we check that
        // this is the wrong value
        require(perBlockDeposits[blockNr][depositNr] != seqeuncerSubmittedLeaf, "No Fraud");

        // Since the seqeuncer submitted the wrong deposit leaf at this index we slash and roll back.
        slash(data.sequencer, blockNr);
        rollback(data.blockNr);
    }
}
