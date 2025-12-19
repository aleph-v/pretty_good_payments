// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Deposits.sol";
import "./SequencerRegistry.sol";
import "./library/PredictableMerkleLib.sol";
import {Proof} from "./library/ZKVerifier.sol";

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
        rollback(data.blockNr - 1);
    }

    // Note- the updateNr corresponds to which group of three elements plus root is challanged
    // TODO - This function is requiring us to use via-ir, we could just get better structs, see whats
    //        natural after the other challange protocols
    function challangeDepositTreeUpdate(
        BlockData memory data,
        uint256 updateNr,
        bytes32[] memory seqeuncerSubmittedData,
        bytes calldata commitment,
        bytes[] calldata kzgProofs,
        bytes32 priorAnchor,
        bytes calldata priorAnchorCommitment,
        bytes calldata priorAnchorProof,
        bytes32 trueAnchor,
        Proof memory zk
    ) external {
        uint256 blockNr = data.blockNr;
        // Check the block is in the tree
        require(isBlockIncluded(data));
        // TODO check my zero indexing.
        require(updateNr <= data.numDeposits / 3);

        uint256[] memory memoryLocations = new uint256[](4);
        memoryLocations[0] = updateNr * 4;
        memoryLocations[1] = updateNr * 4 + 1;
        memoryLocations[2] = updateNr * 4 + 2;
        memoryLocations[3] = updateNr * 4 + 3;

        // Deposits are Always in the first blob as the max deposits is small enough to fit all deposits in one blob
        // and deposits are always first.
        bytes32 l2blobhash = data.blobhashes[0];
        validateDataOpenings(l2blobhash, commitment, memoryLocations, seqeuncerSubmittedData, kzgProofs);

        // Now we have validated that the positions that the seqeuncer submitted are equal to claimed seqeuncerSubmittedData
        // So we have to check that the prior anchor when updated is not equal to seqeuncerSubmittedData[3] which is the new root
        validatePriorAnchor(priorAnchor, data, updateNr, true, priorAnchorCommitment, priorAnchorProof);

        // Now we can prove that the update from priorAnchor to current anchor is not correct using the zk update proof
        // TODO - Fix block index in tree
        bytes32[6] memory zkProofInputs = [
            priorAnchor,
            bytes32(uint256(0)),
            seqeuncerSubmittedData[0],
            seqeuncerSubmittedData[1],
            seqeuncerSubmittedData[2],
            trueAnchor
        ];
        require(predictableUpdateVerifier.verfiyPredictableUpdate(zkProofInputs, zk), "Invalid ZK update proof");
        require(trueAnchor != seqeuncerSubmittedData[3], "No Fraud");

        // Since the seqeuncer submitted the wrong deposit leaf at this index we slash and roll back.
        slash(data.sequencer, blockNr);
        rollback(data.blockNr - 1);
    }
}
