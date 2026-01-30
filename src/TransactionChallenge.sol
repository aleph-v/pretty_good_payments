// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Spine} from "./Spine.sol";
import {SequencerRegistry} from "./SequencerRegistry.sol";
import {
    BlockNotIncluded,
    TxIndexOutOfBounds,
    EmptyRegion,
    RegionBlobHashMismatch,
    RegionMemoryAddressMismatch,
    RegionLengthMismatch,
    RegionNotAtBlobBoundary,
    ExtensionMemoryNotZero,
    InvalidAnchorBlockInfo,
    ZeroEthKey,
    NoFraud
} from "./library/Errors.sol";

/// @title TransactionChallenge
/// @notice Fraud proof contract for challenging invalid transactions in L2 blocks

contract TransactionChallenge is Spine, SequencerRegistry {
    /// @notice Challenges a transaction's ZK proof or authorization in a submitted block
    /// @dev Validates transaction structure, ZK proof, and eth-key authorization.
    ///      Fraud types: invalid anchor reference, invalid ZK proof, or missing tx registry approval.
    /// @param data The block containing the allegedly fraudulent transaction
    /// @param txNr Transaction index within the block [0, numTransactions)
    /// @param region KZG-proven blob region containing the 14 tx fields (8 proof + 6 inputs).
    /// @param extensionRegion For cross-blob transactions: continuation from next blob. Empty if tx fits in one blob.
    /// @param anchor The merkle tree anchor the transaction claims to use
    /// @param priorAnchorBlock Block containing the anchor (for anchor validation)
    /// @param priorAnchorCommitment KZG commitment for anchor proof
    /// @param priorAnchorProof KZG proof for anchor
    /// @param rollbackTargetBlock Block data for the block before the fraudulent one (for chain rollback)
    function challengeTxZK(
        BlockData memory data,
        uint256 txNr,
        Region calldata region,
        Region calldata extensionRegion,
        bytes32 anchor,
        BlockData memory priorAnchorBlock,
        bytes calldata priorAnchorCommitment,
        bytes calldata priorAnchorProof,
        BlockData memory rollbackTargetBlock
    ) external {
        // Check the block is in the tree
        if (!isBlockIncluded(data)) revert BlockNotIncluded();
        if (txNr >= data.numTransactions) revert TxIndexOutOfBounds();

        // Get the absolute memory address implied by the number of TX
        uint256 memoryAddress = txMemoryAddress(txNr, data.numDeposits);

        // Validate the first region
        if (region.length == 0) revert EmptyRegion();
        uint256 firstBlobNumber = memoryAddress / 4096;
        if (region.hash != data.blobhashes[firstBlobNumber]) revert RegionBlobHashMismatch();
        if (region.memoryAddress != (memoryAddress % 4096)) revert RegionMemoryAddressMismatch();
        validateRegionOpening(region);
        // This check is critical even with an empty extension region as it forces an empty region
        // to have empty data.
        validateRegionOpening(extensionRegion);
        if (region.length + extensionRegion.length != 14) revert RegionLengthMismatch();

        // If we are actually using elements from the extension region we require that we are at the end of the blob
        // and that the blobhash matches, and that the memory region is equal to zero
        if (extensionRegion.length != 0) {
            // We enforce that this actually at the end of the blob.
            if ((region.memoryAddress + region.length) % 4096 != 0) revert RegionNotAtBlobBoundary();
            if (extensionRegion.hash != data.blobhashes[firstBlobNumber + 1]) revert RegionBlobHashMismatch();
            if (extensionRegion.memoryAddress != 0) revert ExtensionMemoryNotZero();
        }

        bytes32[14] memory raw;
        raw[0] = region.data[0];
        uint256 relativeLocation = region.memoryAddress;
        for (uint256 i = 1; i < 14; i++) {
            relativeLocation++;
            raw[i] = relativeLocation >= 4096 ? extensionRegion.data[relativeLocation % 4096] : region.data[i];
        }

        // TODO - Could do this fully no copy with assembly
        uint256[2] memory _pA = [uint256(raw[0]), uint256(raw[1])];
        uint256[2][2] memory _pB;
        _pB[0] = [uint256(raw[2]), uint256(raw[3])];
        _pB[1] = [uint256(raw[4]), uint256(raw[5])];
        uint256[2] memory _pC = [uint256(raw[6]), uint256(raw[7])];
        // We decode the encoded root and ethereum key information
        (uint256 anchorBlockNr, uint256 anchorUpdateNr, bool isDeposit, address ethKey) = decodeTxInfo(bytes32(raw[8]));
        // Public signals order for transfer circuit: [nullifiers[2], leavesOut[3], anchor, ethKey]
        // This matches snarkjs convention: outputs first, then public inputs
        uint256[7] memory publicInputs = [
            uint256(raw[9]), // nullifier0
            uint256(raw[10]), // nullifier1
            uint256(raw[11]), // leaf0
            uint256(raw[12]), // leaf1
            uint256(raw[13]), // leaf2
            0, // anchor (set below after validation)
            uint256(uint160(ethKey))
        ];

        bool noFraud = anchorBlockNr <= data.blockNr;
        if (anchorBlockNr == data.blockNr) {
            // If we are loading a transaction in the same block we will reference the anchor before the transaction nr
            // so in this case we need less than or equal to the transaction nr. If they are equal the validatePriorAnchor
            // refers to the anchor exactly before this transaction, meaning it is a sequential output. (which we don't recommend
            // as you loose some anonymity)
            noFraud = noFraud && (anchorUpdateNr <= txNr || isDeposit);
        }

        // If the transaction has not been set with invalid update or block numbers then we check that the challenger
        // has given the correct block and if so that the transaction has valid anchor ref values (ie not more than tx num)
        if (noFraud) {
            if (!isBlockIncluded(priorAnchorBlock)) revert InvalidAnchorBlockInfo();
            if (priorAnchorBlock.blockNr != anchorBlockNr) revert InvalidAnchorBlockInfo();

            // Checks if the user has submitted an invalid update number
            // For deposits, anchorUpdateNr is a GROUP index, so we use ceiling division to get the number of groups
            noFraud = isDeposit
                ? anchorUpdateNr < (priorAnchorBlock.numDeposits + 2) / 3
                : anchorUpdateNr < priorAnchorBlock.numTransactions;
        }

        // If the user has not formatted the reference to the anchor wrong we validate that the challenger has given us the correct
        // anchor for that combo of block number and update number then use that as the anchor for the zk and check if the transaction
        // zk proof is correct.
        if (noFraud) {
            // Now we show that the challenger has provided the anchor at the actual index of the user's tx
            validatePriorAnchor(
                anchor, priorAnchorBlock, anchorUpdateNr, isDeposit, priorAnchorCommitment, priorAnchorProof
            );
            // Finally we validate the zk proof
            publicInputs[5] = uint256(anchor);
            noFraud = transactionZkVerifier.verifyProof(_pA, _pB, _pC, publicInputs);
        }

        // If the rest of the transaction is valid and correctly formatted we check for the case that this is an ethereum keyed
        // transaction and check that the proof is missing its approval in the transaction registry
        if (noFraud) {
            // If the eth key is address zero and the proof validates there is no fraud and we revert
            if (ethKey == address(0)) revert ZeroEthKey();
            // Extract fields [null0, null1, leaf0, leaf1, leaf2] from publicInputs
            // Public inputs order: [null0, null1, leaf0, leaf1, leaf2, anchor, ethKey]
            // So the first 5 elements are exactly what the registry needs
            bytes32[5] memory fields;
            assembly ("memory-safe") {
                fields := publicInputs
            }
            // Since all other fraud opportunities have been excused we require the fraud is here by requiring the query to return false.
            if (transferRegistry.query(ethKey, fields)) revert NoFraud();
        }

        slash(data.sequencer, data.blockNr);
        rollback(data.blockNr, rollbackTargetBlock);
    }

    /// @notice Encodes the block number transaction number and address into a bytes32
    /// @param blockNr The block number
    /// @param updateNr The tree update number
    /// @param isDeposit If the update is a deposit this is true if it is a transaction this is false
    /// @param ethAddress The eth address to encode
    function encodeTxIntoBytes32(uint32 blockNr, uint32 updateNr, bool isDeposit, address ethAddress)
        external
        pure
        returns (bytes32 ret)
    {
        ret = isDeposit ? (bytes32)(uint256(1) << 254) : bytes32(uint256(0));
        ret = ret | (bytes32)((uint256(blockNr) << 222) + (uint256(updateNr) << 190));
        ret = ret | (bytes32)(uint256(uint160(ethAddress)));
    }

    /// @notice Decodes block number, update number, deposit flag, and eth address from encoded bytes32
    /// @param data The encoded 32 byte value (from encodeTxIntoBytes32)
    /// @return blockNr The referenced block number
    /// @return updateNr The tree update index within the block
    /// @return isDeposit True if referencing a deposit update, false for transaction
    /// @return ethAddress The ethereum address for authorization (0 for zk-only transactions)
    function decodeTxInfo(bytes32 data) public pure returns (uint256, uint256, bool, address) {
        bool isDeposit = data & bytes32(uint256(1) << 254) != bytes32(0);
        uint256 blockNr = uint256((data << 2) >> 224);
        uint256 txNr = uint256((data << 34) >> 224);
        address ethAddress = address(uint160((uint256)((data << 77) >> 77)));
        return (blockNr, txNr, isDeposit, ethAddress);
    }
}
