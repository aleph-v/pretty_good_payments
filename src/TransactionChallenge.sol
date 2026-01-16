// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./SequencerRegistry.sol";
import "./library/BlobData.sol";
import "./library/PredictableMerkleLib.sol";

// The component of the challenge system which enforces deposits are done properly

contract TransactionChallenge is Spine, SequencerRegistry {
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
        require(isBlockIncluded(data));
        require(txNr < data.numTransactions);

        // Get the absolute memory address implied by the number of TX
        uint256 memoryAddress = txMemoryAddress(txNr, data.numDeposits);

        // Validate the first region
        require(region.length != 0);
        uint256 firstBlobNumber = memoryAddress / 4096;
        require(region.hash == data.blobhashes[firstBlobNumber]);
        require(region.memoryAddress == (memoryAddress % 4096));
        validateRegionOpening(region);
        // This check is critical even with an empty extension region as it forces an empty region
        // to have empty data.
        validateRegionOpening(extensionRegion);
        require(region.length + extensionRegion.length == 14, "Not enough data");

        // If we are actually using elements from the extension region we require that we are at the end of the blob
        // and that the blobhash matches, and that the memory region is equal to zero
        if (extensionRegion.length != 0) {
            // We enforce that this actually at the end of the blob.
            assert((region.memoryAddress + region.length) % 4096 == 0);
            require(extensionRegion.hash == data.blobhashes[firstBlobNumber + 1]);
            require(extensionRegion.memoryAddress == 0);
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
            uint256(raw[9]),  // nullifier0
            uint256(raw[10]), // nullifier1
            uint256(raw[11]), // leaf0
            uint256(raw[12]), // leaf1
            uint256(raw[13]), // leaf2
            0,                // anchor (set below after validation)
            uint256(uint160(ethKey))
        ];

        bool noFraud = anchorBlockNr <= data.blockNr;
        if (anchorBlockNr == data.blockNr) {
            // If we are loading a tx in the same block we require it is less than this tx (or that it is a deposit)
            noFraud = noFraud && (anchorUpdateNr < txNr || isDeposit);
        }

        // If the transaction has not been set with invalid update or block numbers then we check that the challenger
        // has given the correct block and if so that the transaction has valid anchor ref values (ie not more than tx num)
        if (noFraud) {
            require(isBlockIncluded(priorAnchorBlock), "Invalid anchor block info");
            require(priorAnchorBlock.blockNr == anchorBlockNr, "Invalid anchor block info");

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
            require(ethKey != address(0));
            // Extract fields [null0, null1, leaf0, leaf1, leaf2] from publicInputs
            // Public inputs order: [null0, null1, leaf0, leaf1, leaf2, anchor, ethKey]
            // So the first 5 elements are exactly what the registry needs
            bytes32[5] memory fields;
            assembly ("memory-safe") {
                fields := publicInputs
            }
            // Since all other fraud opportunities have been excused we require the fraud is here by requiring the query to return false.
            require(!transferRegistry.query(ethKey, fields), "No Fraud");
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

    /// @notice Decodes block number tx number and address from bytes32
    /// @param data The encoded 32 byte blob
    /// @return (blockNr, txNr, ethAddress)
    function decodeTxInfo(bytes32 data) public pure returns (uint256, uint256, bool, address) {
        bool isDeposit = data & bytes32(uint256(1) << 254) != bytes32(0);
        uint256 blockNr = uint256((data << 2) >> 224);
        uint256 txNr = uint256((data << 34) >> 224);
        address ethAddress = address(uint160((uint256)((data << 77) >> 77)));
        return (blockNr, txNr, isDeposit, ethAddress);
    }
}
