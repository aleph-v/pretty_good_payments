// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./SequencerRegistry.sol";
import "./library/BlobData.sol";
import "./library/PredictableMerkleLib.sol";

// The component of the challange system which enforces deposits are done properly

contract TransactionChallenge is Spine, SequencerRegistry {
    function challengeTxZK(
        BlockData memory data,
        uint256 txNr,
        Region calldata region,
        Region calldata extensionRegion,
        bytes32 anchor,
        BlockData memory priorAnchorBlock,
        bytes calldata priorAnchorCommitment,
        bytes calldata priorAnchorProof
    ) external {
        // Check the block is in the tree
        require(isBlockIncluded(data));

        // Get the absolute memory address implied by the number of TX
        uint256 memoryAddress = txMemoryAddress(txNr, data.numDeposits);

        // Validate the first region
        assert(region.length != 0);
        uint256 firstBlobNumber = memoryAddress / 4096;
        require(region.hash == data.blobhashes[firstBlobNumber]);
        require(region.memoryAddress == (memoryAddress % 4096));
        validateRegionOpening(region);
        // Because tx are 15 elements we can have them aligned at memory region boundaries.
        // We check for length 14 because we don't need to open the anchor after (very last in mem)
        if (region.length != 14) {
            // We still want 4 in total
            assert(region.length + extensionRegion.length == 4);
            // We enforce that this actually at the end of the blob.
            assert(region.memoryAddress + region.length + 1 == 4096);
            require(extensionRegion.hash == data.blobhashes[firstBlobNumber + 1]);
            require(extensionRegion.memoryAddress == 0);
            validateRegionOpening(extensionRegion);
        }

        bytes32[14] memory raw;
        raw[0] = region.data[0];
        uint256 relativeLocation = region.memoryAddress;
        for (uint256 i = 1; i < 14; i++) {
            relativeLocation++;
            raw[i] = relativeLocation >= 4096 ? region.data[i] : extensionRegion.data[relativeLocation % 4096];
        }

        // TODO - Could do this fully no copy with assembly
        uint256[2] memory _pA = [uint256(raw[0]), uint256(raw[1])];
        uint256[2][2] memory _pB;
        _pB[0] = [uint256(raw[2]), uint256(raw[3])];
        _pB[1] = [uint256(raw[4]), uint256(raw[5])];
        uint256[2] memory _pC = [uint256(raw[6]), uint256(raw[7])];
        // We decode the encoded root and ethereum key information
        (uint256 anchorBlockNr, uint256 anchorUpdateNr, bool isDeposit, address ethKey) = decodeTxInfo(bytes32(raw[8]));
        uint256[7] memory publicInputs =
            [0, uint256(uint160(ethKey)), uint256(raw[9]), uint256(raw[10]), uint256(raw[11]), uint256(raw[12]), uint256(raw[13])];


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
            noFraud = isDeposit
                ? anchorUpdateNr <= priorAnchorBlock.numDeposits
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
            publicInputs[0] = uint256(anchor);
            noFraud = transactionZkVerifier.verifyProof(_pA, _pB, _pC, publicInputs);
        }

        // If the rest of the transaction is valid and correctly formatted we check for the case that this is an ethereum keyed
        // transaction and check that the proof is missing its approval in the transaction registry
        if (noFraud) {
            // If the eth key is address zero and the proof validates there is no fraud and we revert
            require(ethKey != address(0));
            // quick assembly conversion to get the fields
            bytes32[5] memory fields;
            assembly ("memory-safe") {
                fields := add(publicInputs, 32)
            }
            // Since all other fraud opportunities have been excused we require the fraud is here by requiring the query to return false.
            require(!transferRegistry.query(ethKey, fields));
        }

        slash(data.sequencer, data.blockNr);
        rollback(data.blockNr);
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
        ret = isDeposit ? bytes32(uint256(1) << 255) : bytes32(uint256(0));
        ret = ret | bytes32((uint256(blockNr) << 223) + (uint256(updateNr) << 195));
        ret = ret | bytes32(bytes20(ethAddress));
    }

    /// @notice Decodes block number tx number and address from bytes32
    /// @param data The encoded 32 byte blob
    /// @return (blockNr, txNr, ethAddress)
    function decodeTxInfo(bytes32 data) public pure returns (uint256, uint256, bool, address) {
        bool isDeposit = data & bytes32(uint256(1) << 255) != bytes32(0);
        uint256 blockNr = uint256((data << 1) >> 224);
        uint256 txNr = uint256((data << 33) >> 224);
        address ethAddress = address(bytes20((data << 76) >> 76));
        return (blockNr, txNr, isDeposit, ethAddress);
    }
}
