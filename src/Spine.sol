// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BlobData} from "./library/BlobData.sol";
import {IUpdateVerifier} from "./interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "./interfaces/ITransferVerifier.sol";
import {IYieldRouter} from "./interfaces/IYieldRouter.sol";
import {ITransactionRegistry} from "./TransactionRegistry.sol";

// The core library managing new blocks

contract Spine is BlobData {
    // TODO real number
    uint256 public constant CHALLENGE_PERIOD = 100;
    uint256 public constant MAX_TX = 4096;
    // Each deposit is a single field plus one root for three deposits, and we want them to fit in one blob (3072/3) + 3072 = 4096
    uint256 public constant MAX_DEPOSITS = 3072;
    bytes32 public immutable GENESIS_ANCHOR;

    // Needed in the deposit withdraw libs downstream.
    IYieldRouter public immutable yieldRouter;
    IUpdateVerifier public immutable predictableUpdateVerifier;
    ITransferVerifier public immutable transactionZkVerifier;
    ITransactionRegistry public immutable transferRegistry;

    struct TimestampAndIndex {
        uint128 day;
        uint128 index;
    }
    // Helps track the actual block index

    TimestampAndIndex public lastTimestamp;
    uint256 constant DAY = 86400;
    uint256 immutable START = block.timestamp;

    // The anchor is the root of the merkle tree at the end of this block
    struct BlockData {
        bytes32 anchor;
        uint256 timestamp;
        uint256 numTransactions;
        uint256 numDeposits;
        uint256 blockNr;
        TimestampAndIndex blockIndex;
        address sequencer;
        bytes32[] blobhashes;
    }

    struct IndexAndPartialHash {
        uint64 index;
        bytes24 partialHash;
    }

    // We optimism the storage footprint of submission by storing the hash of the block info
    // to use this block info later we have to provide the whole block
    bytes32[] roots;
    // We need to store the anchors so they can be looked up in the challenge protocol
    // We do a bit of a trick here we only need 64 bits for index so we store 24 bytes of the hash
    // using one store, and can compare this to the block hash, which to break would require two
    // roots matching at 192 bits (birthday attack is 96 bits to attack)
    mapping(bytes32 => IndexAndPartialHash) anchorToIndex;

    // TODO - Should we add more event data? May make it easier to index in the sequencer
    event NewRoot(uint256 indexed blocknumber, bytes32 indexed anchor, bytes32 indexed l2BlockHash, BlockData data);

    // Pushes a block into the chain of roots, records the data
    function addBlock(BlockData memory data, uint256[] memory blobIndices) internal {
        // Enforce the claimed data is correct
        data.timestamp = block.timestamp;
        data.blockNr = roots.length;
        for (uint256 i = 0; i < blobIndices.length; i++) {
            bytes32 hash = blobhash(blobIndices[i]);
            require(hash != 0);
            data.blobhashes[i] = hash;
        }
        require(data.numDeposits <= MAX_DEPOSITS);
        require(data.numTransactions <= MAX_TX);
        uint256 depositBlobUse = data.numDeposits % 3 == 0 ? (data.numDeposits / 3) * 4 : (data.numDeposits / 3 + 1) * 4;
        require(depositBlobUse + data.numTransactions * 15 < 4096 * blobIndices.length);
        require(data.numTransactions != 0 || data.numDeposits != 0);

        // The tree is split such that each day we start in a new subbranch to track this using the prior block
        uint256 actualDay = (block.timestamp - START) / DAY;
        uint256 nextBlock = lastTimestamp.day == actualDay ? lastTimestamp.index + 1 : 0;
        if (roots.length == 0) {
            // Case for the very first block ever
            nextBlock = 0;
        }
        TimestampAndIndex memory timestamp = TimestampAndIndex({ day: uint128(actualDay), index: uint128(nextBlock) });
        lastTimestamp = timestamp;
        data.blockIndex = timestamp;

        // TODO - Meter the gas use possible opt target
        bytes32 l2BlockHash = keccak256(abi.encode(data));

        // Do the stores nessecary
        // Casting here we use the force cast because we want this to truncate so it fits
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes24 partialHash = (bytes24)(l2BlockHash);
        anchorToIndex[data.anchor].index = uint64(data.blockNr);
        anchorToIndex[data.anchor].partialHash = partialHash;
        roots.push(l2BlockHash);

        // Includes the block number and the root
        // Users can get the rest of the data from the getters
        emit NewRoot(data.blockNr, data.anchor, l2BlockHash, data);
    }

    event Rollback(uint256 from, uint256 to);

    // Uses assembly to rollback the state array
    function rollback(uint256 index, BlockData memory priorBlock) internal {
        // TODO - Should we enforce no rollback to timestamps which are too old?
        require(index < roots.length);
        emit Rollback(roots.length, index);

        // TODO - Meter the gas use possible opt target
        if (index != 0) {
            bytes32 l2BlockHash = keccak256(abi.encode(priorBlock));
            require(l2BlockHash == roots[index - 1], "Prior Root Mismatch");
            lastTimestamp = priorBlock.blockIndex;
        } else {
            lastTimestamp = TimestampAndIndex({ day: 0, index: 0 });
        }

        assembly ("memory-safe") {
            sstore(roots.slot, index)
        }
    }

    // Returns the highest nonreorged index
    function getCurrentBlocknumber() public view returns (uint256) {
        return (roots.length);
    }

    // Helper function determining if a hash of a block is confirmed
    function isConfirmed(BlockData memory data) public view returns (bool) {
        if (!isBlockIncluded(data)) {
            return false;
        }
        return (data.timestamp + CHALLENGE_PERIOD < block.timestamp);
    }

    // Checks that a block is currently in the tree
    function isBlockIncluded(BlockData memory data) internal view returns (bool) {
        bytes32 l2BlockHash = keccak256(abi.encode(data));
        return roots[data.blockNr] == l2BlockHash;
    }

    // We can use this function to check if anchor exists in the current tree (ie not reorged)
    function isAnchorIncluded(bytes32 anchor) public view returns (bool) {
        if (anchor == GENESIS_ANCHOR) {
            return (true);
        }

        uint64 index = anchorToIndex[anchor].index;
        bytes24 partialHash = anchorToIndex[anchor].partialHash;
        if (uint256(index) >= roots.length) {
            return false;
        }
        // Note if the last 24 bytes match we assume this hash has not been rolled back.
        // Casting here we use the force cast because we want this to truncate so it fits
        // forge-lint: disable-next-line(unsafe-typecast)
        return (partialHash == (bytes24)(roots[uint256(index)]));
    }

    // Checks that the provided anchor is either the anchor after blockNr - 1 or that it is the anchor after update given by updateNr in block blockNr
    function validatePriorAnchor(
        bytes32 anchor,
        BlockData memory data,
        uint256 updateNr,
        bool isDeposit,
        bytes calldata commitment,
        bytes calldata proof
    ) internal view {
        // Either this is the first deposit or the first transaction in a block with no deposits
        // then we check that the index of anchor is equal to blockNr - 1
        if ((isDeposit && updateNr == 0) || (data.numDeposits == 0 && updateNr == 0)) {
            require(isAnchorIncluded(anchor));
            if (data.blockNr == 0) {
                require(anchor == GENESIS_ANCHOR);
            } else {
                require(anchorToIndex[anchor].index == data.blockNr - 1);
            }
            return;
        }
        // Since we are not in the easy case we have to compute the location of the prior root in blob memory and validate with a proof
        // We actually can just load the first index of the memory region for the update and then sub 1
        uint256 absoluteMemoryLocation = priorRootMemoryLocation(updateNr, isDeposit, data.numDeposits);
        uint256 blobIndex = absoluteMemoryLocation / 4096;
        bytes32 memoryBlobHash = data.blobhashes[blobIndex];
        uint256 memoryLocationInBlob = absoluteMemoryLocation % 4096;

        validateSingle(memoryBlobHash, commitment, memoryLocationInBlob, anchor, proof);
    }
}
