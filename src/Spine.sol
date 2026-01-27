// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {BlobData} from "./library/BlobData.sol";
import {IUpdateVerifier} from "./interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "./interfaces/ITransferVerifier.sol";
import {IYieldRouter} from "./interfaces/IYieldRouter.sol";
import {ITransactionRegistry} from "./TransactionRegistry.sol";
import {
    ZeroBlobHash,
    TooManyDeposits,
    TooManyTransactions,
    InsufficientBlobCapacity,
    EmptyBlock,
    RollbackIndexOutOfBounds,
    PriorRootMismatch,
    AnchorNotIncluded,
    InvalidGenesisAnchor,
    AnchorIndexMismatch
} from "./library/Errors.sol";

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
    uint256 public immutable START = block.timestamp;

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

    // We optimize the storage footprint of submission by storing the hash of the block info
    // to use this block info later we have to provide the whole block
    bytes32[] roots;
    // We need to store the anchors so they can be looked up in the challenge protocol
    // We do a bit of a trick here we only need 64 bits for index so we store 24 bytes of the hash
    // using one store, and can compare this to the block hash, which to break would require two
    // roots matching at 192 bits (birthday attack is 96 bits to attack)
    mapping(bytes32 => IndexAndPartialHash) anchorToIndex;

    event NewRoot(uint256 indexed blocknumber, bytes32 indexed anchor, bytes32 indexed l2BlockHash, BlockData data);

    /// @notice Adds a new L2 block to the chain, validating blob data and storing the block hash
    /// @dev Sets timestamp, blockNr, and blobhashes on the data struct. Emits NewRoot event.
    /// @param data Block data struct. anchor, numTransactions, numDeposits, sequencer must be set.
    ///        blobhashes array must be pre-allocated with length equal to blobIndices.length.
    /// @param blobIndices EVM blob indices to read hashes from. Must provide sufficient capacity
    ///        for deposits (ceil(numDeposits/3)*4) plus transactions (numTransactions*15).
    function addBlock(BlockData memory data, uint256[] memory blobIndices) internal {
        // Enforce the claimed data is correct
        data.timestamp = block.timestamp;
        data.blockNr = roots.length;
        for (uint256 i = 0; i < blobIndices.length; i++) {
            bytes32 hash = blobhash(blobIndices[i]);
            if (hash == 0) revert ZeroBlobHash();
            data.blobhashes[i] = hash;
        }
        if (data.numDeposits > MAX_DEPOSITS) revert TooManyDeposits();
        if (data.numTransactions > MAX_TX) revert TooManyTransactions();
        uint256 depositBlobUse = data.numDeposits % 3 == 0 ? (data.numDeposits / 3) * 4 : (data.numDeposits / 3 + 1) * 4;
        if (depositBlobUse + data.numTransactions * 15 >= 4096 * blobIndices.length) revert InsufficientBlobCapacity();
        if (data.numTransactions == 0 && data.numDeposits == 0) revert EmptyBlock();

        // The tree is split such that each day we start in a new subbranch to track this using the prior block
        uint256 actualDay = (block.timestamp - START) / DAY;
        uint256 nextBlock = lastTimestamp.day == actualDay ? lastTimestamp.index + 1 : 0;
        if (roots.length == 0) {
            // Case for the very first block ever
            nextBlock = 0;
        }
        TimestampAndIndex memory timestamp = TimestampAndIndex({day: uint128(actualDay), index: uint128(nextBlock)});
        lastTimestamp = timestamp;
        data.blockIndex = timestamp;

        // TODO - Meter the gas use possible opt target
        bytes32 l2BlockHash = keccak256(abi.encode(data));

        // Do the stores necessary
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

    /// @notice Rolls back the chain to a previous state by truncating the roots array
    /// @dev Uses assembly to efficiently resize the roots array. Updates lastTimestamp to match priorBlock.
    /// @param indexToRemove Block number to rollback to (all blocks >= this index are removed)
    /// @param priorBlock Block data for block at indexToRemove-1. Must match stored hash if indexToRemove > 0.
    ///        Ignored if indexToRemove == 0.
    function rollback(uint256 indexToRemove, BlockData memory priorBlock) internal {
        // TODO - Should we enforce no rollback to timestamps which are too old?
        if (indexToRemove >= roots.length) revert RollbackIndexOutOfBounds();
        emit Rollback(roots.length, indexToRemove);

        // TODO - Meter the gas use possible opt target
        if (indexToRemove != 0) {
            bytes32 l2BlockHash = keccak256(abi.encode(priorBlock));
            if (l2BlockHash != roots[indexToRemove - 1]) revert PriorRootMismatch();
            lastTimestamp = priorBlock.blockIndex;
        } else {
            lastTimestamp = TimestampAndIndex({day: 0, index: 0});
        }

        assembly ("memory-safe") {
            sstore(roots.slot, indexToRemove)
        }
    }

    /// @notice Returns the current chain height (number of blocks)
    /// @return The total number of blocks in the chain
    function getCurrentBlocknumber() public view returns (uint256) {
        return (roots.length);
    }

    /// @notice Checks if a block is included and has passed the challenge period
    /// @param data The block data to check
    /// @return True if block is included and timestamp + CHALLENGE_PERIOD < current time
    function isConfirmed(BlockData memory data) public view returns (bool) {
        if (!isBlockIncluded(data)) {
            return false;
        }
        return (data.timestamp + CHALLENGE_PERIOD < block.timestamp);
    }

    /// @notice Checks if a block's hash matches the stored root at its block number
    /// @param data The block data to verify
    /// @return True if keccak256(abi.encode(data)) matches roots[data.blockNr]
    function isBlockIncluded(BlockData memory data) internal view returns (bool) {
        bytes32 l2BlockHash = keccak256(abi.encode(data));
        return roots[data.blockNr] == l2BlockHash;
    }

    /// @notice Checks if an anchor exists in the current chain (not reorged)
    /// @dev Uses partial hash comparison (24 bytes) for gas efficiency. Genesis anchor always returns true.
    /// @param anchor The merkle tree anchor to check
    /// @return True if anchor is genesis or exists at a valid index with matching partial hash
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
        return (partialHash == bytes24(roots[uint256(index)]));
    }

    /// @notice Validates that the provided anchor matches the expected prior anchor for a tree update
    /// @dev For first update in a block (updateNr==0 for deposits, or updateNr==0 with no deposits for tx),
    ///      checks anchor matches the previous block's final anchor. Otherwise validates via KZG proof.
    /// @param anchor The claimed prior anchor to validate
    /// @param data Block data containing the update
    /// @param updateNr The update index within the block. For deposits: group index [0, ceil(numDeposits/3)).
    ///        For transactions: transaction index [0, numTransactions).
    /// @param isDeposit True if validating a deposit update, false for transaction
    /// @param commitment KZG commitment for blob proof (unused if updateNr==0 for first update)
    /// @param proof KZG proof for the anchor at the prior root memory location
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
            if (!isAnchorIncluded(anchor)) revert AnchorNotIncluded();
            if (data.blockNr == 0) {
                if (anchor != GENESIS_ANCHOR) revert InvalidGenesisAnchor();
            } else {
                if (anchorToIndex[anchor].index != data.blockNr - 1) revert AnchorIndexMismatch();
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
