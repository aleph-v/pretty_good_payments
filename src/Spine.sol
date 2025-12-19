// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// The core library managing new blocks

// We are going to have most of the state here

contract Spine {
    // TODO real number
    uint256 constant CHALLANGE_PERIOD = 100;
    uint256 constant MAX_TX = 4096;
    uint256 constant MAX_DEPOSITS = 1024;

    // Needed in the deposit withdraw libs downstream.
    address immutable yieldRouter;

    // The anchor is the root of the merkle tree at the end of this block
    struct BlockData {
        bytes32 anchor;
        uint256 timestamp;
        uint256 numTransactions;
        uint256 numDeposits;
        uint256 index;
        address sequencer;
        bytes32[] blobhashes;
    }

    struct IndexAndPartialHash {
        uint64 index;
        bytes24 partialHash;
    }

    // We optimise the storage footprint of submission by storing the hash of the block info
    // to use this block info later we have to provide the whole block
    bytes32[] roots;
    // We need to store the anchors so they can be looked up in the challange protocol
    // We do a bit of a trick here we only need 64 bits for index so we store 24 bytes of the hash
    // using one store, and can compare this to the block hash, which to break would require two
    // roots matching at 192 bits (birthday attack is 96 bits to attack)
    mapping(bytes32 => IndexAndPartialHash) anchorToIndex;

    // TODO - Should we add more event data? May make it easier to index in the sequencer
    event NewRoot(uint256 indexed blocknumber, bytes32 indexed root, BlockData data);

    // Pushes a block into the chain of roots, records the data
    function addBlock(BlockData memory data, uint256[] memory blobIndicies) internal {
        // Enforce the claimed data is correct
        data.timestamp = block.timestamp;
        data.index = roots.length;
        for (uint256 i = 0; i < blobIndicies.length; i++) {
            bytes32 hash = blobhash(blobIndicies[i]);
            require(hash != 0);
            data.blobhashes[i] = hash;
        }
        require(data.numDeposits < MAX_DEPOSITS);
        require(data.numTransactions < MAX_TX);

        // TODO - Meter the gas use possible opt target
        bytes32 l2BlockHash = keccak256(abi.encode(data));

        // Do the stores nessecary
        bytes24 partialHash = bytes24(l2BlockHash >> 8);
        anchorToIndex[data.anchor].index = uint64(data.index);
        anchorToIndex[data.anchor].partialHash = partialHash;
        roots.push(l2BlockHash);

        // Includes the block number and the root
        // Users can get the rest of the data from the getters
        emit NewRoot(data.index, l2BlockHash, data);
    }

    event Rollback(uint256 from, uint256 to);

    // Uses assembly to rollback the state array
    function rollback(uint256 index) internal {
        // TODO - Should we enforce no rollback to timestamps which are too old?
        require(index < roots.length);
        emit Rollback(roots.length, index);

        assembly {
            sstore(roots.slot, index)
        }
    }

    // Returns the highest nonreorged index
    function getCurrentBlocknumber() public view returns (uint256) {
        return (roots.length);
    }

    // Helper function determining if a hash of a block is confirmed
    function isConfirmed(BlockData memory data, uint256 blockNumber) public view returns (bool) {
        bytes32 l2BlockHash = keccak256(abi.encode(data));
        if (roots[blockNumber] != l2BlockHash) {
            // Rorged or incorrect blockdata
            return false;
        }

        return (data.timestamp + CHALLANGE_PERIOD < block.timestamp);
    }

    // We can use this function to check if anchor exists in the current tree (ie not reorged)
    function isAnchorIncluded(bytes32 anchor) public view returns (bool) {
        uint64 index = anchorToIndex[anchor].index;
        bytes24 partialHash = anchorToIndex[anchor].partialHash;
        if (uint256(index) >= roots.length) {
            return false;
        }
        return (partialHash == bytes24(roots[uint256(index)] >> 8));
    }
}
