// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// The core library managing new blocks

// We are going to have most of the state here

contract Spine {
    // TODO real number
    uint256 constant CHALLANGE_PERIOD = 100;

    // Needed in the deposit withdraw libs downstream.
    address immutable yieldRouter;

    // TODO - Optimise the block layouts
    struct ProposedBlock {
        uint64 timestamp;
        uint32 numTransactions;
        uint32 numDeposits;
        uint32 index;
        address sequencer;
    }

    // Contains each root in order
    bytes32[] roots;
    mapping(bytes32 => ProposedBlock) public blockdata;
    mapping(bytes32 => bytes32[]) public blobhashes;

    // TODO - Should we add more event data? May make it easier to index in the sequencer
    event NewRoot(uint256 indexed blocknumber, bytes32 indexed root);

    // Pushes a block into the chain of roots, records the data
    function addBlock(bytes32 root, ProposedBlock memory data, uint256[] memory blobIndicies) internal {
        // We won't let the user sset their own timestamp
        data.timestamp = (uint64)(block.timestamp);
        data.index = (uint32)(roots.length);
        blockdata[root] = data;
        // Add the root to the array
        roots.push(root);
        // Store the blobhashes
        bytes32[] storage blobhash_ptr = blobhashes[root];
        require(blobhash_ptr.length == 0);
        for (uint256 i = 0; i < blobIndicies.length; i++) {
            bytes32 hash = blobhash(blobIndicies[i]);
            require(hash != 0);
            blobhash_ptr.push(hash);
        }
        // Includes the block number and the root
        // Users can get the rest of the data from the getters
        emit NewRoot(data.index, root);
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

    // Helper function confirming the
    function isConfirmed(bytes32 root) public view returns (bool) {
        // TODO optimise?
        if (blockdata[root].timestamp == 0) {
            // Never added
            return false;
        }
        if (roots[blockdata[root].index] != root) {
            // Reorged
            return false;
        }
        return (blockdata[root].timestamp + CHALLANGE_PERIOD < block.timestamp);
    }
}
