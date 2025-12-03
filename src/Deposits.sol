// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./library/BlobData.sol";
import "./library/LeafLib.sol";

// The component of the challange system which enforces deposits are done properly

contract Deposits is Spine {
    using LeafLib for Leaf;

    uint256 constant MAX_DEPOSITS = 100;
    uint256 highestDeposit;
    //Records the required deposits in each block
    mapping(uint256 => bytes32[]) perBlockDeposits;

    // Works by doing the posiedon hashing of leaf and then pushing it into the deposits for the next possible block
    // If the chain is reorged due to fraud this deposits tree does not rollback, new blocks created at new indicies must
    // also include the same deposits.
    function deposit(Leaf memory leaf) external {
        // First transfer from the user
        // Then route this token into the yield system

        // Then hash to create blinding factor
        // then hash to create leaf

        // Finally if the highestDeposit > current block number add to the array at highest block, if higgest deposit <= current block
        // then add it to current block + 1 and set that as highest block
        // TODO we could smooth this out by requiring it every five blocks
        // NOTE we know that this can create some race conditions on block submission but we don't expect real problems.
    }
}
