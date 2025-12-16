// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./library/PredictableMerkleLib.sol";

// Handles user withdraws

// We require the user to make a transaction which has an eth address as a public key, this means with roughly 80 bits
// of security the note cannot be respent since it would require finding a private key to an eth address which should be
// intractable. Then we just mark the note as withdrawn so the same note cannot be used again.

// TODO - We might want to work on an escape hatch or other mechanism, requiring the user to self seqeunce a withdraw tx
//        might be too much of a burden if they are being censored (because it requires staking).

contract Withdraw is Spine {
    using PredictableMerkleLib for Leaf;

    mapping(uint256 => bool) public withdrawn;

    function withdraw(Leaf memory leaf, bytes32 anchor, uint256 index, bytes32[] memory proof) external {
        // Checks that the anchor is confirmed and that the leaf is in the tree
        require(isConfirmed(anchor));
        require(!withdrawn[index]);
        leaf.enforceInTree(anchor, index, proof);
        // Next we check that the leaf is actually withdrawable
        // The user submits a transaction which is to a key which
        require(leaf.publicKey >> 160 == 0);

        // Now process
        withdrawn[index] = true;
        //yieldRouter.triggerWithdraw(leaf.asset, leaf.amount, address(leaf.publicKey));
    }
}
