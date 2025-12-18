// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./library/PredictableMerkleLib.sol";
import "./library/BlobData.sol";

// Handles user withdraws

// We require the user to make a transaction which has an eth address as a public key, this means with roughly 80 bits
// of security the note cannot be respent since it would require finding a private key to an eth address which should be
// intractable. Then we just mark the note as withdrawn so the same note cannot be used again.

// TODO - We might want to work on an escape hatch or other mechanism, requiring the user to self seqeunce a withdraw tx
//        might be too much of a burden if they are being censored (because it requires staking).

contract Withdraw is Spine, BlobData {
    using PredictableMerkleLib for Leaf;

    mapping(bytes32 => mapping(uint256 => bool)) public withdrawn;

    function withdraw(
        Leaf memory leaf,
        bytes32 anchor,
        uint256 blobHashIndex,
        uint256 txNr,
        uint256 which,
        bytes calldata commitment,
        bytes calldata proof
    ) external {
        // Checks that the anchor is confirmed and that the leaf is in the tree
        require(isConfirmed(anchor));
        // TODO need more index info on withdraws
        require(!withdrawn[anchor][txNr << 2 + which]);

        // Get the leaf hash and the blob hash
        bytes32 leafHash = leaf.hash();
        bytes32 blobhash = blobhashes[anchor][blobHashIndex];

        // Validate the tx info and then compute the location "leaf" should be in the blob
        require(which < 3);
        require(txNr < blockdata[anchor].numTransactions);
        // We cannot withdraw from deposit leafs
        // NOTE - We treat the case of multiple blobs as simple multiple conjoined memory regions so the leafMemoryAddress function
        //        will return a value greater than 4096 but will still give the correct location. Therefore we subtract out
        //        extra blob field elements to get the true "in blob" 32 byte memory address
        uint256 blobIndex = leafMemoryAddress(txNr, blockdata[anchor].numDeposits, false, which) - 4096 * blobHashIndex;
        // Validate will revert on any problems but will otherwise prove that the is an output leaf
        // of transaction number txNumber
        validateSingle(blobhash, commitment, blobIndex, leafHash, proof);

        // Next we check that the leaf is actually withdrawable
        // The user submits a transaction which is to a key which
        // TODO - New Wwithdraw scheme
        require(leaf.publicKey >> 160 == 0);

        // Now process
        withdrawn[anchor][txNr << 2 + which] = true;
        //yieldRouter.triggerWithdraw(leaf.asset, leaf.amount, address(leaf.publicKey));
    }
}
