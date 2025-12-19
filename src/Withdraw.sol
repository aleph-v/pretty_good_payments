// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Spine.sol";
import "./library/PredictableMerkleLib.sol";
import "./library/BlobData.sol";

// Handles user withdraws

// We require the user to make a transaction which has an eth address as a public key, this means with roughly 96 bits
// of work you can burn funds from the L2 but you would need far more to actually steal funds, as finding a preimage
// with 96 bits of first zeros requires roughly 2^96 tries but would only allow theft if you could also find a matching
// address priv key requring far more bits.

// TODO - We might want to work on an escape hatch or other mechanism, requiring the user to self seqeunce a withdraw tx
//        might be too much of a burden if they are being censored (because it requires staking).

contract Withdraw is Spine, BlobData {
    using PredictableMerkleLib for Leaf;

    mapping(uint256 => mapping(uint256 => bool)) public withdrawn;

    function withdraw(
        Leaf memory leaf,
        BlockData memory data,
        uint256 blockNr,
        uint256 blobHashIndex,
        uint256 txNr,
        uint256 which,
        bytes calldata commitment,
        bytes calldata proof
    ) external {
        // Checks that the anchor is confirmed and that the leaf is in the tree
        require(isConfirmed(data, blockNr));
        // TODO need more index info on withdraws
        require(!withdrawn[blockNr][txNr << 2 + which]);

        // Get the leaf hash and the blob hash
        bytes32 leafHash = leaf.hash();
        bytes32 l2blobhash = data.blobhashes[blobHashIndex];

        // Validate the tx info and then compute the location "leaf" should be in the blob
        require(which < 3);
        require(txNr < data.numTransactions);
        // We cannot withdraw from deposit leafs
        // NOTE - We treat the case of multiple blobs as simple multiple conjoined memory regions so the leafMemoryAddress function
        //        will return a value greater than 4096 but will still give the correct location. Therefore we subtract out
        //        extra blob field elements to get the true "in blob" 32 byte memory address
        uint256 blobIndex = leafMemoryAddress(txNr, data.numDeposits, false, which) - 4096 * blobHashIndex;
        // Validate will revert on any problems but will otherwise prove that the is an output leaf
        // of transaction number txNumber
        validateSingle(l2blobhash, commitment, blobIndex, leafHash, proof);

        // Next we check that the leaf is actually withdrawable
        // The user submits a transaction which is to a key which
        // TODO - New Wwithdraw scheme
        require(leaf.publicKey >> 160 == 0);

        // Now process
        withdrawn[blockNr][txNr << 2 + which] = true;
        //yieldRouter.triggerWithdraw(leaf.asset, leaf.amount, address(leaf.publicKey));
    }
}
