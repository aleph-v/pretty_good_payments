// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Spine} from "./Spine.sol";
import {PredictableMerkleLib, Leaf} from "./library/PredictableMerkleLib.sol";
import {
    BlockNotConfirmed,
    AlreadyWithdrawn,
    InvalidLeafWhich,
    TxIndexOutOfBounds,
    PublicKeyNotZero
} from "./library/Errors.sol";

// Handles user withdraws
contract Withdraw is Spine {
    using PredictableMerkleLib for Leaf;

    mapping(uint256 => mapping(uint256 => bool)) public withdrawn;

    function withdraw(
        Leaf memory leaf,
        BlockData memory data,
        uint256 txNr,
        uint256 which,
        bytes calldata commitment,
        bytes calldata proof
    ) external {
        // Checks that the anchor is confirmed and that the leaf is in the tree
        if (!isConfirmed(data)) revert BlockNotConfirmed();
        if (withdrawn[data.blockNr][(txNr << 2) + which]) revert AlreadyWithdrawn();

        // Validate the tx info and then compute the location "leaf" should be in the blob
        if (which >= 3) revert InvalidLeafWhich();
        if (txNr >= data.numTransactions) revert TxIndexOutOfBounds();

        // Get the leaf hash and the blob hash
        bytes32 leafHash = leaf.hash();
        uint256 memoryAddress = leafMemoryAddress(txNr, data.numDeposits, false, which);
        bytes32 l2blobhash = data.blobhashes[memoryAddress/4096];
        // We cannot withdraw from deposit leafs
        uint256 blobIndex = memoryAddress % 4096;
        // Validate will revert on any problems but will otherwise prove that the is an output leaf
        // of transaction number txNumber
        validateSingle(l2blobhash, commitment, blobIndex, leafHash, proof);

        // Next we check that the leaf is actually withdrawable
        // The user submits a transaction to a public key zero while setting the blinding factor,
        // this renders this note provably un-spendable.
        if (leaf.publicKey != 0) revert PublicKeyNotZero();

        // Now process
        withdrawn[data.blockNr][(txNr << 2) + which] = true;
        yieldRouter.triggerWithdraw(address(leaf.asset), leaf.amount, address(bytes20(leaf.blinding)));
    }
}
