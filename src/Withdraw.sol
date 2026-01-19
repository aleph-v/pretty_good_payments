// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Spine} from "./Spine.sol";
import {PredictableMerkleLib, Leaf} from "./library/PredictableMerkleLib.sol";
import {
    BlockNotConfirmed,
    AlreadyWithdrawn,
    InvalidLeafWhich,
    TxIndexOutOfBounds,
    PublicKeyNotZero
} from "./library/Errors.sol";

/// @title Withdraw
/// @notice Handles withdrawals from L2 to L1 by proving output leaves with publicKey=0

contract Withdraw is Spine {
    using PredictableMerkleLib for Leaf;

    mapping(uint256 => mapping(uint256 => bool)) public withdrawn;

    /// @notice Withdraws funds from a confirmed L2 transaction output
    /// @dev Output must have publicKey=0 (making it unspendable on L2). Recipient is encoded in leaf.blinding.
    ///      KZG proof validates the leaf exists at the correct memory address in the block's blob.
    /// @param leaf The output leaf to withdraw. Must have publicKey=0, blinding encodes recipient address.
    /// @param data Block data containing the transaction (must be confirmed)
    /// @param txNr Transaction index within the block [0, numTransactions)
    /// @param which Output index within the transaction [0, 3)
    /// @param commitment 48-byte KZG commitment for the blob
    /// @param proof 48-byte KZG proof for the leaf hash at calculated memory address
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
        bytes32 l2blobhash = data.blobhashes[memoryAddress / 4096];
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
