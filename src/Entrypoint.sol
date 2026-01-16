// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {DepositChallenge} from "./DepositChallenge.sol";
import {TransactionChallenge} from "./TransactionChallenge.sol";
import {NullifierChallenge} from "./NullifierChallenge.sol";
import {TreeUpdateChallenge} from "./TreeUpdateChallenge.sol";
import {Withdraw} from "./Withdraw.sol";
import {IYieldRouter} from "./interfaces/IYieldRouter.sol";
import {IUpdateVerifier} from "./interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "./interfaces/ITransferVerifier.sol";
import {ITransactionRegistry} from "./TransactionRegistry.sol";
import {NotAllowed, EpochNotFinished} from "./library/Errors.sol";

/// @title Entrypoint
/// @notice Main contract for L2 sequencing, combining all challenge types and handling sequencer yield payouts
/// @dev Inherits: Withdraw, DepositChallenge, TransactionChallenge, NullifierChallenge, TreeUpdateChallenge.
///      Tracks sequencer blob usage per epoch to compute proportional yield distribution.

contract Entrypoint is Withdraw, DepositChallenge, TransactionChallenge, NullifierChallenge, TreeUpdateChallenge {
    
    /// @notice Initializes the entrypoint with verifiers and external contracts
    /// @param genesis The genesis anchor (initial merkle root)
    /// @param _yieldRouter Contract handling yield distribution
    /// @param _predictableUpdateVerifier Groth16 verifier for merkle tree updates
    /// @param _transactionZkVerifier Groth16 verifier for transaction ZK proofs
    /// @param _transferRegistry Registry for ethereum-keyed transaction approvals
    constructor(
        bytes32 genesis,
        IYieldRouter _yieldRouter,
        IUpdateVerifier _predictableUpdateVerifier,
        ITransferVerifier _transactionZkVerifier,
        ITransactionRegistry _transferRegistry
    ) {
        GENESIS_ANCHOR = genesis;
        yieldRouter = _yieldRouter;
        predictableUpdateVerifier = _predictableUpdateVerifier;
        transactionZkVerifier = _transactionZkVerifier;
        transferRegistry = _transferRegistry;
    }

    // Here we track the percent rewards per epoch for each sequencer
    mapping(uint256 => uint256) public totalBlobUse;
    mapping(uint256 => mapping(address => uint256)) public sequencerBlobUse;

    uint256 priorityBonus = 2e3;
    uint256 constant BASE = 1e3;
    uint256 constant FIXED_BASE = 1e18;

    /// @notice Allows registered sequencers to post new L2 blocks
    /// @dev Validates sequencer permission, adds block, and tracks blob usage for yield calculation.
    ///      Priority sequencers receive a 2x bonus on their blob usage credits.
    /// @param data Block data struct with anchor, transactions, deposits, and sequencer info
    /// @param blobIndices EVM blob indices to read hashes from
    function post(BlockData memory data, uint256[] memory blobIndices) external {
        if (!isAllowed(msg.sender)) revert NotAllowed();
        addBlock(data, blobIndices);
        (uint256 epoch, bool currentlyPriority) = currentEpoch();

        // Tracking this basis of blob data usage gives a fair tradeoff on cost
        uint256 depositBlobUse = data.numDeposits % 3 == 0 ? (data.numDeposits / 3) * 4 : (data.numDeposits / 3 + 1) * 4;
        uint256 rawBlobUse = data.numTransactions * 15 + depositBlobUse;
        uint256 adjustedTx = currentlyPriority ? rawBlobUse * priorityBonus / BASE : rawBlobUse;
        totalBlobUse[epoch] += adjustedTx;
        sequencerBlobUse[epoch][msg.sender] += adjustedTx;
    }

    /// @notice Returns a sequencer's proportional share of blob usage in a given epoch
    /// @dev Returns 0 if no blobs were used in the epoch. Result is in 1e18 fixed point (1e18 = 100%).
    /// @param sequencer Address of the sequencer
    /// @param epoch The epoch number (must be in the past)
    /// @return Sequencer's share as 1e18 fixed point. 5e17 = 50%, 1e18 = 100%.
    function getPercentInEpoch(address sequencer, uint256 epoch) external view returns (uint256) {
        (uint256 epochNow,) = currentEpoch();
        if (epochNow <= epoch) revert EpochNotFinished();
        if (totalBlobUse[epoch] == 0) {
            return (0);
        }
        return ((sequencerBlobUse[epoch][sequencer] * FIXED_BASE) / totalBlobUse[epoch]);
    }

    /// @notice Checks if an epoch has passed the challenge period and is safe to withdraw from
    /// @dev An epoch is finalized when current epoch > epoch + (CHALLENGE_PERIOD / EPOCH_LENGTH) + 1
    /// @param epoch The epoch number to check
    /// @return True if the epoch is finalized, false otherwise
    function isFinalized(uint256 epoch) public view returns (bool) {
        (uint256 epochNow,) = currentEpoch();
        uint256 minEpochsWait = CHALLENGE_PERIOD / EPOCH_LENGTH + 1;
        return (epoch + minEpochsWait < epochNow);
    }
}
