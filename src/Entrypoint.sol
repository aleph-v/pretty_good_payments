// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./DepositChallenge.sol";
import "./TransactionChallenge.sol";
import "./NullifierChallenge.sol";
import "./TreeUpdateChallenge.sol";
import "./Withdraw.sol";

// This is the main entrypoint for sequencing and handles the percentage payouts.
// Through the inheritance system this pulls in all of the logic needed.

// TODO - Look into ways to minimize the cost of the tracking system.

contract Entrypoint is Withdraw, DepositChallenge, TransactionChallenge, NullifierChallenge, TreeUpdateChallenge {

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

    // Here we track the percent rewards per epoch for the the
    mapping(uint256 => uint256) public totalBlobUse;
    mapping(uint256 => mapping(address => uint256)) public sequencerBlobUse;

    uint256 priorityBonus = 2e3;
    uint256 constant BASE = 1e3;
    uint256 constant FIXED_BASE = 1e18;

    // The function which allows sequencers to post
    function post(BlockData memory data, uint256[] memory blobIndices) external {
        require(isAllowed(msg.sender));
        addBlock(data, blobIndices);
        (uint256 epoch, bool currentlyPriority) = currentEpoch();

        // Tracking this basis of blob data usage gives a fair tradeoff on cost
        uint256 depositBlobUse = data.numDeposits % 3 == 0? (data.numDeposits/3)*4: (data.numDeposits/3 + 1)*4;
        uint256 rawBlobUse = data.numTransactions * 15 + depositBlobUse;
        uint256 adjustedTx = currentlyPriority ? rawBlobUse * priorityBonus / BASE : rawBlobUse;
        totalBlobUse[epoch] += adjustedTx;
        sequencerBlobUse[epoch][msg.sender] += adjustedTx;
        // We report and allocate the previous priority sequencer's rewards
        uint256 index = epoch % firstLookSequencers.length;
        uint256 priorSequencerIndex = index == 0 ? firstLookSequencers.length - 1 : index - 1;
        address priorSequencer = firstLookSequencers[priorSequencerIndex];
        allocateRewards(epoch - 1, priorSequencer);
    }

    function allocateRewards(uint256 epoch, address sequencer) public {
        uint256 percent = (sequencerBlobUse[epoch][sequencer] * 1e18) / totalBlobUse[epoch];
        require(percent != 0, "Nothing to report");
        yieldRouter.reportPayoutPercent(sequencer, percent, epoch);
    }
}
