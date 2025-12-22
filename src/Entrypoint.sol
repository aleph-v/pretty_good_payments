// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./DepositChallenge.sol";
import "./TransactionChallenge.sol";
import "./NullifierChallenge.sol";
import "./TreeUpdateChallange.sol";
import "./Withdraw.sol";

// This is the main entrypoint for seqeuncing and handles the percentage payouts.
// Through the inheritance system this pulls in all of the logic needed.

// TODO - Look into ways to minimize the cost of the tracking system.

contract Entrypoint is Withdraw, DepositChallenge, TransactionChallenge, NullifierChallenge, TreeUpdateChallange {
    // Here we track the percent rewards per epoc for the the 
    mapping(uint256 => uint256) public totalBlobUse;
    mapping(uint256 => mapping(address => uint256)) public sequencerBlobUse;

    uint256 priorityBonus = 2e3;
    uint256 constant BASE = 1e3;
    uint256 constant FIXED_BASE  = 1e18;

    // The function which allows sequencers to post
    function post(
        BlockData memory data, 
        uint256[] memory blobIndicies
    ) external {
        require(isAllowed(msg.sender));
        addBlock(data, blobIndicies);
        (uint256 epoc, bool currentlyPriorty) = currentEpoc();

        // Tracking this basis of blob data usage gives a fair tradeoff on cost
        uint256 rawBlobUse = data.numTransactions*15 + data.numDeposits*4;
        uint256 adjustedTx = currentlyPriorty? rawBlobUse*priorityBonus/BASE: rawBlobUse;
        totalTx[epoc] += adjustedTx;
        sequencerBlobUse[epoc][msg.sender] += adjustedTx;
    }

    function allocateRewards(uint256 epocNumber, address sequencer) external {
        // Allows you to push percent rewards into the yield system for a sequencer
    }
}
