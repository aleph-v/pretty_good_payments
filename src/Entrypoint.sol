// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./DepositChallenge.sol";
import "./TransactionChallenge.sol";
import "./NullifierChallenge.sol";
import "./Withdraw.sol";

// This is the main entrypoint for seqeuncing and handles the percentage payouts.
// Through the inheritance system this pulls in all of the logic needed.

contract Entrypoint is Withdraw, DepositChallenge, TransactionChallenge, NullifierChallenge {
    mapping(uint256 => uint256) public totalTx;
    mapping(uint256 => mapping(address => uint256)) public sequencerTx;

    // The function which allows sequencers to post
    function post() external {
        // Check using the sequencer registry functions we can post
        // then push up the data to spine
    }

    function allocateRewards(uint256 epocNumber, address sequencer) external {
        // Allows you to push percent rewards into the yield system for a sequencer
    }
}
