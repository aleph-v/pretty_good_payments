// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


/// (State Root Spine)
///         |              |
///         v              v
///  (deposit/withdraw)   (sequncer update)

// State Root: 
// Parts: Submission, Windows, Staking, Yield
// Downstream: Challange protocol (invalid tx, non entered TX)

contract Sequencer {
    uint256 public number;

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }
}
