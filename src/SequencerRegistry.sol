// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Ownable} from "solady/auth/Ownable.sol";

// The module which handles the registration of the sequencers

// TODO - Yield System integration, need weth support

contract SequencerRegistry is Ownable {
    uint256 constant EPOCH_LENGTH = 10;
    uint256 constant CHALLENGE_WINDOW = 10;
    uint256 immutable START = block.timestamp;
    // Allows at most denoms of 1/10000th of an ether
    uint256 constant STAKE_DIVISOR = 10 ^ 14;
    uint256 constant MAX_STAKE = 200 ether / STAKE_DIVISOR;

    uint256 public requiredStake = 20 ether / STAKE_DIVISOR;

    // TODO - Optimize packing
    struct SequencerStatus {
        bool isActive;
        bool isPriority;
        uint8 priorityIndex;
        uint64 blocknumberChallenged;
        uint64 timestampChallenged;
        uint64 stakeAmount;
        address payable challenger;
    }

    mapping(address => SequencerStatus) public sequencers;
    mapping(address => uint256) public exits;
    address[] public firstLookSequencers;

    // Checks if (1) the user is a registered sequencer (2) if the time is within the reserved sequencing period
    // then that this is firstLookSequencer
    function isAllowed(address sequencer) public view returns (bool) {
        (uint256 current, bool isClosed) = currentEpoch();
        if (isClosed) {
            return (sequencer == firstLookSequencers[current % firstLookSequencers.length]);
        }
        return sequencers[sequencer].isActive && (sequencers[sequencer].stakeAmount >= requiredStake);
    }

    // Computes the epoc and returns if we are in the first half of an epoch
    function currentEpoch() public view returns (uint256, bool) {
        uint256 epoch = (block.timestamp - START) / EPOCH_LENGTH;
        // The rounding error here tells us how much of the epoc has passed.
        uint256 elapsed = block.timestamp - (epoch * EPOCH_LENGTH + START);
        return (epoch, elapsed < EPOCH_LENGTH / 2);
    }

    // Take the money from the sequncer then
    function fund() external payable {
        require(sequencers[msg.sender].challenger == address(0));
        // TODO Need to trigger deposit into the yield system
        sequencers[msg.sender].isActive = true;
        sequencers[msg.sender].stakeAmount += uint64(msg.value / STAKE_DIVISOR);
    }

    function slash(address sequencer, uint256 blockNumber) internal {
        sequencers[sequencer].isActive = false;
        sequencers[sequencer].timestampChallenged = (uint64)(block.timestamp);

        if (
            sequencers[sequencer].blocknumberChallenged == 0
                || sequencers[sequencer].blocknumberChallenged > blockNumber
        ) {
            // In this case we add the sender as the person who is getting half the stake
            sequencers[sequencer].challenger == msg.sender;
            // This is to account for an annoying case where a sequencer pushes multiple invalid blocks then slashes themselves.
            sequencers[sequencer].blocknumberChallenged == blockNumber;
        }

        if (sequencers[sequencer].isPriority) {
            _remove(sequencers[sequencer].priorityIndex);
        }
    }

    function claimChallengeReward(address who) external {
        SequencerStatus memory status = sequencers[who];
        uint256 challengeTime = uint256(status.timestampChallenged);
        require(challengeTime != 0 && block.timestamp - challengeTime >= CHALLENGE_WINDOW, "Not ready");
        delete sequencers[who];
        (bool success,) = status.challenger.call{value: status.stakeAmount * STAKE_DIVISOR / 2}("");
        require(success, "Payout failed");
        // TODO burn the other half into yield using the yield system
    }

    function registerExit() external {
        require(sequencers[msg.sender].isActive);
        sequencers[msg.sender].isActive = false;
        if (sequencers[msg.sender].isPriority) {
            _remove(sequencers[msg.sender].priorityIndex);
        }
        exits[msg.sender] = block.timestamp;
    }

    function exit(address who) external {
        require(exits[who] != 0 && block.timestamp - exits[who] >= CHALLENGE_WINDOW, "Exit pending");
        SequencerStatus memory status = sequencers[who];
        require(status.challenger == address(0));
        // Now we can remove and refund them
        delete sequencers[who];
        delete exits[who];
        (bool success,) = payable(who).call{value: status.stakeAmount * STAKE_DIVISOR}("");
        // TODO burn the other half into yield using the yield system
        require(success, "Payout failed");
    }

    function addFirstLook(address who) external onlyOwner {
        require(sequencers[who].isActive);
        firstLookSequencers.push(who);
        sequencers[who].isPriority = true;
    }

    function removeFirstLook(uint256 which) public onlyOwner {
        _remove(which);
    }

    // NOTE - Invalid uses of this will lock the sequencing
    function updateStakeRequirement(uint256 amount) public onlyOwner {
        require(amount < MAX_STAKE);
        requiredStake = amount;
    }

    function _remove(uint256 which) internal {
        // Remove their status
        address who = firstLookSequencers[which];
        sequencers[who].isPriority = false;
        // Delete from array
        uint256 lenAfter = firstLookSequencers.length - 1;
        firstLookSequencers[which] = firstLookSequencers[lenAfter];
        assembly {
            sstore(firstLookSequencers.slot, lenAfter)
        }
    }
}
