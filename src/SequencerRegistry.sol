// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Ownable} from "solady/auth/Ownable.sol";
import {Spine} from "./Spine.sol";
import {
    AlreadyChallenged,
    ChallengeWindowNotElapsed,
    PayoutFailed,
    SequencerNotActive,
    ExitWindowNotElapsed,
    StakeExceedsMaximum
} from "./library/Errors.sol";

// The module which handles the registration of the sequencers

contract SequencerRegistry is Spine, Ownable {
    uint256 constant EPOCH_LENGTH = 10;
    uint256 constant CHALLENGE_WINDOW = 10;
    // Allows at most denoms of 1/10000th of an ether
    uint256 constant STAKE_DIVISOR = 10 ** 14;
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
            uint256 len = firstLookSequencers.length;
            if (len == 0) {
                return (true);
            }
            return (sequencer == firstLookSequencers[current % len]);
        }
        return sequencers[sequencer].isActive && (sequencers[sequencer].stakeAmount >= requiredStake);
    }

    // Computes the epoch and returns if we are in the first half of an epoch
    function currentEpoch() public view returns (uint256, bool) {
        uint256 epoch = (block.timestamp - START) / EPOCH_LENGTH;
        // The rounding error here tells us how much of the epoch has passed.
        uint256 elapsed = block.timestamp - (epoch * EPOCH_LENGTH + START);
        return (epoch, elapsed < EPOCH_LENGTH / 2);
    }

    // Checks if the sequencer has a set challenger address
    function isChallenged(address who) public view returns (bool) {
        return (sequencers[who].challenger != address(0));
    }

    // Take the money from the sequncer then
    function fund() external payable {
        if (sequencers[msg.sender].challenger != address(0)) revert AlreadyChallenged();
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
            sequencers[sequencer].challenger = payable(msg.sender);
            // This is to account for an annoying case where a sequencer pushes multiple invalid blocks then slashes themselves.
            sequencers[sequencer].blocknumberChallenged = uint64(blockNumber);
        }

        if (sequencers[sequencer].isPriority) {
            _remove(sequencers[sequencer].priorityIndex);
        }
    }

    function claimChallengeReward(address who) external {
        SequencerStatus memory status = sequencers[who];
        uint256 challengeTime = uint256(status.timestampChallenged);
        if (challengeTime == 0 || block.timestamp - challengeTime < CHALLENGE_WINDOW) revert ChallengeWindowNotElapsed();
        delete sequencers[who];
        (bool success,) = status.challenger.call{value: status.stakeAmount * STAKE_DIVISOR / 2}("");
        if (!success) revert PayoutFailed();
        // TODO burn the other half into yield using the yield system
    }

    function registerExit() external {
        if (!sequencers[msg.sender].isActive) revert SequencerNotActive();
        sequencers[msg.sender].isActive = false;
        if (sequencers[msg.sender].isPriority) {
            _remove(sequencers[msg.sender].priorityIndex);
        }
        exits[msg.sender] = block.timestamp;
    }

    function exit(address who) external {
        if (exits[who] == 0 || block.timestamp - exits[who] < CHALLENGE_WINDOW) revert ExitWindowNotElapsed();
        SequencerStatus memory status = sequencers[who];
        if (status.challenger != address(0)) revert AlreadyChallenged();
        // Now we can remove and refund them
        delete sequencers[who];
        delete exits[who];
        (bool success,) = payable(who).call{value: status.stakeAmount * STAKE_DIVISOR}("");
        if (!success) revert PayoutFailed();
    }

    function addFirstLook(address who) external onlyOwner {
        if (!sequencers[who].isActive) revert SequencerNotActive();
        firstLookSequencers.push(who);
        sequencers[who].isPriority = true;
        sequencers[who].priorityIndex = uint8(firstLookSequencers.length - 1);
    }

    function removeFirstLook(uint256 which) public onlyOwner {
        _remove(which);
    }

    // NOTE - Invalid uses of this will lock the sequencing
    function updateStakeRequirement(uint256 amount) public onlyOwner {
        if (amount >= MAX_STAKE) revert StakeExceedsMaximum();
        requiredStake = amount;
    }

    function _remove(uint256 which) internal {
        // Remove their status
        address who = firstLookSequencers[which];
        sequencers[who].isPriority = false;
        // Delete from array
        uint256 lenAfter = firstLookSequencers.length - 1;
        // Make sure to set the index to keep things updated
        sequencers[firstLookSequencers[lenAfter]].priorityIndex = uint8(which);
        firstLookSequencers[which] = firstLookSequencers[lenAfter];
        assembly ("memory-safe") {
            sstore(firstLookSequencers.slot, lenAfter)
        }
    }
}
