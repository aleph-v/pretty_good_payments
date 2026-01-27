// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

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
    uint256 constant EPOCH_LENGTH = 1800;
    uint256 constant CHALLENGE_WINDOW = 3600;
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

    /// @notice Checks if a sequencer is allowed to submit blocks at current time
    /// @dev During first half of epoch (closed period), only priority sequencers can submit.
    ///      During second half (open period), any active sequencer with sufficient stake can submit.
    /// @param sequencer Address to check
    /// @return True if sequencer can submit blocks now
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

    /// @notice Returns current epoch number and whether we're in the closed (priority) period
    /// @return epoch Current epoch number (time since START / EPOCH_LENGTH)
    /// @return isClosed True if in first half of epoch (priority sequencing), false if open
    function currentEpoch() public view returns (uint256, bool) {
        uint256 epoch = (block.timestamp - START) / EPOCH_LENGTH;
        // The rounding error here tells us how much of the epoch has passed.
        uint256 elapsed = block.timestamp - (epoch * EPOCH_LENGTH + START);
        return (epoch, elapsed < EPOCH_LENGTH / 2);
    }

    /// @notice Checks if a sequencer has been challenged
    /// @param who Sequencer address to check
    /// @return True if sequencer has a non-zero challenger address
    function isChallenged(address who) public view returns (bool) {
        return (sequencers[who].challenger != address(0));
    }

    /// @notice Deposits stake to become or remain an active sequencer
    /// @dev Stake is stored in units of STAKE_DIVISOR (10^14 wei). Reverts if already challenged.
    function fund() external payable {
        if (sequencers[msg.sender].challenger != address(0)) revert AlreadyChallenged();
        // TODO Need to trigger deposit into the yield system
        sequencers[msg.sender].isActive = true;
        sequencers[msg.sender].stakeAmount += uint64(msg.value / STAKE_DIVISOR);
    }

    /// @notice Slashes a sequencer for submitting invalid blocks
    /// @dev Deactivates sequencer, records challenger. Only updates challenger if this is the earliest fraud.
    ///      Removes from priority list if applicable.
    /// @param sequencer Address of sequencer to slash
    /// @param blockNumber Block number where fraud occurred (used to track earliest fraud)
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

    /// @notice Claims reward after successfully challenging a sequencer
    /// @dev Challenger receives half the slashed stake. Must wait CHALLENGE_WINDOW after slash.
    /// @param who Address of the slashed sequencer
    function claimChallengeReward(address who) external {
        SequencerStatus memory status = sequencers[who];
        uint256 challengeTime = uint256(status.timestampChallenged);
        if (challengeTime == 0 || block.timestamp - challengeTime < CHALLENGE_WINDOW) {
            revert ChallengeWindowNotElapsed();
        }
        delete sequencers[who];
        (bool success,) = status.challenger.call{value: status.stakeAmount * STAKE_DIVISOR / 2}("");
        if (!success) revert PayoutFailed();
        // TODO burn the other half into yield using the yield system
    }

    /// @notice Initiates exit process for a sequencer to withdraw their stake
    /// @dev Sequencer must wait CHALLENGE_WINDOW after registering before calling exit()
    function registerExit() external {
        if (!sequencers[msg.sender].isActive) revert SequencerNotActive();
        sequencers[msg.sender].isActive = false;
        if (sequencers[msg.sender].isPriority) {
            _remove(sequencers[msg.sender].priorityIndex);
        }
        exits[msg.sender] = block.timestamp;
    }

    /// @notice Completes exit and refunds stake after waiting period
    /// @dev Must be called after CHALLENGE_WINDOW has passed since registerExit(). Fails if challenged.
    /// @param who Address of the exiting sequencer
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

    /// @notice Adds an active sequencer to the priority (first-look) list
    /// @dev Only owner can call. Sequencer must already be active.
    /// @param who Address to add to priority list
    function addFirstLook(address who) external onlyOwner {
        if (!sequencers[who].isActive) revert SequencerNotActive();
        firstLookSequencers.push(who);
        sequencers[who].isPriority = true;
        sequencers[who].priorityIndex = uint8(firstLookSequencers.length - 1);
    }

    /// @notice Removes a sequencer from the priority list by index
    /// @dev Only owner can call.
    /// @param which Index in firstLookSequencers array [0, firstLookSequencers.length)
    function removeFirstLook(uint256 which) public onlyOwner {
        _remove(which);
    }

    /// @notice Updates the minimum stake required to be an active sequencer
    /// @dev Only owner can call. Setting too high may lock sequencing if no one meets requirement.
    /// @param amount New stake requirement in STAKE_DIVISOR units. Must be < MAX_STAKE.
    function updateStakeRequirement(uint256 amount) public onlyOwner {
        if (amount >= MAX_STAKE) revert StakeExceedsMaximum();
        requiredStake = amount;
    }

    /// @notice Internal function to remove a sequencer from priority list
    /// @dev Uses swap-and-pop pattern. Updates priorityIndex of moved element.
    /// @param which Index to remove [0, firstLookSequencers.length)
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
