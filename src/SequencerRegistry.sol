// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Ownable} from "solady/auth/Ownable.sol";

// The module which handles the registration of the sequencers

// TODO - Yield System integration

contract SequencerRegistry is Ownable {
    uint256 constant EPOC_LENGTH = 10;
    uint256 constant CHALLENGE_WINDOW = 10;
    uint256 immutable START = block.timestamp;
    // Allows at most denoms of 1/10000th of an ether
    uint256 constant STAKE_DIVISOR = 10^14;
    uint256 constant MAX_STAKE = 200 ether / STAKE_DIVISOR;

    uint256 requiredStake = 20 ether / STAKE_DIVISOR;

    // TODO - Optimize packing
    struct SequencerStatus {
        bool isActive;
        bool isPriority;
        uint8 priorityIndex;
        uint64 blocknumberChallanged;
        uint64 timestampChallanged;
        uint64 stakeAmount;
        address payable challenger;
    }
    mapping(address => SequencerStatus) sequencers;
    mapping(address => uint256) exits;
    address[] firstLookSequncers;

    // Checks if (1) the user is a registered sequencer (2) if the time is within the reserved seqeuncing period
    // then that this is firstLookSequncer
    function isAllowed(address sequencer) public view returns (bool) {
        (uint256 current, bool isClosed) = currentEpoc();
        if (isClosed) {
            return (sequencer == firstLookSequncers[current % firstLookSequncers.length]);
        }
        return sequencers[sequencer].isActive && (sequencers[sequencer].stakeAmount >= requiredStake);
    }

    // Computes the epoc and returns if we are in the first half of an epoc
    function currentEpoc() public view returns (uint256, bool) {
        uint256 epoc = (block.timestamp - START) / EPOC_LENGTH;
        // The rounding error here tells us how much of the epoc has passed.
        uint256 elapsed = block.timestamp - (epoc * EPOC_LENGTH + START);
        return (epoc, elapsed < EPOC_LENGTH / 2);
    }

    // Take the money from the sequncer then
    function fund() external payable {
        require(sequencers[msg.sender].challenger == address(0));
        // TODO Need to trigger deposit into the yield system
        sequencers[msg.sender].isActive = true;
        sequencers[msg.sender].stakeAmount += uint64(msg.value/STAKE_DIVISOR);
    }

    function slash(address sequencer, uint256 blockNumber) internal {
        sequencers[sequencer].isActive = false;
        sequencers[sequencer].timestampChallanged = (uint64)(block.timestamp);

        if (
            sequencers[sequencer].blocknumberChallanged == 0
                || sequencers[sequencer].blocknumberChallanged > blockNumber
        ) {
            // In this case we add the sender as the person who is getting half the stake
            sequencers[sequencer].challenger == msg.sender;
            // This is to account for an annoying case where a sequencer pushes multiple invalid blocks then slashes themselves.
            // TODO Probally there is a better way?
            sequencers[sequencer].blocknumberChallanged == blockNumber;
        }

        if (sequencers[sequencer].isPriority) {
            _remove(sequencers[sequencer].priorityIndex);
        }
    }

    function claimChallangeReward(address who) external {
        SequencerStatus memory status = sequencers[who];
        uint256 challangeTime = uint256(status.timestampChallanged);
        require(challangeTime != 0 && block.timestamp - challangeTime >= CHALLENGE_WINDOW, "Not ready");
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
        (bool success,) = payable(who).call{value: status.stakeAmount * STAKE_DIVISOR}("");
        // TODO burn the other half into yield using the yield system
        require(success, "Payout failed");
    }

    function addFirstLook(address who) external onlyOwner {
        require(sequencers[who].isActive);
        firstLookSequncers.push(who);
        sequencers[who].isPriority = true;
    }

    function removeFirstLook(uint256 which) public onlyOwner {
        _remove(which);
    }

    // NOTE - Invalid uses of this will lock the seqeuncing
    function updateStake(uint256 amount) public onlyOwner {
        require(amount < MAX_STAKE);
        requiredStake = amount;
    }

    function _remove(uint256 which) internal {
        // Remove their status
        address who = firstLookSequncers[which];
        sequencers[who].isPriority = false;
        // Delete from array
        uint256 lenAfter = firstLookSequncers.length - 1;
        firstLookSequncers[which] = firstLookSequncers[lenAfter];
        assembly {
            sstore(firstLookSequncers.slot, lenAfter)
        }
    }
}
