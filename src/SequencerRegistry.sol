// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// The module which handles the registration of the sequencers

contract SequencerRegistry {
    uint256 constant EPOC_LENGTH = 10;
    uint256 immutable start;

    uint256 requiredStake;

    struct sequencerStatus {
        bool isActive;
        bool isPriority;
        bool challangeClaimed;
        address challenger;
        uint64 blocknumberChallanged;
        uint64 timestampChallanged;
    }
    mapping(address => sequencerStatus) sequencers;
    address[] firstLookSequncers;

    // Checks if (1) the user is a registered sequencer (2) if the time is within the reserved seqeuncing period
    // then that this is firstLookSequncer
    function isAllowed(address sequencer) public view returns (bool) {
        return true;
    }

    // Computes the epoc and returns if we are in the first half of an epoc
    function currentEpoc() public view returns (uint256, bool) {
        uint256 epoc = (block.timestamp - start) / EPOC_LENGTH;
        // The rounding error here tells us how much of the epoc has passed.
        uint256 elapsed = block.timestamp - (epoc * EPOC_LENGTH + start);
        return (epoc, elapsed < EPOC_LENGTH / 2);
    }

    // Take the money from the sequncer then
    function register() external payable {
        require(msg.value > requiredStake);
        require(sequencers[msg.sender].challenger == address(0));
        // TODO Need to trigger deposit into the yield system
        sequencers[msg.sender].isActive = true;
    }

    function slash(address sequencer, uint256 blockNumber) internal {
        sequencers[sequencer].isActive = false;
        sequencers[sequencer].isPriority = false;
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
    }

    function claimChallanged(address sequencer) external {
        // TODO the user who has done the deepest depth challange gets half the reward after time elapsed has passed boundry.
    }
}
