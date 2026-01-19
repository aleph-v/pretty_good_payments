// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Entrypoint} from "../src/Entrypoint.sol";

/// @title RegisterSequencer
/// @notice Script to register and fund a sequencer
/// @dev Requires ENTRYPOINT_ADDRESS and SEQUENCER_PRIVATE_KEY environment variables
contract RegisterSequencer is Script {
    function run() external {
        address entrypointAddr = vm.envAddress("ENTRYPOINT_ADDRESS");
        uint256 sequencerKey = vm.envUint("SEQUENCER_PRIVATE_KEY");
        uint256 stakeAmount = vm.envOr("STAKE_AMOUNT", uint256(20 ether));

        address sequencer = vm.addr(sequencerKey);
        Entrypoint entrypoint = Entrypoint(payable(entrypointAddr));

        console.log("Entrypoint:", entrypointAddr);
        console.log("Sequencer:", sequencer);
        console.log("Stake Amount:", stakeAmount);

        vm.startBroadcast(sequencerKey);

        // Fund the sequencer (registers them as active)
        entrypoint.fund{value: stakeAmount}();

        vm.stopBroadcast();

        // Verify registration
        (bool isActive,,,,,,) = entrypoint.sequencers(sequencer);

        console.log("\n=== Registration Result ===");
        console.log("Is Active:", isActive);
        console.log("Sequencer registered with stake:", stakeAmount / 1 ether, "ETH");
    }
}

/// @title AddPrioritySequencer
/// @notice Script to add a sequencer to the priority (first-look) list
/// @dev Requires owner privileges on the Entrypoint contract
contract AddPrioritySequencer is Script {
    function run() external {
        address entrypointAddr = vm.envAddress("ENTRYPOINT_ADDRESS");
        uint256 ownerKey = vm.envUint("OWNER_PRIVATE_KEY");
        address sequencerToAdd = vm.envAddress("SEQUENCER_ADDRESS");

        Entrypoint entrypoint = Entrypoint(payable(entrypointAddr));

        console.log("Adding priority sequencer:", sequencerToAdd);

        vm.startBroadcast(ownerKey);

        entrypoint.addFirstLook(sequencerToAdd);

        vm.stopBroadcast();

        console.log("Sequencer added to priority list");
    }
}

/// @title CheckSequencerStatus
/// @notice Script to check a sequencer's registration status
contract CheckSequencerStatus is Script {
    function run() external view {
        address entrypointAddr = vm.envAddress("ENTRYPOINT_ADDRESS");
        address sequencer = vm.envAddress("SEQUENCER_ADDRESS");

        Entrypoint entrypoint = Entrypoint(payable(entrypointAddr));

        (
            bool isActive,
            bool isPriority,
            uint8 priorityIndex,
            uint64 blocknumberChallenged,
            uint64 timestampChallenged,
            uint64 stakeAmount,
            address challenger
        ) = entrypoint.sequencers(sequencer);

        uint256 stakeInWei = uint256(stakeAmount) * 10 ** 14;
        uint256 requiredStake = entrypoint.requiredStake() * 10 ** 14;

        console.log("=== Sequencer Status ===");
        console.log("Address:", sequencer);
        console.log("Is Active:", isActive);
        console.log("Is Priority:", isPriority);
        console.log("Priority Index:", priorityIndex);
        console.log("Stake Amount:", stakeInWei / 1 ether, "ETH");
        console.log("Required Stake:", requiredStake / 1 ether, "ETH");
        console.log("Challenged at block:", blocknumberChallenged);
        console.log("Challenged at time:", timestampChallenged);
        console.log("Challenger:", challenger);

        bool isAllowed = entrypoint.isAllowed(sequencer);
        console.log("Is Allowed to Post:", isAllowed);
    }
}
