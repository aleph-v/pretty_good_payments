// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import "solady/auth/Ownable.sol";

// Should implement a version of the hash which matches the hash used in the zk proofs
// Will be inherited by withdraws, deposits, and merkle tree lib

contract YieldSourceRegistry is Ownable {
    //
    address immutable bridge;
    mapping(address => IERC4626) sources;

    // For tracking the yields for sequencer payouts
    IERC4626[] trackedYieldSources;
    mapping(address => uint256) priorBalances;
    mapping(address => mapping(uint256 => uint256)) periodPayouts;
    mapping(address => mapping(address => uint256)) sequencerPayments;
    mapping(address => mapping(uint256 => bool)) reportedEpoc;

    modifier onlyBridge() {
        require(msg.sender == bridge);
        _;
    }

    // Triggers a global withdraw and deposit
    function changeYieldSource(address token, IERC4626 newSource) external onlyOwner {}

    // Triggers a yield source shutdown, which blocks new deposits and marks that the withdraws are not honored 1 to 1
    function shutdownAsset(address token) external onlyOwner {}

    // TODO we can optimise this state usage a lot I think. Possibly we can do this with a globalized payout system?
    //      At very least I think we can do a period power system instead of an epoc system?

    function poke() public {
        // If we have moved into a new period then go through the list of tracked yield sources, and report the increase in the period
        // Divide this by periods per epoc and store in the period payouts mapping for each asset

        // This is called on report payout (called 1 time per epoc automatically) or by a subsystem with a cron job.

        // We might want a max period payment field
    }

    // Reports a address as having earned a percent of the yield in an epoc
    function reportPayoutPercent(address sequencer, uint256 percent, uint256 epoc) external onlyBridge {
        poke();
        require(!reportedEpoc[sequencer][epoc]);
        // Iterate through tracked yield sources and give a percent of what is in the period payouts mapping
        // then add those values to the sequencer withdrawable.
        // If there is a loss these values get rugged.
    }

    function sequencerWithdraw(address token) external {
        // withdraws from the sequncer withdaws mapping.
    }
}
