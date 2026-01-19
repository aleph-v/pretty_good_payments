// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @title IYieldRouter
/// @notice Interface for yield routing and sequencer payout functionality
/// @dev Bridge contract calls triggerDeposit/triggerWithdraw; sequencers claim via payout system

interface IYieldRouter {
    /// @notice Called by bridge to deposit assets into yield source
    /// @param asset Token address to deposit
    /// @param amount Amount to deposit (must already be transferred to router)
    function triggerDeposit(address asset, uint256 amount) external;

    /// @notice Called by bridge to withdraw assets for user withdrawals
    /// @param asset Token address to withdraw
    /// @param amount Amount to withdraw
    /// @param destination Recipient address
    function triggerWithdraw(address asset, uint256 amount, address destination) external;

    /// @notice Reports payout percentage for a sequencer in an epoch
    /// @param sequencer Sequencer address
    /// @param percent Percentage (1e18 = 100%)
    /// @param epoch Epoch number
    function reportPayoutPercent(address sequencer, uint256 percent, uint256 epoch) external;
}
