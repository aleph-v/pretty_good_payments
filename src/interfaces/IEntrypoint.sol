// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/// @title IEntrypoint
/// @notice Interface for the main entrypoint contract's yield-related queries
/// @dev Used by YieldRouter to query sequencer participation and finalization status

interface IEntrypoint {
    /// @notice Returns a sequencer's blob usage share in an epoch
    /// @param sequencer Sequencer address
    /// @param epoch Epoch number (must be in the past)
    /// @return Percentage as 1e18 fixed point (1e18 = 100%)
    function getPercentInEpoch(address sequencer, uint256 epoch) external view returns (uint256);

    /// @notice Checks if an epoch has passed the challenge period
    /// @param epoch Epoch number
    /// @return True if finalized and safe to withdraw
    function isFinalized(uint256 epoch) external view returns (bool);

    /// @notice Checks if a sequencer is currently challenged
    /// @param who Sequencer address
    /// @return True if the sequencer has been challenged
    function isChallenged(address who) external view returns (bool);
}
