// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// We may have many special purpose versions of these based on the yield integrations.

interface IYieldRouter {
    function triggerDeposit(address asset, uint256 amount) external;
    function triggerWithdraw(address asset, uint256 amount, address destination) external;
    function reportPayoutPercent(address sequencer, uint256 percent, uint256 epoch) external;
}
