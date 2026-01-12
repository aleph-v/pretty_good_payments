// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IYieldRouter} from "../../src/interfaces/IYieldRouter.sol";

contract MockYieldRouter is IYieldRouter {
    uint256 public depositCount;
    address public lastDepositAsset;
    uint256 public lastDepositAmount;

    function triggerDeposit(address asset, uint256 amount) external override {
        depositCount++;
        lastDepositAsset = asset;
        lastDepositAmount = amount;
    }

    function triggerWithdraw(address, uint256, address) external override {}
    function reportPayoutPercent(address, uint256, uint256) external override {}
}
