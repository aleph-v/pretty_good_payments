// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IYieldRouter} from "../../src/interfaces/IYieldRouter.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

contract MockYieldRouter is IYieldRouter {
    using SafeERC20 for IERC20;

    uint256 public depositCount;
    address public lastDepositAsset;
    uint256 public lastDepositAmount;

    uint256 public withdrawCount;
    address public lastWithdrawAsset;
    uint256 public lastWithdrawAmount;
    address public lastWithdrawRecipient;

    function triggerDeposit(address asset, uint256 amount) external override {
        depositCount++;
        lastDepositAsset = asset;
        lastDepositAmount = amount;
    }

    function triggerWithdraw(address asset, uint256 amount, address recipient) external override {
        withdrawCount++;
        lastWithdrawAsset = asset;
        lastWithdrawAmount = amount;
        lastWithdrawRecipient = recipient;
        // Transfer tokens to recipient (assumes this contract holds the tokens)
        IERC20(asset).safeTransfer(recipient, amount);
    }

    function reportPayoutPercent(address, uint256, uint256) external override {}
}
