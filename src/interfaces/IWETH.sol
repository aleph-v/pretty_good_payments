// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256) external;
}
