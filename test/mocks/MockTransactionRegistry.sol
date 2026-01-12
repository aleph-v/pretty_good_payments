// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ITransactionRegistry} from "../../src/TransactionRegistry.sol";

contract MockTransactionRegistry is ITransactionRegistry {
    function allow(bytes32[5] memory) external override {}

    function query(address, bytes32[5] memory) external pure override returns (bool) {
        return true;
    }
}
