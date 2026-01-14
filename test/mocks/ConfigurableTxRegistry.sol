// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ITransactionRegistry} from "../../src/TransactionRegistry.sol";

/// @notice Configurable mock for testing TransactionChallenge
/// @dev Allows setting specific query results for testing different fraud scenarios
contract ConfigurableTxRegistry is ITransactionRegistry {
    // Default return value for queries
    bool public defaultReturn = true;

    // Specific overrides for address + fields combinations
    mapping(bytes32 => bool) public overrides;
    mapping(bytes32 => bool) public hasOverride;

    function allow(bytes32[5] memory) external override {}

    function query(address sender, bytes32[5] memory fields) external view override returns (bool) {
        bytes32 key = keccak256(abi.encodePacked(sender, fields));
        if (hasOverride[key]) {
            return overrides[key];
        }
        return defaultReturn;
    }

    /// @notice Set the default return value for all queries
    function setDefaultReturn(bool value) external {
        defaultReturn = value;
    }

    /// @notice Set a specific return value for a sender + fields combination
    function setQueryResult(address sender, bytes32[5] memory fields, bool result) external {
        bytes32 key = keccak256(abi.encodePacked(sender, fields));
        overrides[key] = result;
        hasOverride[key] = true;
    }

    /// @notice Clear an override so it falls back to default
    function clearOverride(address sender, bytes32[5] memory fields) external {
        bytes32 key = keccak256(abi.encodePacked(sender, fields));
        hasOverride[key] = false;
    }
}
