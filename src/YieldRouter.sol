// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import "./YieldSourceRegistry.sol";

// Should implement a version of the hash which matches the hash used in the zk proofs
// Will be inherited by withdraws, deposits, and merkle tree lib

contract YieldRouter is YieldSourceRegistry {
    function triggerDeposit(address asset, uint256 amount) external onlyBridge {
        // Routes based on the asset to a source of yield which implements 4626
    }

    function triggerWithdraw(address asset, uint256 amount, address destination) external onlyBridge {
        // Routes based on the asset to a source of yield which implements 4626
    }
}
