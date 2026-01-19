// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Entrypoint} from "../../src/Entrypoint.sol";
import {TransactionRegistry, ITransactionRegistry} from "../../src/TransactionRegistry.sol";
import {IYieldRouter} from "../../src/interfaces/IYieldRouter.sol";
import {IUpdateVerifier} from "../../src/interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "../../src/interfaces/ITransferVerifier.sol";
import {ZeroTree} from "../../src/library/ZeroTree.sol";

/// @title Deploy
/// @notice Base deployment script for Pretty Good Payments
/// @dev Inherit and implement abstract functions for different deployment targets
abstract contract Deploy is Script {
    /// @notice Struct containing all deployed contract addresses
    struct DeployedAddresses {
        address entrypoint;
        address yieldRouter;
        address transactionRegistry;
        address transferVerifier;
        address updateVerifier;
        address token;
    }

    /// @notice The genesis anchor (initial merkle root)
    /// @dev Override in child contracts for different genesis values
    function getGenesisAnchor() internal virtual returns (bytes32) {
        // Compute the root of an empty merkle tree (all zero leaves)
        return ZeroTree.computeZeroTreeRoot();
    }

    /// @notice Deploy the transfer ZK verifier
    /// @dev Override to deploy mock or real verifier
    function deployTransferVerifier() internal virtual returns (address);

    /// @notice Deploy the merkle update ZK verifier
    /// @dev Override to deploy mock or real verifier
    function deployUpdateVerifier() internal virtual returns (address);

    /// @notice Deploy or return the yield router address
    /// @dev Override to deploy mock or real yield router
    /// @param entrypoint The entrypoint address (for real YieldRouter that needs bridge reference)
    function deployYieldRouter(address entrypoint) internal virtual returns (address);

    /// @notice Deploy or return the token address for testing
    /// @dev Override to deploy mock token or return real token address
    function getTokenAddress() internal virtual returns (address);

    /// @notice Main deployment function
    /// @return deployed Struct containing all deployed addresses
    function run() external returns (DeployedAddresses memory deployed) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy verifiers
        deployed.transferVerifier = deployTransferVerifier();
        console.log("Transfer Verifier:", deployed.transferVerifier);

        deployed.updateVerifier = deployUpdateVerifier();
        console.log("Update Verifier:", deployed.updateVerifier);

        // 2. Deploy transaction registry
        TransactionRegistry registry = new TransactionRegistry();
        deployed.transactionRegistry = address(registry);
        console.log("Transaction Registry:", deployed.transactionRegistry);

        // 3. Deploy yield router (may need entrypoint address, so we pass address(0) for now)
        // For MockYieldRouter this is fine; for real YieldRouter we'd need CREATE2
        deployed.yieldRouter = deployYieldRouter(address(0));
        console.log("Yield Router:", deployed.yieldRouter);

        // 4. Deploy entrypoint
        bytes32 genesis = getGenesisAnchor();
        Entrypoint entrypoint = new Entrypoint(
            genesis,
            IYieldRouter(deployed.yieldRouter),
            IUpdateVerifier(deployed.updateVerifier),
            ITransferVerifier(deployed.transferVerifier),
            ITransactionRegistry(deployed.transactionRegistry)
        );
        deployed.entrypoint = address(entrypoint);
        console.log("Entrypoint:", deployed.entrypoint);
        console.log("Genesis Anchor:", vm.toString(genesis));

        // 5. Get/deploy token
        deployed.token = getTokenAddress();
        console.log("Token:", deployed.token);

        vm.stopBroadcast();

        // Output summary
        console.log("\n=== Deployment Summary ===");
        console.log("Entrypoint:           ", deployed.entrypoint);
        console.log("Yield Router:         ", deployed.yieldRouter);
        console.log("Transaction Registry: ", deployed.transactionRegistry);
        console.log("Transfer Verifier:    ", deployed.transferVerifier);
        console.log("Update Verifier:      ", deployed.updateVerifier);
        console.log("Token:                ", deployed.token);

        return deployed;
    }
}
