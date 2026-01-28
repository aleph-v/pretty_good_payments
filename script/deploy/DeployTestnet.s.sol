// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Entrypoint} from "../../src/Entrypoint.sol";
import {YieldRouter} from "../../src/YieldRouter.sol";
import {TransactionRegistry, ITransactionRegistry} from "../../src/TransactionRegistry.sol";
import {IYieldRouter} from "../../src/interfaces/IYieldRouter.sol";
import {IUpdateVerifier} from "../../src/interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "../../src/interfaces/ITransferVerifier.sol";
import {ZeroTree} from "../../src/library/ZeroTree.sol";
import {FakeZK} from "../../test/mocks/FakeZk.sol";
import {TestnetERC20} from "../../test/mocks/TestnetERC20.sol";
import {TestnetERC4626} from "../../test/mocks/TestnetERC4626.sol";

/// @title DeployTestnet
/// @notice Testnet deployment with real YieldRouter and mock tokens/vaults
/// @dev Uses nonce prediction to solve the circular dependency between Entrypoint and YieldRouter:
///      - YieldRouter needs Entrypoint address (as bridge)
///      - Entrypoint needs YieldRouter address
///      Solution: Predict addresses based on deployer nonce, deploy in correct order
///
/// Usage:
///   forge script script/deploy/DeployTestnet.s.sol:DeployTestnet \
///     --rpc-url <RPC_URL> \
///     --private-key <PRIVATE_KEY> \
///     --broadcast
contract DeployTestnet is Script {
    // Period length: 1 day in seconds
    uint256 constant PERIOD_LENGTH = 86400;

    // EPOCH_LENGTH from SequencerRegistry = 1800 seconds (30 minutes)
    // This must match the constant in SequencerRegistry.sol
    uint256 constant EPOCH_LENGTH = 1800;

    /// @notice Computes epochs per period from constants
    /// @dev epochsPerPeriod = PERIOD_LENGTH / EPOCH_LENGTH = 86400 / 1800 = 48
    function getEpochsPerPeriod() internal pure returns (uint256) {
        return PERIOD_LENGTH / EPOCH_LENGTH;
    }

    /// @notice Main deployment function
    function run() external {
        // Get deployer from environment or CLI
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("=== Testnet Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("");
        console.log("=== Configuration ===");
        console.log("Period Length:", PERIOD_LENGTH, "seconds (1 day)");
        console.log("Epoch Length:", EPOCH_LENGTH, "seconds (30 minutes)");
        console.log("Epochs Per Period:", getEpochsPerPeriod());
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy testnet token (owner-restricted mint/burn)
        //    Deployer retains ownership to mint tokens for users and simulate yield
        TestnetERC20 token = new TestnetERC20("PGP Testnet Token", "tPGP");
        console.log("Token (TestnetERC20):", address(token));

        // 2. Deploy testnet vault
        TestnetERC4626 vault = new TestnetERC4626(token, "PGP Testnet Vault", "vtPGP");
        console.log("Vault (TestnetERC4626):", address(vault));

        // 3. Deploy verifiers (FakeZK for testnet)
        FakeZK transferVerifier = new FakeZK();
        console.log("Transfer Verifier:", address(transferVerifier));

        FakeZK updateVerifier = new FakeZK();
        console.log("Update Verifier:", address(updateVerifier));

        // 4. Deploy transaction registry
        TransactionRegistry registry = new TransactionRegistry();
        console.log("Transaction Registry:", address(registry));

        // 5. Prepare tracked tokens array for YieldRouter
        address[] memory trackedTokens = new address[](1);
        trackedTokens[0] = address(token);

        // 6. Predict addresses for Entrypoint and YieldRouter
        //    Current nonce will deploy Entrypoint, next nonce will deploy YieldRouter
        uint64 currentNonce = vm.getNonce(deployer);
        address predictedEntrypoint = vm.computeCreateAddress(deployer, currentNonce);
        address predictedYieldRouter = vm.computeCreateAddress(deployer, currentNonce + 1);

        console.log("");
        console.log("=== Address Prediction ===");
        console.log("Deployer nonce:", currentNonce);
        console.log("Predicted Entrypoint:", predictedEntrypoint);
        console.log("Predicted YieldRouter:", predictedYieldRouter);

        // 7. Deploy Entrypoint with predicted YieldRouter address
        bytes32 genesis = ZeroTree.computeZeroTreeRoot();
        Entrypoint entrypoint = new Entrypoint(
            genesis,
            IYieldRouter(predictedYieldRouter),
            IUpdateVerifier(address(updateVerifier)),
            ITransferVerifier(address(transferVerifier)),
            ITransactionRegistry(address(registry))
        );
        require(address(entrypoint) == predictedEntrypoint, "Entrypoint address mismatch - check nonce");

        console.log("");
        console.log("Entrypoint deployed:", address(entrypoint));
        console.log("Genesis Anchor:", vm.toString(genesis));

        // 8. Deploy YieldRouter with Entrypoint as bridge
        YieldRouter yieldRouter =
            new YieldRouter(PERIOD_LENGTH, getEpochsPerPeriod(), address(entrypoint), trackedTokens);
        require(address(yieldRouter) == predictedYieldRouter, "YieldRouter address mismatch - check nonce");

        console.log("YieldRouter deployed:", address(yieldRouter));

        // 9. Configure YieldRouter - set vault as yield source for token
        yieldRouter.changeYieldSource(address(token), vault);
        console.log("YieldRouter configured: token ->", address(vault));

        vm.stopBroadcast();

        // Output summary
        console.log("");
        console.log("=== Deployment Complete ===");
        console.log("Entrypoint:           ", address(entrypoint));
        console.log("YieldRouter:          ", address(yieldRouter));
        console.log("Transaction Registry: ", address(registry));
        console.log("Transfer Verifier:    ", address(transferVerifier));
        console.log("Update Verifier:      ", address(updateVerifier));
        console.log("Token (TestnetERC20): ", address(token));
        console.log("Vault (TestnetERC4626):", address(vault));

        console.log("");
        console.log("=== Token Info ===");
        console.log("Token owner (can mint/burn):", deployer);
        console.log("To mint tokens: token.mint(recipient, amount)");
        console.log("To simulate yield: token.mint(vault, amount)");

        // Generate and write config files
        string memory rpcUrl = vm.envOr("RPC_URL", string("http://localhost:8545"));

        _writeConfigFiles(
            address(entrypoint), address(yieldRouter), address(registry), address(token), rpcUrl, block.chainid
        );

        console.log("");
        console.log("=== Config File Written ===");
        console.log("config/config.toml (unified config for sequencer and challenger)");

        // Write verification script
        _writeVerificationScript(
            address(token),
            address(vault),
            address(transferVerifier),
            address(updateVerifier),
            address(registry),
            address(entrypoint),
            address(yieldRouter),
            genesis,
            block.chainid
        );

        console.log("");
        console.log("=== Verification Script Written ===");
        console.log("Run: chmod +x verify-contracts.sh && ./verify-contracts.sh");

        // Also output verification commands to console for manual use
        _logVerificationCommands(
            address(token),
            address(vault),
            address(transferVerifier),
            address(updateVerifier),
            address(registry),
            address(entrypoint),
            address(yieldRouter),
            genesis,
            block.chainid
        );
    }

    // ==================== Config File Generation ====================

    function _writeConfigFiles(
        address entrypoint,
        address,
        /* yieldRouter */
        address registry,
        address,
        /* token */
        string memory rpcUrl,
        uint256 chainId
    ) internal {
        // Ensure config directory exists
        vm.createDir("config", true);

        // Generate and write unified config
        string memory config = _generateUnifiedConfig(entrypoint, registry, rpcUrl, chainId);
        vm.writeFile("config/config.toml", config);
    }

    function _generateUnifiedConfig(address entrypoint, address registry, string memory rpcUrl, uint256 chainId)
        internal
        view
        returns (string memory)
    {
        return string.concat(
            _configHeader(chainId),
            _networkSection(rpcUrl, chainId),
            _contractsSection(entrypoint, registry),
            _keysSection(),
            _sequencerSection(),
            _challengerSection(),
            _circuitsSection(),
            _storageSection()
        );
    }

    function _configHeader(uint256 chainId) internal view returns (string memory) {
        return string.concat(
            "# Pretty Good Payments - Unified Configuration\n",
            "# Auto-generated by DeployTestnet.s.sol\n",
            "# Chain ID: ",
            vm.toString(chainId),
            "\n",
            "# Generated at block: ",
            vm.toString(block.number),
            "\n",
            "#\n",
            "# This single config file works for both the sequencer and challenger binaries.\n",
            "# Environment variables can override any setting (e.g., PGP_RPC_URL, PGP_CHAIN_ID)\n",
            "# Private keys should use environment variables in production:\n",
            "#   PGP_SEQUENCER_PRIVATE_KEY, PGP_CHALLENGER_PRIVATE_KEY\n\n"
        );
    }

    function _networkSection(string memory rpcUrl, uint256 chainId) internal pure returns (string memory) {
        return string.concat(
            "[network]\n",
            "rpc_url = \"",
            rpcUrl,
            "\"\n",
            "beacon_url = \"http://localhost:5052\"\n",
            "chain_id = ",
            vm.toString(chainId),
            "\n\n"
        );
    }

    function _contractsSection(address entrypoint, address registry) internal pure returns (string memory) {
        return string.concat(
            "[contracts]\n",
            "entrypoint = \"",
            vm.toString(entrypoint),
            "\"\n",
            "deposits = \"",
            vm.toString(entrypoint),
            "\"\n", // Same contract for now
            "transaction_registry = \"",
            vm.toString(registry),
            "\"\n\n"
        );
    }

    function _keysSection() internal pure returns (string memory) {
        return string.concat(
            "[keys]\n",
            "# Separate private keys allow different ETH balances for sequencer vs challenger\n",
            "# SECURITY: Use environment variables in production!\n",
            "#   export PGP_SEQUENCER_PRIVATE_KEY=\"0x...\"\n",
            "#   export PGP_CHALLENGER_PRIVATE_KEY=\"0x...\"\n",
            "# sequencer_private_key = \"${SEQUENCER_PRIVATE_KEY}\"\n",
            "# challenger_private_key = \"${CHALLENGER_PRIVATE_KEY}\"\n\n"
        );
    }

    function _sequencerSection() internal pure returns (string memory) {
        return string.concat(
            "[sequencer]\n",
            "api_host = \"127.0.0.1\"\n",
            "api_port = 8080\n",
            "block_interval_ms = 12000\n",
            "mempool_max_pending = 10000\n\n"
        );
    }

    function _challengerSection() internal pure returns (string memory) {
        return string.concat(
            "[challenger]\n",
            "poll_interval_ms = 2000\n",
            "confirmations = 6\n",
            "lookback_blocks = 1000\n",
            "dry_run = false\n",
            "max_challenge_retries = 5\n\n"
        );
    }

    function _circuitsSection() internal pure returns (string memory) {
        return string.concat(
            "[circuits]\n",
            "transfer_verification_key = \"circuits/outputs/transfer/transferVKey.json\"\n",
            "update_verification_key = \"circuits/outputs/predictableUpdate/predictableUpdateVKey.json\"\n",
            "snarkjs_path = \"snarkjs\"\n",
            "circuit_wasm_path = \"circuits/outputs/predictableUpdate/predictableUpdate_js/predictableUpdate.wasm\"\n",
            "circuit_zkey_path = \"circuits/outputs/predictableUpdate/predictableUpdate.zkey\"\n\n"
        );
    }

    function _storageSection() internal pure returns (string memory) {
        return string.concat(
            "[storage]\n",
            "# Shared database for both sequencer and challenger\n",
            "database_path = \"./data/pgp.db\"\n",
            "blob_cache_size = 16\n"
        );
    }

    // ==================== Etherscan Verification ====================

    function _writeVerificationScript(
        address token,
        address vault,
        address transferVerifier,
        address updateVerifier,
        address registry,
        address entrypoint,
        address yieldRouter,
        bytes32 genesis,
        uint256 chainId
    ) internal {
        string memory script = string.concat(
            "#!/bin/bash\n",
            "# Etherscan Contract Verification Script\n",
            "# Auto-generated by DeployTestnet.s.sol\n",
            "# Chain ID: ",
            vm.toString(chainId),
            "\n",
            "#\n",
            "# Prerequisites:\n",
            "#   export ETHERSCAN_API_KEY=your_api_key\n",
            "#\n",
            "# For testnets, you may need to specify the verifier URL:\n",
            "#   --verifier-url https://api-sepolia.etherscan.io/api\n",
            "#\n",
            "set -e\n\n",
            "if [ -z \"$ETHERSCAN_API_KEY\" ]; then\n",
            "  echo \"Error: ETHERSCAN_API_KEY not set\"\n",
            "  exit 1\n",
            "fi\n\n",
            "CHAIN_ID=",
            vm.toString(chainId),
            "\n\n"
        );

        // TestnetERC20: constructor(string name, string symbol)
        script = string.concat(
            script,
            "echo \"Verifying TestnetERC20...\"\n",
            "forge verify-contract \\\n",
            "  ",
            vm.toString(token),
            " \\\n",
            "  test/mocks/TestnetERC20.sol:TestnetERC20 \\\n",
            "  --chain-id $CHAIN_ID \\\n",
            "  --constructor-args $(cast abi-encode \"constructor(string,string)\" \"PGP Testnet Token\" \"tPGP\") \\\n",
            "  --etherscan-api-key $ETHERSCAN_API_KEY \\\n",
            "  --watch\n\n"
        );

        // TestnetERC4626: constructor(IERC20 asset, string name, string symbol)
        script = string.concat(
            script,
            "echo \"Verifying TestnetERC4626...\"\n",
            "forge verify-contract \\\n",
            "  ",
            vm.toString(vault),
            " \\\n",
            "  test/mocks/TestnetERC4626.sol:TestnetERC4626 \\\n",
            "  --chain-id $CHAIN_ID \\\n",
            "  --constructor-args $(cast abi-encode \"constructor(address,string,string)\" ",
            vm.toString(token),
            " \"PGP Testnet Vault\" \"vtPGP\") \\\n",
            "  --etherscan-api-key $ETHERSCAN_API_KEY \\\n",
            "  --watch\n\n"
        );

        // FakeZK (transferVerifier): no constructor args
        script = string.concat(
            script,
            "echo \"Verifying FakeZK (Transfer Verifier)...\"\n",
            "forge verify-contract \\\n",
            "  ",
            vm.toString(transferVerifier),
            " \\\n",
            "  test/mocks/FakeZk.sol:FakeZK \\\n",
            "  --chain-id $CHAIN_ID \\\n",
            "  --etherscan-api-key $ETHERSCAN_API_KEY \\\n",
            "  --watch\n\n"
        );

        // FakeZK (updateVerifier): no constructor args
        script = string.concat(
            script,
            "echo \"Verifying FakeZK (Update Verifier)...\"\n",
            "forge verify-contract \\\n",
            "  ",
            vm.toString(updateVerifier),
            " \\\n",
            "  test/mocks/FakeZk.sol:FakeZK \\\n",
            "  --chain-id $CHAIN_ID \\\n",
            "  --etherscan-api-key $ETHERSCAN_API_KEY \\\n",
            "  --watch\n\n"
        );

        // TransactionRegistry: no constructor args
        script = string.concat(
            script,
            "echo \"Verifying TransactionRegistry...\"\n",
            "forge verify-contract \\\n",
            "  ",
            vm.toString(registry),
            " \\\n",
            "  src/TransactionRegistry.sol:TransactionRegistry \\\n",
            "  --chain-id $CHAIN_ID \\\n",
            "  --etherscan-api-key $ETHERSCAN_API_KEY \\\n",
            "  --watch\n\n"
        );

        // Entrypoint: constructor(bytes32, IYieldRouter, IUpdateVerifier, ITransferVerifier, ITransactionRegistry)
        script = string.concat(
            script,
            "echo \"Verifying Entrypoint...\"\n",
            "forge verify-contract \\\n",
            "  ",
            vm.toString(entrypoint),
            " \\\n",
            "  src/Entrypoint.sol:Entrypoint \\\n",
            "  --chain-id $CHAIN_ID \\\n",
            "  --constructor-args $(cast abi-encode \"constructor(bytes32,address,address,address,address)\" ",
            vm.toString(genesis),
            " ",
            vm.toString(yieldRouter),
            " ",
            vm.toString(updateVerifier),
            " ",
            vm.toString(transferVerifier),
            " ",
            vm.toString(registry),
            ") \\\n",
            "  --etherscan-api-key $ETHERSCAN_API_KEY \\\n",
            "  --watch\n\n"
        );

        // YieldRouter: constructor(uint256 periodLength, uint256 epochsPerPeriod, address bridge, address[] trackedTokens)
        script = string.concat(
            script,
            "echo \"Verifying YieldRouter...\"\n",
            "forge verify-contract \\\n",
            "  ",
            vm.toString(yieldRouter),
            " \\\n",
            "  src/YieldRouter.sol:YieldRouter \\\n",
            "  --chain-id $CHAIN_ID \\\n",
            "  --constructor-args $(cast abi-encode \"constructor(uint256,uint256,address,address[])\" ",
            vm.toString(PERIOD_LENGTH),
            " ",
            vm.toString(getEpochsPerPeriod()),
            " ",
            vm.toString(entrypoint),
            " ",
            "\"[",
            vm.toString(token),
            "]\") \\\n",
            "  --etherscan-api-key $ETHERSCAN_API_KEY \\\n",
            "  --watch\n\n"
        );

        script = string.concat(script, "echo \"\"\n", "echo \"All contracts verified successfully!\"\n");

        vm.writeFile("verify-contracts.sh", script);
    }

    function _logVerificationCommands(
        address token,
        address vault,
        address transferVerifier,
        address updateVerifier,
        address registry,
        address entrypoint,
        address yieldRouter,
        bytes32 genesis,
        uint256 chainId
    ) internal pure {
        string memory cid = vm.toString(chainId);

        console.log("");
        console.log("=== Etherscan Verification Commands ===");
        console.log("Set ETHERSCAN_API_KEY before running these commands.");
        console.log("For testnets, add: --verifier-url https://api-<network>.etherscan.io/api");
        console.log("");

        console.log("# 1. TestnetERC20");
        console.log(
            string.concat(
                "forge verify-contract ",
                vm.toString(token),
                " test/mocks/TestnetERC20.sol:TestnetERC20 --chain-id ",
                cid,
                " --constructor-args $(cast abi-encode 'constructor(string,string)' 'PGP Testnet Token' 'tPGP')",
                " --etherscan-api-key $ETHERSCAN_API_KEY"
            )
        );

        console.log("");
        console.log("# 2. TestnetERC4626");
        console.log(
            string.concat(
                "forge verify-contract ",
                vm.toString(vault),
                " test/mocks/TestnetERC4626.sol:TestnetERC4626 --chain-id ",
                cid,
                " --constructor-args $(cast abi-encode 'constructor(address,string,string)' ",
                vm.toString(token),
                " 'PGP Testnet Vault' 'vtPGP')",
                " --etherscan-api-key $ETHERSCAN_API_KEY"
            )
        );

        console.log("");
        console.log("# 3. FakeZK (Transfer Verifier)");
        console.log(
            string.concat(
                "forge verify-contract ",
                vm.toString(transferVerifier),
                " test/mocks/FakeZk.sol:FakeZK --chain-id ",
                cid,
                " --etherscan-api-key $ETHERSCAN_API_KEY"
            )
        );

        console.log("");
        console.log("# 4. FakeZK (Update Verifier)");
        console.log(
            string.concat(
                "forge verify-contract ",
                vm.toString(updateVerifier),
                " test/mocks/FakeZk.sol:FakeZK --chain-id ",
                cid,
                " --etherscan-api-key $ETHERSCAN_API_KEY"
            )
        );

        console.log("");
        console.log("# 5. TransactionRegistry");
        console.log(
            string.concat(
                "forge verify-contract ",
                vm.toString(registry),
                " src/TransactionRegistry.sol:TransactionRegistry --chain-id ",
                cid,
                " --etherscan-api-key $ETHERSCAN_API_KEY"
            )
        );

        console.log("");
        console.log("# 6. Entrypoint");
        console.log(
            string.concat(
                "forge verify-contract ",
                vm.toString(entrypoint),
                " src/Entrypoint.sol:Entrypoint --chain-id ",
                cid,
                " --constructor-args $(cast abi-encode 'constructor(bytes32,address,address,address,address)' ",
                vm.toString(genesis),
                " ",
                vm.toString(yieldRouter),
                " ",
                vm.toString(updateVerifier),
                " ",
                vm.toString(transferVerifier),
                " ",
                vm.toString(registry),
                ")",
                " --etherscan-api-key $ETHERSCAN_API_KEY"
            )
        );

        console.log("");
        console.log("# 7. YieldRouter");
        console.log(
            string.concat(
                "forge verify-contract ",
                vm.toString(yieldRouter),
                " src/YieldRouter.sol:YieldRouter --chain-id ",
                cid,
                " --constructor-args $(cast abi-encode 'constructor(uint256,uint256,address,address[])' ",
                vm.toString(PERIOD_LENGTH),
                " ",
                vm.toString(getEpochsPerPeriod()),
                " ",
                vm.toString(entrypoint),
                " '[",
                vm.toString(token),
                "]')",
                " --etherscan-api-key $ETHERSCAN_API_KEY"
            )
        );
    }
}
