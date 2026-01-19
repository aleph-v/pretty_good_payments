// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

/// @title GenerateConfig
/// @notice Generates TOML configuration files for challenger and sequencer binaries
/// @dev Run after deployment to create config files with correct contract addresses
contract GenerateConfig is Script {
    function run() external {
        // Read deployed addresses from environment
        address entrypoint = vm.envAddress("ENTRYPOINT_ADDRESS");
        address yieldRouter = vm.envAddress("YIELD_ROUTER_ADDRESS");
        address registry = vm.envAddress("TRANSACTION_REGISTRY_ADDRESS");
        address token = vm.envAddress("TOKEN_ADDRESS");
        string memory rpcUrl = vm.envOr("RPC_URL", string("http://localhost:8545"));
        uint256 chainId = block.chainid;

        // Generate both config files
        string memory challengerConfig = generateChallengerConfig(entrypoint, registry, rpcUrl, chainId);
        string memory sequencerConfig =
            generateSequencerConfig(entrypoint, yieldRouter, registry, token, rpcUrl, chainId);

        // Ensure config directory exists
        vm.createDir("config", true);

        // Write config files
        vm.writeFile("config/challenger.toml", challengerConfig);
        console.log("Written: config/challenger.toml");

        vm.writeFile("config/sequencer.toml", sequencerConfig);
        console.log("Written: config/sequencer.toml");

        // Also write a combined base config
        string memory baseConfig = generateBaseConfig(entrypoint, yieldRouter, registry, token, rpcUrl, chainId);
        vm.writeFile("config.toml", baseConfig);
        console.log("Written: config.toml (base config)");
    }

    function generateBaseConfig(
        address entrypoint,
        address yieldRouter,
        address registry,
        address token,
        string memory rpcUrl,
        uint256 chainId
    ) internal view returns (string memory) {
        return string.concat(
            "# Auto-generated Pretty Good Payments configuration\n",
            "# Chain ID: ",
            vm.toString(chainId),
            "\n",
            "# Generated at block: ",
            vm.toString(block.number),
            "\n\n",
            "[network]\n",
            "rpc_url = \"",
            rpcUrl,
            "\"\n",
            "chain_id = ",
            vm.toString(chainId),
            "\n\n",
            "[contracts]\n",
            "entrypoint = \"",
            vm.toString(entrypoint),
            "\"\n",
            "yield_router = \"",
            vm.toString(yieldRouter),
            "\"\n",
            "transaction_registry = \"",
            vm.toString(registry),
            "\"\n",
            "token = \"",
            vm.toString(token),
            "\"\n"
        );
    }

    function generateChallengerConfig(address entrypoint, address registry, string memory rpcUrl, uint256 chainId)
        internal
        view
        returns (string memory)
    {
        return string.concat(
            _challengerHeader(rpcUrl, chainId), _challengerContracts(entrypoint, registry), _challengerSettings()
        );
    }

    function _challengerHeader(string memory rpcUrl, uint256 chainId) internal view returns (string memory) {
        return string.concat(
            "# Pretty Good Payments - Challenger Configuration\n",
            "# Chain ID: ",
            vm.toString(chainId),
            "\n",
            "# Generated at block: ",
            vm.toString(block.number),
            "\n\n",
            "[network]\n",
            "rpc_url = \"",
            rpcUrl,
            "\"\n",
            "# beacon_url = \"http://localhost:5052\"\n",
            "chain_id = ",
            vm.toString(chainId),
            "\n\n"
        );
    }

    function _challengerContracts(address entrypoint, address registry) internal view returns (string memory) {
        return string.concat(
            "[contracts]\n",
            "entrypoint = \"",
            vm.toString(entrypoint),
            "\"\n",
            "transaction_registry = \"",
            vm.toString(registry),
            "\"\n\n"
        );
    }

    function _challengerSettings() internal pure returns (string memory) {
        return string.concat(
            "[challenger]\n",
            "private_key = \"${CHALLENGER_PRIVATE_KEY}\"\n",
            "poll_interval_ms = 2000\n",
            "lookback_blocks = 100\n",
            "max_gas_price_gwei = 100\n",
            "challenge_gas_limit = 500000\n\n",
            "[challenger.validators]\n",
            "transaction_zk = true\n",
            "deposit = true\n",
            "nullifier = true\n",
            "tree_update = true\n\n",
            "[storage]\n",
            "db_path = \"./data/challenger.db\"\n\n",
            "[logging]\n",
            "level = \"info\"\n",
            "format = \"pretty\"\n\n",
            "[metrics]\n",
            "enabled = false\n"
        );
    }

    function generateSequencerConfig(
        address entrypoint,
        address yieldRouter,
        address registry,
        address token,
        string memory rpcUrl,
        uint256 chainId
    ) internal view returns (string memory) {
        return string.concat(
            _sequencerHeader(rpcUrl, chainId),
            _sequencerContracts(entrypoint, yieldRouter, registry, token),
            _sequencerSettings()
        );
    }

    function _sequencerHeader(string memory rpcUrl, uint256 chainId) internal view returns (string memory) {
        return string.concat(
            "# Pretty Good Payments - Sequencer Configuration\n",
            "# Chain ID: ",
            vm.toString(chainId),
            "\n",
            "# Generated at block: ",
            vm.toString(block.number),
            "\n\n",
            "[network]\n",
            "rpc_url = \"",
            rpcUrl,
            "\"\n",
            "# beacon_url = \"http://localhost:5052\"\n",
            "chain_id = ",
            vm.toString(chainId),
            "\n\n"
        );
    }

    function _sequencerContracts(address entrypoint, address yieldRouter, address registry, address token)
        internal
        view
        returns (string memory)
    {
        return string.concat(
            "[contracts]\n",
            "entrypoint = \"",
            vm.toString(entrypoint),
            "\"\n",
            "yield_router = \"",
            vm.toString(yieldRouter),
            "\"\n",
            "transaction_registry = \"",
            vm.toString(registry),
            "\"\n",
            "token = \"",
            vm.toString(token),
            "\"\n\n"
        );
    }

    function _sequencerSettings() internal pure returns (string memory) {
        return string.concat(
            "[sequencer]\n",
            "private_key = \"${SEQUENCER_PRIVATE_KEY}\"\n",
            "max_transactions_per_block = 4096\n",
            "max_deposits_per_block = 3072\n",
            "max_blobs_per_block = 6\n",
            "block_time_ms = 12000\n",
            "epoch_wait_ms = 5000\n",
            "max_gas_price_gwei = 100\n",
            "max_blob_gas_price_gwei = 50\n\n",
            "[api]\n",
            "enabled = true\n",
            "host = \"0.0.0.0\"\n",
            "port = 8080\n",
            "max_requests_per_second = 100\n",
            "max_pending_transactions = 10000\n\n",
            "[mempool]\n",
            "max_size = 50000\n",
            "eviction_policy = \"fifo\"\n\n",
            "[storage]\n",
            "db_path = \"./data/sequencer.db\"\n\n",
            "[logging]\n",
            "level = \"info\"\n",
            "format = \"pretty\"\n\n",
            "[metrics]\n",
            "enabled = false\n"
        );
    }
}
