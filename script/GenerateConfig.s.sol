// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";

/// @title GenerateConfig
/// @notice Generates unified TOML configuration file for both challenger and sequencer binaries
/// @dev Run after deployment to create config file with correct contract addresses
contract GenerateConfig is Script {
    function run() external {
        // Read deployed addresses from environment
        address entrypoint = vm.envAddress("ENTRYPOINT_ADDRESS");
        address deposits = vm.envOr("DEPOSITS_ADDRESS", entrypoint); // Default to entrypoint if not set
        address registry = vm.envOr("TRANSACTION_REGISTRY_ADDRESS", address(0));
        string memory rpcUrl = vm.envOr("RPC_URL", string("http://localhost:8545"));
        uint256 chainId = block.chainid;

        // Generate unified config file
        string memory config = generateUnifiedConfig(entrypoint, deposits, registry, rpcUrl, chainId);

        // Ensure config directory exists
        vm.createDir("config", true);

        // Write unified config file
        vm.writeFile("config/config.toml", config);
        console.log("Written: config/config.toml");
    }

    function generateUnifiedConfig(
        address entrypoint,
        address deposits,
        address registry,
        string memory rpcUrl,
        uint256 chainId
    ) internal view returns (string memory) {
        return string.concat(
            _header(chainId),
            _networkSection(rpcUrl, chainId),
            _contractsSection(entrypoint, deposits, registry),
            _keysSection(),
            _sequencerSection(),
            _challengerSection(),
            _circuitsSection(),
            _storageSection()
        );
    }

    function _header(uint256 chainId) internal view returns (string memory) {
        return string.concat(
            "# Pretty Good Payments - Unified Configuration\n",
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

    function _contractsSection(address entrypoint, address deposits, address registry)
        internal
        pure
        returns (string memory)
    {
        string memory registryLine = registry != address(0)
            ? string.concat("transaction_registry = \"", vm.toString(registry), "\"\n")
            : "# transaction_registry = \"0x...\"\n";

        return string.concat(
            "[contracts]\n",
            "entrypoint = \"",
            vm.toString(entrypoint),
            "\"\n",
            "deposits = \"",
            vm.toString(deposits),
            "\"\n",
            registryLine,
            "\n"
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
}
