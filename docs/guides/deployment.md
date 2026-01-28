# Deployment Guide

This guide covers deploying PGP contracts to Ethereum mainnet or testnets.

## Prerequisites

### Software

- Foundry (forge, cast, anvil)
- Node.js 18+
- Python 3.9+

### Accounts

- Deployer account with ETH
- Owner account (can be same as deployer)
- Initial sequencer accounts (optional)

### External Dependencies

**Poseidon Libraries** (deployed deterministically):
- PoseidonT3: `0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93`
- PoseidonT5: `0x555333f3f677Ca3930Bf7c56ffc75144c51D9767`

**ERC4626 Yield Vault** (for production):
- Choose based on your supported tokens
- Must be audited and trusted

## Deployment Steps

### 1. Configure Environment

Create `.env`:

```bash
# Network
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
CHAIN_ID=1

# Accounts
DEPLOYER_PRIVATE_KEY=0x...
OWNER_ADDRESS=0x...

# Configuration
GENESIS_ANCHOR=0x...  # Initial merkle root (usually zero tree root)
REQUIRED_STAKE=...                   # Configurable stake amount in wei
```

### 2. Deploy ZK Verifiers

Deploy the Groth16 verifier contracts:

```bash
# Transfer circuit verifier
forge create src/integrations/TransferVerifier.sol:Groth16Verifier \
  --rpc-url $RPC_URL \
  --private-key $DEPLOYER_PRIVATE_KEY

# Update circuit verifier
forge create src/integrations/UpdateVerifier.sol:Groth16Verifier \
  --rpc-url $RPC_URL \
  --private-key $DEPLOYER_PRIVATE_KEY
```

### 3. Deploy YieldRouter

```bash
forge create src/YieldRouter.sol:YieldRouter \
  --rpc-url $RPC_URL \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --constructor-args \
    $PERIOD_LENGTH \           # Period length in seconds (e.g., 86400 for 1 day)
    $EPOCHS_PER_PERIOD \       # Epochs per period (e.g., 48)
    $ENTRYPOINT_ADDRESS \      # Bridge (deploy entrypoint first, then update)
    "[$USDC_ADDRESS]"          # Tracked tokens
```

### 4. Deploy TransactionRegistry

```bash
forge create src/TransactionRegistry.sol:TransactionRegistry \
  --rpc-url $RPC_URL \
  --private-key $DEPLOYER_PRIVATE_KEY
```

### 5. Deploy Entrypoint

```bash
forge create src/Entrypoint.sol:Entrypoint \
  --rpc-url $RPC_URL \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --libraries lib/poseidon-solidity/contracts/PoseidonT3.sol:PoseidonT3:0x3333... \
  --libraries lib/poseidon-solidity/contracts/PoseidonT5.sol:PoseidonT5:0x5553... \
  --constructor-args \
    $GENESIS_ANCHOR \
    $YIELD_ROUTER_ADDRESS \
    $UPDATE_VERIFIER_ADDRESS \
    $TRANSFER_VERIFIER_ADDRESS \
    $REGISTRY_ADDRESS
```

### 6. Configure YieldRouter

```bash
# Set yield source for each token
cast send $YIELD_ROUTER "changeYieldSource(address,address)" \
  $USDC_ADDRESS $USDC_VAULT \
  --private-key $OWNER_PRIVATE_KEY
```

### 7. Transfer Ownership (Optional)

If deployer != owner:

```bash
# Transfer ownership of Entrypoint
cast send $ENTRYPOINT "transferOwnership(address)" $OWNER_ADDRESS \
  --private-key $DEPLOYER_PRIVATE_KEY

# Transfer ownership of YieldRouter
cast send $YIELD_ROUTER "transferOwnership(address)" $OWNER_ADDRESS \
  --private-key $DEPLOYER_PRIVATE_KEY
```

## Using Production Profile

For deployment with external Poseidon libraries:

```bash
# Build with production profile
forge build --profile production

# Deploy with library linking
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --broadcast \
  --verify \
  --profile production
```

The production profile in `foundry.toml`:

```toml
[profile.production]
libraries = [
    "lib/poseidon-solidity/contracts/PoseidonT3.sol:PoseidonT3:0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93",
    "lib/poseidon-solidity/contracts/PoseidonT5.sol:PoseidonT5:0x555333f3f677Ca3930Bf7c56ffc75144c51D9767"
]
```

## Deployment Script

Create `script/Deploy.s.sol`:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Entrypoint} from "../src/Entrypoint.sol";
import {YieldRouter} from "../src/YieldRouter.sol";
import {TransactionRegistry} from "../src/TransactionRegistry.sol";

contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        // Deploy registry
        TransactionRegistry registry = new TransactionRegistry();

        // Deploy yield router (bridge address updated later)
        // Note: Period length and epochs per period are configurable per network
        YieldRouter yieldRouter = new YieldRouter(
            periodLength,    // Period length in seconds (configurable)
            epochsPerPeriod, // Epochs per period (configurable)
            address(0), // Placeholder for bridge
            new address[](0)
        );

        // Deploy verifiers
        // ... deploy verifier contracts

        // Deploy entrypoint
        bytes32 genesis = keccak256("genesis"); // Or compute zero tree root
        Entrypoint entrypoint = new Entrypoint(
            genesis,
            yieldRouter,
            updateVerifier,
            transferVerifier,
            registry
        );

        // Configure yield router bridge
        // Note: This requires a setter or redeployment

        vm.stopBroadcast();
    }
}
```

Run:

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Verification

### Verify on Etherscan

```bash
forge verify-contract \
  --chain-id 1 \
  --compiler-version v0.8.28 \
  --constructor-args $(cast abi-encode "constructor(bytes32,address,address,address,address)" \
    $GENESIS $YIELD_ROUTER $UPDATE_VERIFIER $TRANSFER_VERIFIER $REGISTRY) \
  $ENTRYPOINT_ADDRESS \
  src/Entrypoint.sol:Entrypoint \
  $ETHERSCAN_API_KEY
```

### Verify Deployment

```bash
# Check genesis anchor
cast call $ENTRYPOINT "GENESIS_ANCHOR()"

# Check verifiers
cast call $ENTRYPOINT "predictableUpdateVerifier()"
cast call $ENTRYPOINT "transactionZkVerifier()"

# Check owner
cast call $ENTRYPOINT "owner()"

# Check required stake
cast call $ENTRYPOINT "requiredStake()"
```

## Testnet Deployment

### Sepolia

```bash
# Use Sepolia RPC
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY

# Deploy Poseidon libraries first (if not already deployed)
# Check https://github.com/chancehudson/poseidon-solidity for addresses

# Deploy with test parameters
REQUIRED_STAKE=1000000000000000000  # 1 ETH for testing
```

### Local (Anvil)

```bash
# Start anvil
anvil --block-time 12

# Deploy in another terminal
RPC_URL=http://localhost:8545
DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Post-Deployment

### Add Priority Sequencers

```bash
cast send $ENTRYPOINT "addFirstLook(address)" $SEQUENCER1 \
  --private-key $OWNER_PRIVATE_KEY

cast send $ENTRYPOINT "addFirstLook(address)" $SEQUENCER2 \
  --private-key $OWNER_PRIVATE_KEY
```

### Configure Yield Sources

```bash
# Add USDC yield source
cast send $YIELD_ROUTER "changeYieldSource(address,address)" \
  $USDC $USDC_VAULT \
  --private-key $OWNER_PRIVATE_KEY

# Set max interest (optional)
cast send $YIELD_ROUTER "setMaxInterest(address,uint256)" \
  $USDC 1000000000 \  # 1000 USDC max per period
  --private-key $OWNER_PRIVATE_KEY
```

### Start Sequencer

```bash
./sequencer --config config.toml
```

### Start Challenger

```bash
./challenger --config config.toml
```

## Upgrades

PGP contracts are **not upgradeable**. For updates:

1. Deploy new contracts
2. Migrate state (off-chain)
3. Redirect users to new deployment
4. Handle pending deposits/withdrawals

### Migration Considerations

- Finalize all pending blocks
- Allow all withdrawals to complete
- Transfer yield vault balances
- Update all off-chain services
