# Quick Start

This guide helps you set up a local development environment for Pretty Good Payments.

## Prerequisites

- **Rust** 1.70+ with cargo
- **Node.js** 18+ with npm
- **Python** 3.9+ with pip
- **Foundry** (forge, anvil, cast)

## Installation

### 1. Clone and Install Dependencies

```bash
git clone https://github.com/your-org/pretty_good_payments.git
cd pretty_good_payments

# Install Foundry dependencies
forge install

# Install Python dependencies (for KZG proofs)
pip install ckzg eth-abi

# Install Circom/snarkjs (for ZK proofs)
npm install -g snarkjs
```

### 2. Build Contracts

```bash
# Build with default profile (for testing)
forge build

# Build with production profile (links external Poseidon libraries)
forge build --profile production
```

### 3. Build Off-Chain Components

```bash
cd offchain
cargo build --release
```

### 4. Run Tests

```bash
# Solidity tests
forge test

# Rust tests
cd offchain && cargo test
```

## Local Development Setup

### Start Local Anvil Node

```bash
anvil --block-time 12
```

### Deploy Contracts

```bash
# Deploy to local anvil
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
```

### Run Sequencer

```bash
cd offchain
cargo run --release --bin sequencer -- \
  --rpc-url http://localhost:8545 \
  --entrypoint-address <DEPLOYED_ADDRESS> \
  --private-key <SEQUENCER_PRIVATE_KEY>
```

### Run Challenger

```bash
cd offchain
cargo run --release --bin challenger -- \
  --rpc-url http://localhost:8545 \
  --beacon-url http://localhost:5052 \
  --entrypoint-address <DEPLOYED_ADDRESS> \
  --database-path ./challenger.db
```

## Project Structure Overview

```
src/
  Entrypoint.sol          # Main contract, combines all functionality
  Spine.sol               # Block storage and validation
  Deposits.sol            # Deposit handling
  Withdraw.sol            # Withdrawal processing
  SequencerRegistry.sol   # Sequencer management
  YieldRouter.sol         # Yield distribution
  *Challenge.sol          # Fraud proof contracts
  library/
    BlobData.sol          # KZG proof validation
    PredictableMerkleLib.sol  # Merkle tree operations

offchain/crates/
  sequencer/              # Sequencer implementation
  challenger/             # Challenger implementation
  common/                 # Shared types
  merkle/                 # Merkle tree library
```

## Next Steps

- [Architecture Overview](architecture/overview.md) - Understand the system design
- [User Guide](guides/user-guide.md) - Learn the user flow
- [Sequencer Guide](guides/sequencer.md) - Run a production sequencer
