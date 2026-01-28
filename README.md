# Pretty Good Payments

**Private, free stablecoin transactions at scale on Ethereum**

Pretty Good Payments (PGP) is a Layer 2 payment system that enables private transactions for ERC-20 tokens, settling to Ethereum mainnet. The system uses a simplified version of the Zcash private e-cash model with an optimistic rollup secured by a one-round fraud proof challenge game.

## Key Features

- **Privacy**: Transactions use zero-knowledge proofs to hide sender, receiver, and amounts
- **Free transactions**: Users pay nothing - sequencers are compensated through yield generated on deposited funds
- **High throughput**: Up to 400 transactions per second on Ethereum mainnet using EIP-4844 blobs
- **Low cost**: 0.01 to 0.0001 cents per transaction depending on network conditions
- **Decentralized**: Open sequencer registration with stake-based security

## How It Works

```
User Deposits          Sequencer Batches          L1 Settlement
     |                       |                         |
     v                       v                         v
[ERC-20] --> [L2 Notes] --> [Blob TX] --> [Entrypoint Contract]
     ^                       ^                         |
     |                       |                         v
[Withdraw] <-- [ZK Proof] <-- [Challenge Window] <-- [Finalized]
```

### The Transaction Lifecycle

1. **Deposit**: Users deposit ERC-20 tokens by calling the Entrypoint contract. Tokens are transferred to a yield-generating vault, and a note hash is recorded for inclusion in a future block. The sequencer MUST include this deposit or face slashing. Even if fraud causes a rollback, deposits are re-queued and will eventually be included.

2. **Transact**: Users create zero-knowledge proofs that demonstrate:
   - They know a note exists in the merkle tree
   - They are authorized to spend the note (know the private key)
   - Output notes contain exactly the same total value as inputs
   - Nullifiers are computed correctly to prevent double-spending

   Each transaction can consume up to 2 input notes and create up to 3 output notes. Users submit their proofs to a sequencer for inclusion.

3. **Sequence**: Sequencers batch transactions into EIP-4844 blobs and post them to L1. Each blob can hold approximately 273 transactions. The blob data is committed using KZG polynomial commitments, enabling efficient fraud proofs without storing all data on-chain.

4. **Challenge**: During the challenge window, anyone can prove fraud by:
   - Opening specific blob fields using KZG proofs (~50k gas per field)
   - Demonstrating the sequencer violated protocol rules
   - Triggering a rollback and claiming half the sequencer's stake

5. **Withdraw**: Users create a special note with `publicKey = 0` and `blinding = destinationAddress`. After the challenge period, they prove this note exists using a KZG opening proof and receive their tokens on L1.

### Yield-Based Economics

Unlike traditional L2s that charge transaction fees, PGP uses yield to pay sequencers:

1. User deposits go into ERC-4626 yield vaults (Aave, Compound, etc.)
2. Yield is tracked per period and distributed to sequencers
3. Distribution is proportional to blob usage (more transactions = more yield)
4. Priority sequencers receive a 2x multiplier during their exclusive windows

This model enables **free transactions for users** while ensuring sequencers are compensated.

## Security Model

PGP uses an optimistic rollup model with a one-round challenge game:

### Core Assumptions

1. **Optimistic Execution**: Blocks are assumed valid unless challenged
2. **Economic Security**: Sequencers stake ETH that can be slashed for fraud
3. **Liveness**: At least one honest challenger must be online during the challenge window
4. **Data Availability**: Blob data remains available for the challenge period (~18 days on mainnet)

### Challenge Types

The challenge game has four entry points, each targeting a specific type of fraud:

| Challenge Type | Fraud Detected | Evidence Required |
|----------------|----------------|-------------------|
| **Deposit** | Wrong deposit leaf or non-zero padding | KZG proof of actual value vs expected |
| **Nullifier** | Double-spend (same nullifier twice) | KZG proofs of both occurrences |
| **Tree Update** | Incorrect merkle root after update | ZK proof of correct root + KZG proofs |
| **Transaction** | Invalid ZK proof or missing authorization | Full transaction data via KZG |

### Slashing Mechanics

When fraud is proven:

1. The fraudulent block and all subsequent blocks are rolled back
2. The sequencer loses 100% of their stake:
   - 50% goes to the challenger who proved fraud
   - 50% is burned (prevents collusion)
3. Only the challenger who proves fraud at the **earliest** block number receives the reward
4. Rewards are claimable after the challenge period passes

## Transfer Features

### Private Transfers

The core transfer functionality uses Groth16 zero-knowledge proofs to enable fully private transactions:

- **Sender privacy**: No one can identify who sent a transaction
- **Receiver privacy**: No one can identify who received funds
- **Amount privacy**: Transaction amounts are hidden
- **Unlinkable**: Nullifiers cannot be connected to output notes without the private key

Users prove they own notes by demonstrating knowledge of the private key that hashes to the note's public key. The nullifier `hash(privateKey, blinding, index)` prevents double-spending while remaining unlinkable to the original note.

### Ethereum-Owned Programmable Accounts

PGP supports a feature called **Ethereum-owned accounts** that enables L1-programmable privacy:

#### How It Works

Any note with a `publicKey` value less than 160 bits is considered "Ethereum-owned." The public key is interpreted as an Ethereum address, and spending requires L1 authorization:

```
Standard Note:     publicKey = hash(privateKey)     -> Spend with ZK proof of privateKey
Eth-Owned Note:    publicKey = ethereumAddress      -> Spend with L1 registry approval
```

When spending an Ethereum-owned note, the ZK circuit outputs the `ethKey` as a public input. The on-chain verifier checks that this address has approved the transaction in the `TransactionRegistry` contract.

#### L1 Authorization Flow

```
1. User creates transaction with eth-owned inputs
2. User signs approval on L1:
   TransactionRegistry.approve([nullifier0, nullifier1, leaf0, leaf1, leaf2])
3. Sequencer sees approval and includes transaction
4. Challenge contract verifies registry approval exists
```

This dedicated L1 authorization flow can be used to make L2 payments programmable enabling multisig ownership, trustless swaps, escrows and other features which require resolution logic while at the same time giving destination, amount amd token type privacy for the users.

#### Privacy Trade-offs

| Aspect | Standard Notes | Eth-Owned Notes |
|--------|----------------|-----------------|
| Sender privacy | Full | Partial (address visible on L1) |
| Receiver privacy | Full | Full |
| Amount privacy | Full | Full (unless blinding leaked) |
| Authorization | ZK proof only | Requires L1 transaction |


## Getting Started

- [Quick Start Guide](docs/quick-start.md) - Set up a local development environment
- [User Guide](docs/guides/user-guide.md) - How to deposit, transact, and withdraw
- [Sequencer Guide](docs/guides/sequencer.md) - Run your own sequencer node
- [Architecture Overview](docs/architecture/overview.md) - Deep dive into system design

## Repository Structure

```
pretty_good_payments/
|-- src/                    # Solidity smart contracts
|   |-- Entrypoint.sol      # Main entry point
|   |-- *Challenge.sol      # Fraud proof contracts
|   |-- YieldRouter.sol     # Yield management
|   |-- library/            # Shared libraries
|
|-- offchain/               # Rust off-chain components
|   |-- crates/
|       |-- sequencer/      # Block building and submission
|       |-- challenger/     # Fraud detection and challenge
|       |-- common/         # Shared types and utilities
|       |-- merkle/         # Merkle tree implementation
|
|-- circuits/               # Circom ZK circuits
|-- test/                   # Solidity tests
|-- docs/                   # Documentation
```

## License

UNLICENSED - All rights reserved
