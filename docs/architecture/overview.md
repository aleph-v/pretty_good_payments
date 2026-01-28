# Architecture Overview

Pretty Good Payments is an optimistic rollup that uses EIP-4844 blobs for data availability and zero-knowledge proofs for transaction privacy.

## System Architecture

```
                                L1 (Ethereum Mainnet)
+------------------+-------------------------------------------+
|                  |                                           |
|   ERC-20 Tokens  |            Entrypoint Contract            |
|        |         |   +----------+  +----------+  +---------+ |
|        v         |   | Deposits |  | Withdraw |  | Sequencer||
|   YieldRouter <--|-->| Challenge|  |          |  | Registry ||
|        |         |   +----------+  +----------+  +---------+ |
|        v         |   +----------+  +----------+  +---------+ |
|   ERC4626 Vault  |   |Nullifier |  |   Tree   |  |   TX    | |
|                  |   |Challenge |  | Update   |  |Challenge| |
+------------------+---+----------+--+----------+--+---------+-+
                              ^              ^
                              |    Blobs     |
                   +----------+--------------+----------+
                   |                                    |
            +------+------+                    +--------+-------+
            |  Sequencer  |                    |   Challenger   |
            |   (Rust)    |                    |     (Rust)     |
            +------+------+                    +--------+-------+
                   ^                                    ^
                   |          Transactions              |
            +------+------------------------------------+------+
            |                  Mempool                         |
            +--------------------------------------------------+
                                    ^
                                    |
                              User Wallets
```

## Layer 1 Components

### Entrypoint Contract

The main entry point that inherits all other contracts:

```
Entrypoint
    |-- Withdraw
    |       |-- Spine (block storage)
    |               |-- BlobData (KZG validation)
    |-- DepositChallenge
    |       |-- Deposits
    |       |-- SequencerRegistry
    |-- TransactionChallenge
    |-- NullifierChallenge
    |-- TreeUpdateChallenge
```

**Key functions:**
- `post(BlockData, blobIndices)` - Submit new L2 block
- `deposit(Leaf)` - Create deposit note
- `withdraw(Leaf, BlockData, proof)` - Withdraw funds to L1

### Contract Inheritance

| Contract | Inherits From | Purpose |
|----------|---------------|---------|
| `Entrypoint` | All challenge contracts, `Withdraw` | Main interface |
| `Withdraw` | `Spine` | Process withdrawals |
| `DepositChallenge` | `Deposits`, `SequencerRegistry` | Challenge bad deposits |
| `TransactionChallenge` | `Spine`, `SequencerRegistry` | Challenge invalid ZK proofs |
| `NullifierChallenge` | `Spine`, `SequencerRegistry` | Challenge double-spends |
| `TreeUpdateChallenge` | `Spine`, `SequencerRegistry` | Challenge merkle updates |
| `Deposits` | `Spine` | Handle deposits |
| `SequencerRegistry` | `Spine`, `Ownable` | Manage sequencers |
| `Spine` | `BlobData` | Core block storage |

## Off-Chain Components

### Sequencer

The sequencer is responsible for:

1. **Mempool management** - Accept and validate transactions
2. **Block building** - Batch transactions into blobs
3. **Epoch timing** - Submit during allowed windows
4. **Block submission** - Post blob transactions to L1

```rust
// Key modules
sequencer/
  api.rs            // REST API for transaction submission
  mempool.rs        // Transaction queue with validation
  blob_builder.rs   // Construct blob data
  block_submitter.rs // Submit to L1
  epoch.rs          // Timing calculations
```

### Challenger

The challenger monitors for fraud:

1. **Event listening** - Watch for NewRoot events
2. **Blob retrieval** - Fetch blob data from beacon chain
3. **Validation** - Check deposits, nullifiers, ZK proofs, tree updates
4. **Challenge submission** - Submit fraud proofs when detected

```rust
// Key modules
challenger/
  runner.rs         // Main validation logic
  validators/       // Individual fraud checkers
    deposit.rs      // Deposit validation
    nullifier.rs    // Double-spend detection
    transaction.rs  // ZK proof verification
    tree_update.rs  // Merkle update validation
  challenge.rs      // Build challenge transactions
  beacon.rs         // Blob retrieval
  state.rs          // Database persistence
```

## Data Flow

### Deposit Flow

```
1. User calls deposit(leaf) on Entrypoint
2. Tokens transferred to YieldRouter
3. YieldRouter deposits to ERC4626 vault
4. Leaf hash recorded in perBlockDeposits[blockNr]
5. Sequencer includes deposit in next block
6. Deposit becomes spendable after challenge period
```

### Transaction Flow

```
1. User creates ZK proof for spend
2. Submits proof to sequencer API
3. Mempool validates:
   - Nullifiers not spent
   - Anchor reference valid
   - ZK proof valid
4. Sequencer batches into blob
5. Submits blob transaction to Entrypoint.post()
6. Challenger validates block
7. After challenge period, outputs are spendable
```

### Withdrawal Flow

```
1. User creates transaction with publicKey=0
2. Transaction included in block
3. After challenge period
4. User calls withdraw() with:
   - Output leaf preimage
   - Block data
   - KZG proof of leaf in blob
5. Funds sent to address in leaf.blinding
```

## Timing and Epochs

### Epoch Structure

```
|<-------------- EPOCH -------------->|
|<-- Closed (half) -->|<-- Open (half) -->|
|   Priority only       |   Any sequencer     |
```

- **Epoch length**: Configurable per network
- **Closed period**: First half - only priority sequencer
- **Open period**: Second half - any staked sequencer
- **Challenge period**: Configurable per network

### Block Finalization

```
Block N submitted --> Challenge window --> Finalized
                              |
                     Fraud detected? --> Rollback to N-1
                              |                |
                              |                v
                              |         Slash sequencer
                              v
                         No fraud --> Block confirmed
```

## Security Considerations

### Fraud Types

| Type | Description | Detection |
|------|-------------|-----------|
| Wrong deposit | Deposit leaf doesn't match L1 | Compare blob vs contract |
| Double spend | Nullifier reused | Track all nullifiers |
| Invalid ZK proof | Proof doesn't verify | Verify Groth16 proof |
| Wrong tree update | Merkle root incorrect | Recompute with ZK proof |
| Missing auth | Eth-keyed tx not approved | Check registry |

### Economic Security

- **Sequencer stake**: Configurable per network
- **Slash amount**: 50% to challenger, 50% burned
- **Challenge window**: Configurable per network
- **Exit delay**: Same as challenge window (after registerExit)
