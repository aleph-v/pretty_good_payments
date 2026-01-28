# Off-Chain Components

The off-chain system consists of Rust services that handle transaction processing, block building, and fraud detection. These components work together to operate the L2, with the sequencer building blocks and the challenger validating them.

## System Overview

The off-chain architecture has two main roles:

**Sequencer**: Accepts user transactions, validates them, batches them into blobs, and submits blocks to L1. The sequencer is the active participant that moves the system forward.

**Challenger**: Monitors submitted blocks, validates all data, and submits fraud proofs if it detects invalid blocks. The challenger is the watchdog that keeps sequencers honest.

Both roles share infrastructure and can run in the same process. They must share a database to maintain consistent state.

## Shared Database

The sequencer and challenger **must share the same SQLite database**. This is critical for correct operation:

- The **sequencer** writes block data and anchors when building blocks
- The **challenger** writes nullifiers and block roots when validating
- Both read from shared tables for validation and lookups

The shared state includes:
- **Nullifiers**: All spent nullifiers with their block/tx location
- **Anchors**: Merkle roots after each update, indexed for fast lookup
- **Blocks**: Cached block data for validation and challenge building
- **Block roots**: Per-block tree roots for anchor computation

When deploying on separate machines, use network-attached storage or database replication to maintain a shared database.

## Sequencer Architecture

The sequencer has several key components that work together:

### REST API

The sequencer exposes HTTP endpoints for transaction submission and operational control. Users submit transactions to `/submit`, operators can force block submission via `/poke`, and monitoring systems can check health via `/health` and `/stats`.

The API runs in a separate async task and communicates with the mempool through thread-safe channels and mutexes.

### Mempool

The mempool holds validated transactions waiting to be included in blocks. When a transaction arrives, the mempool validates it before accepting:

1. **Capacity check**: Reject if mempool is full
2. **Nullifier uniqueness**: Each nullifier can only appear once across all pending transactions
3. **Historical nullifier check**: Query database to ensure nullifiers weren't spent in previous blocks
4. **Anchor validation**: Verify the referenced merkle root exists and the update index is valid
5. **ZK proof verification**: Call snarkjs to verify the Groth16 proof

Only transactions that pass all checks are added to the queue. Failed transactions receive specific error messages explaining why they were rejected.

The mempool tracks "pending nullifiers" separately from the transaction queue. This prevents accepting two transactions that spend the same note, even before either is included in a block.

### Blob Builder

When it's time to build a block, the blob builder:

1. **Fetches deposits**: Queries the L1 contract for deposits targeting this block
2. **Takes transactions**: Drains transactions from the mempool up to capacity
3. **Computes layout**: Arranges deposits (4 fields per 3) and transactions (15 fields each) in blob memory
4. **Calculates roots**: For each deposit group and transaction, computes the new merkle root after inserting outputs
5. **Produces blob data**: Returns the raw blob bytes ready for submission

The builder maintains a local copy of the merkle tree state to compute roots incrementally. After successful submission, this state becomes authoritative.

### Block Submitter

The block submitter handles the timing and mechanics of L1 submission:

1. **Epoch tracking**: Monitors the current epoch and whether we're in closed or open period
2. **Permission check**: Waits until `isAllowed()` returns true for our address
3. **Transaction building**: Constructs a blob transaction with the built data
4. **Submission**: Sends to L1 and waits for confirmation
5. **Event verification**: Confirms the NewRoot event was emitted with expected values

The submitter handles retries and gas price adjustments for failed submissions.

### Epoch Watcher

The epoch watcher tracks timing for submission windows. It caches the epoch configuration from the contract and calculates:

- Current epoch number
- Whether we're in closed or open period
- Time until next submission window
- Whether our address is the current priority sequencer

This information drives the block submitter's timing decisions.

## Challenger Architecture

The challenger validates every block and submits challenges when fraud is detected.

### Event Listener

The challenger subscribes to NewRoot events from the Entrypoint contract. Each event triggers a validation cycle for the new block. The listener also handles chain reorganizations by rolling back local state when blocks are removed.

### Blob Provider

Blob data must be retrieved from the beacon chain (blobs aren't available through normal Ethereum RPC). The blob provider:

1. **Checks cache**: Returns immediately if blob is already cached
2. **Queries beacon**: Fetches from beacon chain API if within the ~18-day availability window
3. **Falls back to database**: Returns from local storage if beacon no longer has the blob
4. **Caches results**: Stores retrieved blobs for future use

The provider handles the complexity of beacon chain slot timing and blob expiration.

### Validators

Four validators check different aspects of each block:

**Deposit Validator**: Fetches expected deposits from L1 and compares them to what's in the blob. Checks that deposit hashes match and padding slots are zero.

**Nullifier Validator**: Checks each transaction's nullifiers against the database of spent nullifiers. If a nullifier was already used, that's double-spend fraud. After validation, records new nullifiers for future checks.

**Transaction Validator**: Verifies each transaction's ZK proof using snarkjs. Also validates anchor references exist and eth-keyed transactions have registry approval.

**Tree Update Validator**: Recomputes merkle roots locally and compares to the sequencer's claimed roots. Uses an incremental merkle tree to efficiently track state.

### Challenge Builder

When fraud is detected, the challenge builder constructs the on-chain challenge transaction:

1. **Retrieves blob data**: Gets the full blob content for proof generation
2. **Generates KZG proofs**: Creates point evaluation proofs for each field needed
3. **Builds parameters**: Constructs the challenge function's parameters
4. **Handles edge cases**: Manages cross-blob transactions and various fraud types

Different fraud types require different challenge structures. The builder has specialized methods for each type.

### Challenge Submitter

The challenge submitter sends challenge transactions to L1:

1. **Estimates gas**: Simulates the transaction to estimate costs
2. **Submits transaction**: Sends with appropriate gas price
3. **Monitors result**: Waits for confirmation or failure
4. **Handles failures**: Queues for retry if submission fails

Failed challenges are stored in the database for later retry. The submitter implements exponential backoff to avoid overwhelming the network.

## Common Infrastructure

### State Manager

The StateManager provides a clean interface to the SQLite database. It handles:

- Connection management and transactions
- Schema migrations
- CRUD operations for all tables
- Query optimization for common access patterns

Both sequencer and challenger use StateManager to access shared state.

### Blob Parsing

The common library provides blob parsing utilities that convert raw blob bytes into structured data:

- **ParsedBlock**: Contains deposit groups and transactions
- **DepositGroup**: Three leaves plus the group's new root
- **ParsedTransaction**: Proof, anchor info, nullifiers, outputs, and new root

The parser validates field boundaries and handles malformed data gracefully.

### Configuration

Both services use a shared configuration structure loaded from TOML files. Configuration includes:

- Network settings (RPC URL, beacon URL, chain ID)
- Contract addresses
- Key management (private key for signing)
- Storage paths (database, circuit files)
- Operational parameters (mempool size, blob cache size)

Environment variables can override file settings for sensitive values like private keys.

### Merkle Library

The merkle library provides Poseidon-based sparse merkle tree operations:

- Insert leaves at specific indices
- Compute new roots after insertions
- Generate membership proofs
- Track incremental updates efficiently

The implementation uses lazy computation and caching to minimize redundant hash operations.

## Database Schema

The SQLite database contains these tables:

**state**: Key-value store for operational state like last processed block

**nullifiers**: All spent nullifiers with (block_nr, tx_index, which) location

**anchors**: Merkle roots indexed by (block_nr, update_nr, is_deposit)

**blocks**: Cached block data for challenge building and lookups

**block_roots**: Per-block tree roots for anchor computation

**pending_challenges**: Queue of failed challenges for retry

## Deployment Considerations

### Same Machine

Running sequencer and challenger on the same machine is the simplest deployment. Both processes use the same database file path, and SQLite handles concurrent access safely.

### Separate Machines

For redundancy, you might run sequencer and challenger separately:

1. **Network storage**: Mount the database file on shared network storage (NFS, EFS)
2. **Replication**: Use database replication to sync writes between machines
3. **Separate databases**: Run independent databases with the understanding that the challenger may miss some validation (not recommended)

### High Availability

For production deployments:

- Run multiple challenger instances on different machines
- Use separate RPC endpoints to avoid single points of failure
- Implement automatic failover for sequencer operations
- Monitor block lag and challenge submission success rates
