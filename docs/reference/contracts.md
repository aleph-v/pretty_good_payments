# Contract Reference

Quick reference for PGP smart contract functions and their purposes.

## Entrypoint

The main contract users and sequencers interact with.

### User Functions

| Function | Purpose |
|----------|---------|
| `deposit(leaf)` | Deposit tokens and create an L2 note. Tokens are transferred to the yield vault. |
| `withdraw(leaf, blockData, txNr, which, commitment, proof)` | Withdraw tokens to L1 by proving a note exists in a confirmed block. |

### Sequencer Functions

| Function | Purpose |
|----------|---------|
| `post(data, blobIndices)` | Submit a new L2 block with blob data. |
| `fund()` | Stake ETH to become an active sequencer. |
| `registerExit()` | Begin the exit process (starts the waiting period). |
| `exit(who)` | Complete exit and reclaim stake after the waiting period. |

### View Functions

| Function | Returns |
|----------|---------|
| `getCurrentBlocknumber()` | Current L2 block number |
| `isAllowed(sequencer)` | Whether the sequencer can submit now |
| `isConfirmed(blockData)` | Whether a block is past the challenge period |
| `isFinalized(epoch)` | Whether an epoch is past the challenge period |
| `getPercentInEpoch(sequencer, epoch)` | Sequencer's share of epoch blob usage (1e18 = 100%) |
| `getDepositArray(blockNr)` | Pending deposit hashes for a block |

### Challenge Functions

| Function | Purpose |
|----------|---------|
| `challengeDepositWrongLeaf(...)` | Prove wrong deposit data in a block |
| `challengeDepositPadding(...)` | Prove non-zero padding in partial deposit group |
| `challengeNullifier(...)` | Prove nullifier was used twice (double-spend) |
| `challengeTxZK(...)` | Prove invalid ZK proof or missing authorization |
| `challengeTreeUpdate(...)` | Prove incorrect merkle root after update |
| `claimChallengeReward(who)` | Claim 50% of slashed sequencer's stake |

## YieldRouter

Manages yield generation and distribution.

### Bridge Functions (called by Entrypoint only)

| Function | Purpose |
|----------|---------|
| `triggerDeposit(asset, amount)` | Deposit tokens to yield vault |
| `triggerWithdraw(asset, amount, destination)` | Withdraw tokens from vault to user |

### Sequencer Functions

| Function | Purpose |
|----------|---------|
| `sequencerWithdrawAsset(token, sequencer, epoch)` | Claim yield for one epoch |
| `withdrawMany(sequencer, epochs)` | Batch claim yield for multiple epochs |

### Public Functions

| Function | Purpose |
|----------|---------|
| `poke()` | Record yield for current period (anyone can call) |

### Owner Functions

| Function | Purpose |
|----------|---------|
| `changeYieldSource(token, newVault)` | Migrate token to different yield vault |
| `changeTrackedYieldSources(addresses)` | Update list of tracked tokens |
| `setMaxInterest(token, max)` | Set max yield cap per period |

## SequencerRegistry

Manages sequencer staking and permissions.

### Owner Functions

| Function | Purpose |
|----------|---------|
| `addFirstLook(who)` | Add sequencer to priority list |
| `removeFirstLook(index)` | Remove sequencer from priority list |
| `setRequiredStake(amount)` | Change minimum stake requirement |

### View Functions

| Function | Returns |
|----------|---------|
| `currentEpoch()` | Current epoch number and whether in closed period |
| `sequencers(address)` | Sequencer's full status |
| `firstLookSequencers(index)` | Priority sequencer at index |
| `exits(address)` | Timestamp when sequencer registered exit |

## TransactionRegistry

Manages eth-keyed transaction approvals.

| Function | Purpose |
|----------|---------|
| `approve(fields)` | Approve a transaction from your eth-keyed account |
| `query(ethKey, fields)` | Check if a transaction is approved |

## Key Data Structures

### BlockData

Represents an L2 block's metadata:
- `anchor`: Final merkle root after all updates in this block
- `timestamp`: When the block was submitted (set by contract)
- `numTransactions`: Count of transactions in the block
- `numDeposits`: Count of deposits in the block
- `blockNr`: Sequential L2 block number
- `blockIndex`: Day number and index within day (for tree organization)
- `sequencer`: Address that submitted this block
- `blobhashes`: Versioned hashes of attached blobs

### Leaf

Represents a note (both deposits and transaction outputs):
- `asset`: ERC-20 token address
- `amount`: Token amount
- `blinding`: Random factor (or destination address for withdrawals)
- `publicKey`: Owner's key (ZK public key, eth address, or 0 for withdrawals)

### SequencerStatus

Tracks a sequencer's state:
- `isActive`: Can submit blocks
- `isPriority`: In priority rotation
- `priorityIndex`: Position in priority list
- `stakeAmount`: Stake in compressed units
- `challenger`: Address that proved fraud (if any)
- `timestampChallenged`: When fraud was proven
- `blocknumberChallenged`: Which block had fraud

## Events

### Block Events

| Event | When Emitted |
|-------|--------------|
| `NewRoot(blockNr, anchor, l2BlockHash, data)` | New block submitted |
| `Deposit(leafHash, block, number)` | Deposit recorded |

### Sequencer Events

| Event | When Emitted |
|-------|--------------|
| `SequencerSlashed(sequencer, blockNr, challenger)` | Fraud proven |
| `SequencerExited(sequencer, amount)` | Exit completed |

## Important Constants

The following values are configurable per network deployment:

| Constant | Description |
|----------|-------------|
| `EPOCH_LENGTH` | Duration of one epoch in seconds |
| `CHALLENGE_WINDOW` | Duration of challenge period |
| `requiredStake` | Minimum stake to be an active sequencer |

Fixed protocol constants:

| Constant | Value | Description |
|----------|-------|-------------|
| `TREE_DEPTH` | 44 | Total merkle tree depth |
| `BLOB_SIZE` | 4096 | Fields per blob |
| `TX_SIZE` | 15 | Fields per transaction |
| `DAY` | 86400 | Seconds per day |
| `STAKE_DIVISOR` | 10^14 | Stake compression factor |

## Error Reference

See [Error Reference](errors.md) for a complete list of custom errors and their meanings.
