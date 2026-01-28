# Smart Contracts

This document explains the design and purpose of the Solidity smart contracts that power Pretty Good Payments.

## Contract Architecture

The contract system is organized around the **Entrypoint** contract, which serves as the unified interface for all user and sequencer interactions. Rather than deploying separate contracts, PGP uses inheritance to compose all functionality into a single address. This simplifies integration and reduces gas costs by avoiding cross-contract calls.

The inheritance hierarchy reflects the separation of concerns:

- **Entrypoint** is the top-level contract that users interact with
- **Challenge contracts** (Deposit, Nullifier, Transaction, TreeUpdate) handle fraud proofs
- **Deposits** and **Withdraw** manage the L1 token flow
- **SequencerRegistry** handles staking and permissions
- **Spine** provides the core block storage that all other contracts depend on
- **BlobData** contains low-level KZG proof validation logic

## Entrypoint

The Entrypoint contract is what users and sequencers actually call. It exposes three main operations:

**Block Submission**: Sequencers call `post()` to add new L2 blocks. The contract verifies the caller is an allowed sequencer, confirms the deposit count matches what's pending on L1, stores the block hash, and tracks blob usage for yield distribution. The actual block data lives in EIP-4844 blobs attached to the transaction - only the hash and metadata are stored on-chain.

**Deposits**: Users call `deposit()` to move tokens from L1 into the L2 system. The contract transfers tokens to the YieldRouter (which deposits them into yield-generating vaults), records the note hash for inclusion in a future block, and emits an event so the sequencer knows to include it.

**Withdrawals**: Users call `withdraw()` to move funds back to L1. They must provide a KZG proof that their note exists in a confirmed block's blob data. The contract verifies the proof, checks the note hasn't been withdrawn before, and instructs the YieldRouter to send tokens to the destination address.

## Spine: Block Storage

The Spine contract is the backbone of the system - it stores the L2 chain state and provides functions for adding blocks and rolling back on fraud.

### How Blocks Are Stored

Each L2 block is represented by a `BlockData` structure containing the final merkle root (anchor), transaction and deposit counts, the submitting sequencer's address, and the versioned hashes of the attached blobs. Rather than storing this entire structure, the contract stores only its keccak256 hash in a `roots` array. This means anyone who wants to reference a block must provide the full BlockData, which the contract verifies against the stored hash.

The contract also maintains an `anchorToIndex` mapping that enables O(1) lookup of which block produced a given merkle root. This is essential for validating transaction anchor references during challenges.

### Block Index Calculation

To enable efficient merkle tree organization, each block is assigned a `blockIndex` consisting of a day number and an index within that day. The day resets when the calendar day changes (based on contract deployment time), and the index increments for each block within the day. This structure allows the merkle tree to be organized hierarchically by day, enabling users to sync efficiently by downloading day-level summaries.

### Rollback Mechanism

When fraud is proven, the chain must be rolled back to remove the fraudulent block and all blocks after it. The `rollback()` function accepts the index to remove and the BlockData of the prior valid block. It truncates the `roots` array, restores the timestamp tracking, and cleans up the anchor index. This is a destructive operation that can only be triggered by successful challenge transactions.

## Deposits Contract

The Deposits contract handles the L1 side of getting tokens into the L2 system.

### Deposit Targeting

When a user deposits, they can't control exactly which block their deposit appears in - that's determined by sequencers. However, the contract ensures predictability by targeting deposits to specific future blocks. A deposit made now targets block `max(highestPendingDeposit, currentBlock + 2)`. This gives sequencers at least two blocks of lead time to include deposits.

Deposits for a block are stored in `perBlockDeposits[blockNr]`, an array of note hashes. The sequencer MUST include exactly these deposits when submitting that block, or they can be challenged.

### Constant Blinding

For ZK circuit compatibility, all deposit notes use a constant blinding factor rather than a user-chosen one. This is required because the deposit leaf must be deterministically computable from on-chain data for challenge verification. Users should transfer deposited funds to notes with random blinding factors for privacy.

## Withdraw Contract

The Withdraw contract processes L1 withdrawals using KZG proofs to verify note existence.

### Withdrawal Requirements

For a withdrawal to succeed:
1. The containing block must be past the challenge period (confirmed)
2. The note must have `publicKey == 0`, which marks it as an L1-withdrawable note
3. The note must not have been withdrawn before (tracked in a bitmap)
4. A valid KZG proof must demonstrate the note hash exists at the claimed position in the blob

### KZG Proof Validation

The withdrawal provides a KZG commitment and point proof. The contract computes which blob and field index the note should be at based on the transaction number and output index, then calls the EIP-4844 point evaluation precompile to verify the claimed value matches the blob. This is a non-interactive proof that the sequencer actually included this note in the block.

## SequencerRegistry

The SequencerRegistry manages who can submit blocks and their economic stake.

### Epoch-Based Access Control

Time is divided into epochs (configurable length per network). Each epoch has two halves:

**Closed Period** (first half): Only the designated priority sequencer can submit blocks. Priority sequencers rotate through a list maintained by the contract owner. This gives them guaranteed submission windows without competition.

**Open Period** (second half): Any sequencer with sufficient stake can submit blocks. Multiple sequencers may compete, with blocks ordered by transaction inclusion.

This hybrid approach balances decentralization (anyone can become a sequencer) with reliability (priority sequencers have guaranteed windows).

### Staking and Slashing

Sequencers must stake ETH to participate. The stake serves as a security bond - if they submit fraudulent blocks, they lose half their stake to the challenger who proved the fraud, while the other half is burned.

The stake amount is stored in units of 10^14 wei rather than full wei. This compression allows the full sequencer status to fit in a single storage slot, significantly reducing gas costs for status updates.

### Exit Process

Sequencers can't withdraw their stake immediately - they must first call `registerExit()` which deactivates them and starts a waiting period. After the challenge window elapses without any successful challenges, they can call `exit()` to reclaim their stake. This delay ensures challengers have time to prove fraud before the stake disappears.

## Challenge Contracts

The four challenge contracts implement PGP's fraud proof system. Each handles a different type of fraud that sequencers might commit.

### DepositChallenge

This contract proves a sequencer submitted incorrect deposit data. There are three fraud scenarios:

**Note**: The Entrypoint enforces correct deposit counts at submission time - blocks with mismatched deposit counts are rejected before they enter the chain. The challenge contract contains legacy code for count mismatch, but this case cannot occur in practice.

**Wrong Leaf**: The sequencer included a deposit hash that doesn't match the L1 record. The challenger provides a KZG proof showing what value the sequencer actually put in the blob, and the contract compares it against the expected value.

**Non-Zero Padding**: Deposit groups contain 3 deposits each. If a block has deposits that aren't a multiple of 3, the unused slots must be zero. A challenger can prove padding slots contain non-zero values.

### NullifierChallenge

This contract proves double-spending by showing the same nullifier appears twice. The challenger identifies both occurrences (which block, which transaction, which nullifier slot) and provides KZG proofs that both locations contain the same value.

The key constraint is that the "first" occurrence must be in an earlier block than the "second" occurrence - we slash the sequencer who accepted the duplicate, not the sequencer who accepted the original.

### TransactionChallenge

This contract proves a transaction is invalid. There are several fraud scenarios:

**Invalid Anchor Reference**: The transaction references a merkle root that doesn't exist (future block) or an update index that's out of bounds for that block.

**Invalid ZK Proof**: The Groth16 proof doesn't verify against the public inputs. The contract extracts the proof and inputs from the blob via KZG, then calls the verifier contract.

**Missing Eth-Key Authorization**: If the transaction uses an Ethereum address as the public key (eth-keyed account), the owner must have approved the transaction in the TransactionRegistry. The challenger can prove this approval is missing.

### TreeUpdateChallenge

This contract proves the sequencer computed an incorrect merkle root after adding notes. Each deposit group and transaction produces a new root by inserting notes into the tree.

The merkle tree has a two-level hierarchy: a 28-level "root tree" that indexes blocks by day and block-within-day, and a 16-level "block tree" within each block position that holds up to 65,536 notes. The block's position in the root tree is computed as `day × 8192 + block_index_within_day`, using the block index stored in the BlockData structure.

The ZK circuit enforces "frontier insertion" - notes must be inserted at the first empty slot. It proves that the slot before the insertion point is non-empty (or this is slot 0), and that the target slots are empty before insertion. This prevents sequencers from inserting notes at arbitrary positions and ensures the tree remains append-only.

The challenger provides:

1. The prior anchor (root before this update)
2. The three note hashes being inserted (extracted from the blob via KZG)
3. The block index to locate this block in the root tree hierarchy
4. A ZK proof demonstrating the correct new root by: verifying frontier constraints, inserting notes at the correct positions in the block subtree, and computing the updated root tree
5. KZG proofs showing what the sequencer actually submitted

If the sequencer's submitted root differs from the correctly computed root, that's fraud. The contract also checks if this is the last update in the block and verifies the block's final anchor field matches.

## YieldRouter

The YieldRouter manages the economic engine that pays for transaction processing.

### Yield Generation

When users deposit tokens, the YieldRouter deposits them into ERC4626 vaults (like Aave or Compound wrappers). These vaults generate yield over time. The router tracks the "principal" (total deposited minus withdrawn) separately from the current vault balance, so yield can be calculated as the difference.

### Period-Based Accounting

Yield is recorded in discrete periods (configurable length). Anyone can call `poke()` to trigger recording for the current period. This snapshots the yield generated since the last period and makes it available for distribution.

### Sequencer Distribution

Within each period, yield is divided among epochs based on the `EPOCHS_PER_PERIOD` configuration. Within each epoch, yield is distributed to sequencers proportionally to their blob usage. A sequencer who submitted 60% of the blob data in an epoch receives 60% of that epoch's yield allocation.

Priority sequencers receive a 2x multiplier on their blob usage during closed periods, incentivizing reliable block production during guaranteed windows. 

## BlobData Library

The BlobData library provides low-level functions for working with EIP-4844 blob data.

### Memory Layout

Blobs contain 4096 field elements of 32 bytes each. PGP organizes this space as:
- **Deposits region**: Groups of 4 fields (3 deposit hashes + group root)
- **Transactions region**: Groups of 15 fields (8 proof elements + anchor info + 2 nullifiers + 3 outputs + new root)

### KZG Validation

The library wraps the EIP-4844 point evaluation precompile (address 0x0A). Given a versioned blob hash, a field index, and an expected value, it verifies a KZG proof that the blob actually contains that value at that index. This costs approximately 50,000 gas per verification.

For multi-field validation (like reading an entire transaction), the contract uses "region" structures that batch multiple KZG proofs together. This is more gas-efficient than validating fields one at a time.

## Gas Considerations

The contract system is optimized for gas efficiency:

- **Single-slot sequencer status**: All sequencer state fits in one storage slot through careful bit-packing
- **Hash-only block storage**: Only the block hash is stored, not the full data
- **Anchor indexing**: O(1) anchor lookups avoid iteration during challenges
- **Batched KZG validation**: Region-based proof validation reduces overhead

Approximate costs:
- Block submission: ~60,000-130,000 gas (plus blob gas)
- Deposit: ~150,000 gas
- Withdrawal: ~100,000 gas
- Challenge: 200,000-700,000 gas depending on type
