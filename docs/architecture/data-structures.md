# Data Structures

This document explains how data is organized in Pretty Good Payments, both in EIP-4844 blobs and in on-chain storage.

## Blob Memory Layout

EIP-4844 blobs contain 4096 field elements, each 32 bytes. PGP uses this space to store deposits and transactions in a predictable layout that enables KZG proof generation for challenges.

### Overall Organization

Each blob is divided into two regions:

1. **Deposits region**: Starts at field 0
2. **Transactions region**: Starts immediately after deposits

The boundary between regions depends on the number of deposits. A block with 6 deposits uses 8 fields for deposits (2 groups × 4 fields), leaving 4088 fields for transactions.

### Deposit Groups

Deposits are batched into groups of three. Each group uses 4 consecutive fields:

| Field | Contents |
|-------|----------|
| 0 | First deposit leaf hash |
| 1 | Second deposit leaf hash |
| 2 | Third deposit leaf hash |
| 3 | New merkle root after inserting all three |

If a block has deposits that aren't a multiple of three, the final group has padding. For example, with 4 deposits:
- Group 1: [leaf0, leaf1, leaf2, root1]
- Group 2: [leaf3, 0, 0, root2]

The zero padding is enforced by the challenge contracts - non-zero padding is fraud and can be challenged with the deposit challenge.

### Transaction Layout

Each transaction uses 15 consecutive fields:

| Fields | Contents |
|--------|----------|
| 0-7 | Groth16 proof (8 field elements for pA, pB, pC) |
| 8 | Anchor info (encodes block reference + eth key) |
| 9 | First nullifier |
| 10 | Second nullifier |
| 11 | First output leaf hash |
| 12 | Second output leaf hash |
| 13 | Third output leaf hash |
| 14 | New merkle root after inserting outputs |

The proof elements are laid out as: pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1].

### Anchor Info Encoding

The anchor info field packs multiple values into 32 bytes:

- **Bit 254**: Is this referencing a deposit update (1) or transaction update (0)?
- **Bits 222-253**: Block number containing the referenced anchor
- **Bits 190-221**: Update index within that block
- **Bits 0-159**: Ethereum address for eth-keyed transactions (or zero)

This encoding allows a single field to specify which merkle root the transaction is proving membership against, while also carrying the eth-key for authorization checks.

### Cross-Blob Transactions

When a transaction spans blob boundaries (starts in blob N, continues in blob N+1), the field indices simply continue across the boundary. Field 4096 of blob N is logically followed by field 0 of blob N+1.

Challenge contracts handle this through "extension regions" that can load data from a second blob when needed.

### Capacity Limits

A single blob can hold:
- Up to 3,072 deposits (1,024 groups × 3 deposits) leaving some room for transactions
- Up to 273 transactions (4,096 ÷ 15) if there are no deposits

As of time of writing the current max number of blobs per ethereum block is 21 meaning the rollup can seqeunce 21*273 = 5733 transactions per ethereum block.

## On-Chain Storage

The smart contracts store minimal data on-chain, using hashes and mappings for efficiency.

### Block Storage

Each L2 block is stored as a single 32-byte hash in the `roots` array. The hash is computed as keccak256 of the BlockData structure. Anyone referencing a block must provide the full BlockData, which the contract verifies against the stored hash.

This approach minimizes storage costs (one slot per block) while maintaining full verifiability.

### Anchor Index

The `anchorToIndex` mapping enables O(1) lookup of which block produced a given merkle root. This is essential for validating transaction anchor references.

The mapping stores a compressed value containing the block index (64 bits) plus a partial hash (192 bits) for collision resistance. Looking up an anchor returns both the index and enough hash data to verify the match.

### Deposit Queue

Pending deposits are stored in `perBlockDeposits[blockNr]`, an array of leaf hashes. When block N is submitted, it must include exactly the deposits in `perBlockDeposits[N]`.

The `highestDeposit` variable tracks which future block has pending deposits, enabling efficient targeting of new deposits.

### Withdrawal Tracking

Withdrawn outputs are tracked in a bitmap: `withdrawn[blockNr][packedIndex]` where packedIndex combines the transaction number and output index. This prevents double-withdrawal of the same output.

### Sequencer State

Each sequencer's status fits in a single storage slot through careful bit-packing:
- isActive, isPriority: 1 bit each
- priorityIndex: 8 bits
- blocknumberChallenged, timestampChallenged: 64 bits each
- stakeAmount: 64 bits (in units of 10^14 wei)
- challenger: 160 bits

This compression significantly reduces gas costs for sequencer operations.

### Blob Usage Tracking

Per-epoch blob usage is tracked in two mappings:
- `totalBlobUse[epoch]`: Sum of all blob usage in the epoch
- `sequencerBlobUse[epoch][sequencer]`: Per-sequencer contribution

These values are used by the YieldRouter to calculate sequencer rewards.

## Off-Chain Storage

The challenger and sequencer maintain persistent state in SQLite.

### Nullifier Table

All spent nullifiers are recorded with their location:
- `hash`: The nullifier value (primary key)
- `block_nr`: Which block it appeared in
- `tx_index`: Which transaction within the block
- `which`: First (0) or second (1) nullifier of the transaction

This enables efficient double-spend detection by querying whether a nullifier exists.

### Anchor Table

Merkle roots after each update are stored for anchor validation:
- `block_nr`: Block containing this anchor
- `update_nr`: Index of the update (0, 1, 2...)
- `is_deposit`: Whether this is a deposit group or transaction update
- `anchor`: The 32-byte merkle root

Transactions reference anchors by (block_nr, update_nr, is_deposit), which this table resolves.

### Block Cache

Full block data is cached for challenge building:
- `block_nr`: L2 block number (primary key)
- `l1_block_number`: Which L1 block included this
- `data`: Serialized BlockData structure

Cached blocks enable constructing challenge transactions without re-querying L1.

### Block Roots

Per-block tree roots support the root tree for anchor computation:
- `tree_index`: Global index (day × blocks_per_day + block_in_day)
- `block_nr`: Which L2 block
- `root`: The block's final merkle root

The root tree tracks these values to compute anchors for new blocks.

## Merkle Tree Structure

Notes are organized in a 44-level sparse merkle tree with hierarchical indexing. The tree has a two-level structure that separates block-level organization from note-level organization.

### Two-Level Hierarchy

**Root Tree (28 levels)**: The upper portion of the tree indexes blocks using a time-based scheme:
- 15 bits for the day number (up to 32,768 days, ~90 years)
- 13 bits for the block-within-day index (up to 8,192 blocks per day)

The block index is computed as `day × 8192 + block_index_within_day`. When a new calendar day begins (based on the contract's deployment timestamp), the block index resets to zero, placing that day's blocks in a fresh subtree.

**Block Tree (16 levels)**: Within each block's position in the root tree, there's a subtree that holds up to 65,536 notes. Notes are inserted sequentially starting from index 0.

### Index Composition

A note's 44-bit index encodes its position:
- **Bits 0-15** (16 bits): Note within block (up to 65,536 notes)
- **Bits 16-28** (13 bits): Block within day (up to 8,192 blocks)
- **Bits 29-43** (15 bits): Day number (up to 32,768 days)

This structure enables efficient syncing: users download day-level summaries, then block-level summaries for the current day, then individual paths for their notes.

### Frontier Insertion

Notes must be inserted at the tree's "frontier" - the first empty slot in the current block's subtree. The ZK circuit for tree updates enforces that:

1. The slot immediately before the insertion point contains a non-zero value (or this is slot 0)
2. The target slots (where the new notes will go) are currently empty (zero)

This ensures the tree is append-only within each block. A sequencer cannot insert notes at arbitrary positions or overwrite existing notes.

### Zero Hashes

Empty subtrees use precomputed "zero hashes" - the root of a completely empty tree at each depth. The zero hash at level 0 is simply `0`, and each subsequent level's zero hash is `Poseidon(zero_hash[n-1], zero_hash[n-1])`. These are computed once and cached, enabling efficient sparse tree operations.

## Proof Structures

### KZG Point Proofs

KZG proofs demonstrate that a blob contains a specific value at a specific index. Each proof consists of:
- The blob commitment (48 bytes)
- The point proof (48 bytes)
- The field index and claimed value

The EIP-4844 point evaluation precompile verifies these proofs in approximately 50,000 gas.

### Groth16 Proofs

ZK proofs for transactions use the Groth16 proving system:
- pA: 2 field elements (G1 point)
- pB: 4 field elements (G2 point, represented as 2×2 matrix)
- pC: 2 field elements (G1 point)

Total: 8 field elements = 256 bytes in the blob.

### Region Proofs

For multi-field validation, the challenger provides a "region" containing:
- Starting index and length
- All field values in the region
- Individual KZG proofs for each field
- The blob commitment and hash

Regions enable efficient batch validation of transaction data.
