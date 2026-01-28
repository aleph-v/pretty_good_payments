# Challenge Game

The challenge game is PGP's fraud proof system. It allows anyone to prove that a sequencer submitted invalid data and claim a reward for doing so. This mechanism ensures the system remains trustless - users don't need to trust sequencers because fraud can always be detected and punished.

## How It Works

When a sequencer submits a block, it enters a challenge period. During this window, anyone can examine the block and submit a challenge transaction if they find fraud. If the challenge succeeds, the sequencer is slashed (loses stake) and the chain rolls back to remove the fraudulent block.

If no successful challenge is submitted during the window, the block becomes "confirmed" and is considered final. Withdrawals and yield claims can only reference confirmed blocks.

## Types of Fraud

There are four categories of fraud, each handled by a dedicated challenge contract:

### Deposit Fraud

Sequencers must include specific deposits in specific blocks - the deposits are recorded on L1 and the sequencer must match them exactly. The Entrypoint enforces that blocks have the correct deposit count at submission time, so blocks with wrong counts are rejected before entering the chain.

Deposit fraud that can actually occur:

**Wrong value**: The sequencer included a deposit hash that doesn't match what L1 recorded. The challenger proves this by revealing the actual value in the blob (via KZG proof) and comparing it to the expected value.

**Invalid padding**: Deposits are grouped in threes. If a block has 4 deposits, that's two groups: one full (3 deposits) and one partial (1 deposit + 2 zeros). If those padding zeros aren't actually zero, that's fraud.

### Nullifier Fraud (Double-Spending)

Each transaction consumes inputs by publishing their nullifiers. A nullifier should only ever appear once across the entire chain history. If the same nullifier appears twice, someone double-spent - they used the same note as input to two different transactions.

The challenger identifies both occurrences: which block, which transaction, which nullifier slot (each transaction has two). They provide KZG proofs that both locations contain the same value. The "second" occurrence (in the later block) is the fraud - the sequencer should have rejected the transaction because the nullifier was already used.

### Transaction Fraud

Each transaction contains a Groth16 zero-knowledge proof that demonstrates the transaction is valid (inputs exist, outputs balance, sender knows private keys). If this proof is invalid, or if required authorizations are missing, that's fraud.

**Invalid anchor**: Transactions reference a merkle root ("anchor") that proves their inputs exist in the tree. If the transaction references a future block or an update index that doesn't exist, the reference is invalid.

**Invalid proof**: The ZK proof doesn't verify. The challenger extracts the proof and public inputs from the blob and the on-chain verifier contract rejects them.

**Missing authorization**: For "eth-keyed" transactions (where the note owner is an Ethereum address rather than a ZK public key), the owner must approve the transaction in the TransactionRegistry before submission. If this approval is missing, the transaction shouldn't have been included.

### Tree Update Fraud

Every deposit group and transaction updates the merkle tree by inserting new notes and computing a new root. The sequencer publishes the new root, and it must be computed correctly. If the sequencer publishes the wrong root, that's fraud.

#### Tree Structure and Hierarchy

The merkle tree has a two-level hierarchical structure that organizes notes by time:

**Root Tree (28 levels)**: The upper portion of the tree indexes blocks. Each block gets a unique position computed as `day × 8192 + block_index_within_day`. This uses 15 bits for the day number (supporting ~90 years) and 13 bits for the block-within-day index (up to 8,192 blocks per day). When a new calendar day begins, the block index resets to zero, placing that day's blocks in a fresh subtree.

**Block Tree (16 levels)**: Within each block's position in the root tree, there's a subtree that holds up to 65,536 notes. Notes are inserted sequentially starting from index 0.

Together this forms a 44-level tree where each note's position encodes when it was created: which day, which block that day, and which note within that block.

#### Frontier Insertion

Notes must be inserted at the tree's "frontier" - the first empty slot. The ZK circuit enforces this by proving:

1. **The slot before is non-empty** (or this is slot 0): Before inserting at index N, the circuit verifies that index N-1 contains a non-zero value. This prevents inserting into the middle of empty space.

2. **The target slots are empty**: The circuit verifies that indices N, N+1, and N+2 all contain zero before inserting the three new notes. This ensures you're actually extending the tree, not overwriting existing notes.

This frontier constraint is critical for tree consistency. Without it, a malicious sequencer could insert notes at arbitrary positions, breaking the append-only property that users rely on for merkle proofs.

#### Challenge Process

The challenger proves tree update fraud by:
1. Opening the blob data (the notes being inserted and the sequencer's claimed new root)
2. Providing the prior anchor (the root before this update)
3. Providing the block index (day × 8192 + index) to locate this block in the root tree
4. Generating a ZK proof that computes the correct new root by:
   - Verifying the frontier constraint (prior slot non-empty, target slots empty)
   - Inserting the three notes at the correct positions in the block subtree
   - Computing the new block root and updating the root tree
5. Demonstrating the sequencer's claimed root differs from the correctly computed one

This challenge is more expensive because it requires on-chain ZK proof verification in addition to KZG proofs, but it's essential for ensuring the merkle tree remains consistent and respects its hierarchical structure.

## The Challenge Process

All challenges follow a similar structure:

1. **Identify fraud**: The challenger (usually running an automated node) detects invalid data in a submitted block.

2. **Gather proofs**: The challenger retrieves blob data from the beacon chain and generates KZG proofs for the specific fields needed to demonstrate fraud.

3. **Submit challenge**: The challenger calls the appropriate challenge function with evidence. This is a regular Ethereum transaction that costs gas.

4. **Verification**: The contract validates all proofs and checks if fraud actually occurred. If not, the transaction reverts with "NoFraud".

5. **Slash and rollback**: If fraud is confirmed, the sequencer is slashed and the chain rolls back to the block before the fraudulent one. All blocks after the fraudulent block are also removed.

6. **Claim reward**: After the challenge window elapses, the challenger can claim 50% of the slashed stake.

## KZG Proofs

Blob data isn't directly accessible to smart contracts. To read values from blobs, challengers use KZG point evaluation proofs. These cryptographic proofs demonstrate that a specific field in a blob has a specific value.

For single values (like a deposit leaf), the challenger provides one proof. For multi-field data (like a complete 15-field transaction), the challenger provides a "region" containing multiple values and their corresponding proofs.

The EIP-4844 point evaluation precompile verifies these proofs in approximately 50,000 gas each. This is a significant cost component of challenge transactions.

## Rollback Mechanics

When fraud is proven, the chain must be rolled back. The challenger provides the BlockData of the block immediately before the fraudulent one. The contract:

1. Truncates the block array to remove the fraudulent block and everything after it
2. Restores the timestamp tracking to the prior block's values
3. Cleans up anchor index entries that no longer exist

This is a destructive operation that affects all blocks submitted after the fraud, even if those later blocks were valid. This creates strong incentives for sequencers to validate their own submissions carefully.

## Economic Incentives

The challenge game's economics are designed to make fraud unprofitable:

**Challenger reward**: 50% of the slashed stake goes to the challenger. This must exceed the gas cost of submitting challenges for challenging to be economically rational.

**Sequencer loss**: The sequencer loses 100% of their stake (50% to challenger, 50% burned). This means even colluding with a challenger results in net loss.

**Race to challenge**: If multiple challengers detect the same fraud, only the first successful challenge (by transaction inclusion) gets the reward. This creates urgency to submit quickly.

**Earliest fraud wins**: If a sequencer committed fraud in blocks 100 and 105, the challenger who proves the block 100 fraud gets the reward. This incentivizes finding the earliest fraud to maximize rollback.

## Implementation Considerations

### Cross-Blob Handling

Transactions can span blob boundaries. If a transaction starts at the end of blob N and continues into blob N+1, the challenger must provide data from both blobs. The challenge contracts handle this through "extension region" parameters. The extension region struct checks that it is at the start of a blob and that the prior region is at the end of a blob.

### Timing Constraints

Challenges must be submitted during the challenge window. If the window passes without a successful challenge, the block becomes confirmed and can no longer be challenged. Challengers should monitor blocks promptly and submit challenges well before the window closes.

### Multiple Frauds

A single block might contain multiple instances of fraud (e.g., wrong deposits AND invalid transactions). Only one successful challenge is needed to slash the sequencer and roll back - additional challenges after the first don't provide additional rewards.

## Running a Challenger

Anyone can run a challenger node. The off-chain challenger software:

1. Monitors for new block submissions (NewRoot events)
2. Retrieves blob data from the beacon chain
3. Validates all deposits, nullifiers, transactions, and tree updates
4. Generates KZG proofs for any detected fraud
5. Submits challenge transactions
6. Manages retries for failed submissions

Running a challenger is essential for network security. Even without fraud to detect, challengers serve as a deterrent - sequencers know that fraud will be caught and punished.

For detailed instructions on running a challenger, see the [Challenger Guide](../guides/challenger.md).
