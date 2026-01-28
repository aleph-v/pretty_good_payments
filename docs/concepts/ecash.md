# Private E-Cash System

Pretty Good Payments uses a simplified version of the Zcash private e-cash model. This document explains how notes work, how they're spent, and the privacy guarantees.

## Notes

Notes are the fundamental unit of value in PGP. Each note represents ownership of tokens.

### Note Structure

```
Note = [asset_id, amount, blinding, publicKey]

- asset_id:  252 bits - ERC-20 token address
- amount:    180 bits - Token amount
- blinding:  252 bits - Random factor for hiding
- publicKey: 252 bits - Hash of spending key
```

Notes are stored as Poseidon hashes in the merkle tree:

```
noteHash = Poseidon(asset_id, amount, blinding, publicKey)
```

### Spending Keys

A note can be spent by anyone who knows the preimage of `publicKey`:

- **Private key**: Any 252-bit value
- **Public key**: `Poseidon(privateKey)`

## Merkle Tree Structure

Notes are organized in a predictable sparse merkle tree with total depth of 44 levels:

```
                         Anchor (Root)
                              |
              +---------------+---------------+
              |                               |
           Day 0                           Day 1 ...
              |                        (2^15 = 32,768 days)
    +---------+---------+
    |                   |
 Block 0            Block 1 ...
    |              (2^13 = 8,192 blocks per day)
+---+---+
|       |
Note   Note ...
   (2^16 = 65,536 notes per block)
```

### Tree Indexing

The 44-bit note index is composed of three parts:

| Component | Bits | Capacity |
|-----------|------|----------|
| Day index | 15 bits | 32,768 days (~90 years) |
| Block within day | 13 bits | 8,192 blocks per day |
| Note within block | 16 bits | 65,536 notes per block |

```
Note Index (44 bits) = [day (15)] [block (13)] [note (16)]
```

This structure enables efficient syncing - users only need to track:
- Root hashes for each day
- Within the current day, block roots
- Within the current block, individual notes

## Transaction Flow

### Creating a Transaction

1. **Select input notes** (up to 2)
2. **Create output notes** (up to 3)
3. **Compute nullifiers** for inputs
4. **Generate ZK proof** proving:
   - Input notes exist in the tree
   - Prover knows the private keys
   - Outputs have same total value as inputs
   - Nullifiers are correctly computed

```
Transaction = [
    zkProof[8],      // Groth16 proof (8 field elements)
    anchorInfo,      // Reference to merkle root
    nullifier0,      // First input nullifier
    nullifier1,      // Second input nullifier
    leaf0,           // First output note hash
    leaf1,           // Second output note hash
    leaf2,           // Third output note hash
    newRoot          // Merkle root after adding outputs
]
```

### ZK Proof Public Inputs

The transfer circuit has these public inputs:

```
publicInputs = [
    nullifier0,
    nullifier1,
    leaf0,
    leaf1,
    leaf2,
    anchor,      // Merkle root reference
    ethKey       // For Ethereum-keyed accounts
]
```

## Nullifiers

Nullifiers prevent double-spending. Each input note has a unique nullifier:

```
nullifier = Poseidon(privateKey, blinding, noteIndex)
```

Properties:
- **Unique**: Same note always produces same nullifier
- **Unlinkable**: Cannot connect nullifier to note without private key
- **Deterministic**: No randomness in computation

The contract tracks all used nullifiers. Any attempt to reuse triggers a challenge.

## Blinding Factors

The blinding factor serves multiple purposes:

### 1. Transaction Privacy

New notes derive blinding from inputs:

```
newBlinding = Poseidon(userRandom, Poseidon(inputNote1Hash, inputNote2Hash))
```

This creates a chain of derivation that's hidden without knowing the random values.

### 2. Deposit Blinding

Deposits use a constant blinding:

```solidity
bytes32 public constant BLINDING = keccak256("0x") % BLS_MODULUS;
```

This is required for ZK circuit compatibility with deposit proofs.

### 3. Withdrawal Address

For withdrawals, the blinding field encodes the destination:

```
withdrawNote.publicKey = 0  // Marks note as withdrawable
withdrawNote.blinding = destinationAddress
```

## Ethereum-Keyed Accounts

Notes can be controlled by Ethereum addresses instead of ZK private keys.

### How It Works

1. Set `privateKey` to an Ethereum address (< 160 bits)
2. Transaction requires L1 approval in TransactionRegistry
3. User signs `[nullifiers, outputLeaves]` on L1
4. Sequencer includes approval in block

### Use Cases

- **Simplified UX**: Use existing wallet without ZK key management
- **Delegated management**: Let a service consolidate payments
- **Cross-chain**: Prove L1 ownership for L2 actions

### Privacy Trade-offs

| Feature | Full ZK | Eth-Keyed |
|---------|---------|-----------|
| Sender privacy | Yes | No (address visible) |
| Receiver privacy | Yes | Yes |
| Amount privacy | Yes | Yes (unless blinding leaked) |
| Transfer history | Hidden | Partially visible |

### Security Warnings

- Eth-keyed notes can be merged/split by anyone knowing the blinding
- Recommend transferring to private ZK notes after receiving
- The zero address (0x0) has special handling - anyone can spend

## Anchor References

Transactions reference a merkle root (anchor) to prove note membership:

- Pick recent anchors and update your proofs to reference them for maxium anonymity set
- Cross-block references are allowed
- Within same block, can reference prior updates

### Anchor Info Encoding

```
anchorInfo (32 bytes) = [
    isDeposit  (1 bit at position 254),
    blockNr    (32 bits at position 222),
    updateNr   (32 bits at position 190),
    ethKey     (160 bits at position 0)
]
```

## Deposits

### Deposit Flow

```
1. User calls deposit(leaf) on Entrypoint
2. Tokens transferred to YieldRouter
3. Leaf hash recorded in perBlockDeposits[targetBlock]
4. Sequencer MUST include deposit or face challenge
5. Deposit becomes note in merkle tree
```

### Deposit Targeting

Deposits target future blocks to give sequencers time:

```
targetBlock = max(highestDeposit, currentBlock + 2)
```

### Deposit Groups

Deposits are batched in groups of 3:

```
DepositGroup = [leaf0, leaf1, leaf2, groupRoot]
```

The groupRoot is computed by updating the merkle tree with all 3 leaves. Note that if the last leaves are zero then the next update starts at the most recent nonzero leaf.

## Withdrawals

### Creating a Withdrawable Note

1. Create transaction with output where `publicKey = 0`
2. Set `blinding = destinationAddress`
3. Submit transaction normally

### Withdrawal Process

```
1. Wait for block finalization (challenge period)
2. Call withdraw() with:
   - Leaf preimage (asset, amount, blinding, publicKey=0)
   - Block data
   - Transaction index and output index
   - KZG commitment and proof
3. Contract validates:
   - Block is confirmed
   - Not already withdrawn
   - KZG proof valid
   - publicKey == 0
4. Funds sent to address(blinding)
```

## Privacy Best Practices

### Maximizing Privacy

1. **Use new anchors**: Reference roots as near to the withdraw time as possible, avoid referencing in block anchors.
2. **Avoid patterns**: Don't withdraw immediately after deposit.
3. **Use full ZK**: Avoid eth-keyed accounts when possible
4. **Do more on the L2** The more you do on the L2 the less info you leak, the system is not built for deposit withdraw flows.

### What's Hidden

- Sender identity
- Receiver identity
- Transaction amounts
- Transaction graph

### What's Visible

- Block contains a transaction
- Number of outputs (1-3)
- Eth-keyed sender address (if used)
- Deposit and withdrawal amounts/addresses on L1
