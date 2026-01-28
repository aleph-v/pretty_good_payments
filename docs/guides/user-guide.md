# User Guide

This guide explains how to use Pretty Good Payments as an end user.

## Overview

Pretty Good Payments lets you:
1. **Deposit** ERC-20 tokens from Ethereum
2. **Transact** privately on Layer 2
3. **Withdraw** back to Ethereum

All L2 transactions are free - sequencers are paid through yield on deposited funds.

## Depositing

### Prerequisites

- ERC-20 tokens (e.g., USDC, DAI)
- ETH for gas (deposit transaction)
- A ZK keypair (or Ethereum address for eth-keyed accounts)

### Creating a Deposit

1. **Generate or import your keypair**
   ```
   privateKey = random 252-bit value
   publicKey = Poseidon(privateKey)
   ```

2. **Prepare the deposit leaf**
   ```
   leaf = {
     asset: tokenAddress,
     amount: depositAmount,
     blinding: CONSTANT,  // Set by contract
     publicKey: yourPublicKey
   }
   ```

3. **Approve and deposit**
   ```solidity
   // Approve token transfer
   IERC20(token).approve(entrypoint, amount);

   // Create deposit
   entrypoint.deposit(leaf);
   ```

4. **Wait for inclusion**
   - Your deposit targets block N+2 (or later if queue is full)
   - Sequencer must include it or face slashing
   - After the challenge period, your note is spendable

### Tracking Your Deposit

Listen for the `Deposit` event:
```solidity
event Deposit(bytes32 indexed leafHash, uint256 block, uint256 number);
```

Your note location:
- Block: `block` from event
- Index: Derived from block's tree index and deposit position

## Transacting

### Creating a Transaction

1. **Select input notes** (1-2 notes)
   - Must know: asset, amount, blinding, privateKey, noteIndex
   - Notes must have same asset type

2. **Create output notes** (1-3 notes)
   - Split value however you want
   - Total output = total input (no fees)
   - Set recipient's publicKey

3. **Compute nullifiers**
   ```
   nullifier = Poseidon(privateKey, blinding, noteIndex)
   ```

4. **Select anchor**
   - Choose a recent merkle root
   - Older roots = larger anonymity set

5. **Generate ZK proof**
   - Uses transfer.circom circuit
   - Proves membership, authorization, value conservation

6. **Submit to sequencer**
   ```
   POST /submit
   {
     proof: [...],
     anchorInfo: "...",
     nullifiers: [...],
     outputs: [...]
   }
   ```

### Transaction Data

```
Transaction = {
  proof: 8 field elements (Groth16)
  anchorInfo: encoded block/update reference
  nullifier0: first input nullifier
  nullifier1: second input nullifier (or 0)
  leaf0: first output hash
  leaf1: second output hash (or 0)
  leaf2: third output hash (or 0)
}
```

### Privacy Tips

- Use anchors from many blocks ago
- Don't transact immediately after depositing
- Split large amounts into multiple notes
- Avoid patterns in transaction timing

## Withdrawing

### Creating a Withdrawable Note

1. **Create a special output note**
   ```
   withdrawNote = {
     asset: tokenAddress,
     amount: withdrawAmount,
     blinding: destinationAddress,  // Your L1 address
     publicKey: 0  // Marks as withdrawable
   }
   ```

2. **Submit transaction normally**
   - Include withdraw note as one of the outputs
   - Other outputs can be regular notes

3. **Wait for finalization**
   - Block must pass the challenge period
   - Check: `entrypoint.isConfirmed(blockData)`

### Claiming Withdrawal

1. **Get block data**
   ```
   blockData = {
     anchor, timestamp, numTransactions, numDeposits,
     blockNr, blockIndex, sequencer, blobhashes
   }
   ```

2. **Generate KZG proof**
   - Proves your leaf exists in the blob
   - Requires blob commitment and point proof

3. **Call withdraw**
   ```solidity
   entrypoint.withdraw(
     leaf,        // Your note preimage
     blockData,   // Block containing the note
     txNr,        // Transaction index
     which,       // Output index (0, 1, or 2)
     commitment,  // KZG commitment
     proof        // KZG proof
   );
   ```

4. **Receive funds**
   - Tokens sent to `address(leaf.blinding)`
   - Minus any vault losses (rare)

## Ethereum-Keyed Accounts

For simpler UX, you can use your Ethereum address as the note owner.

### Creating Eth-Keyed Notes

Set the publicKey to your Ethereum address:
```
note = {
  asset: tokenAddress,
  amount: amount,
  blinding: randomValue,
  publicKey: yourEthAddress  // Must be < 160 bits
}
```

### Spending Eth-Keyed Notes

1. **Create transaction as normal**
2. **Sign the transaction data on L1**
   ```solidity
   // In TransactionRegistry
   bytes32[5] fields = [null0, null1, leaf0, leaf1, leaf2];
   registry.approve(fields);
   ```
3. **Submit transaction**
   - Sequencer checks registry for approval
   - Transaction included if approved

### Considerations

- **Less private**: Your Ethereum address is visible
- **More convenient**: Use existing wallet
- **Delegated management**: Others can consolidate notes for you

### Security Warning

Anyone who knows your blinding factor can merge/split your eth-keyed notes. Transfer to ZK-keyed notes after receiving.

## Wallet Integration

### Key Management

```javascript
// Generate new keypair
const privateKey = randomBytes(32);
const publicKey = poseidonHash([privateKey]);

// Store securely
localStorage.setItem('pgp_key', privateKey.toString('hex'));
```

### Note Tracking

Track your notes:
```javascript
const myNotes = [];

// On deposit
myNotes.push({
  asset, amount, blinding, publicKey,
  blockNr, index, spent: false
});

// On spend
const spentNote = myNotes.find(n => n.index === spentIndex);
spentNote.spent = true;

// On receive (from transaction output)
myNotes.push({
  asset, amount, blinding, publicKey,
  blockNr, txNr, outputIndex, spent: false
});
```

### Syncing State

To sync with the chain:

1. **Get latest block number**
   ```javascript
   const currentBlock = await entrypoint.getCurrentBlocknumber();
   ```

2. **Sync merkle tree**
   - Download day roots
   - Download block roots for current day
   - Download paths for your notes

3. **Check note status**
   - Verify notes exist in tree
   - Check nullifiers haven't been used

## Troubleshooting

### Deposit Not Appearing

1. Check transaction was mined
2. Wait for target block to be included
3. Wait for the challenge period to elapse
4. Check if sequencer included the deposit

### Transaction Rejected

Common reasons:
- Nullifier already spent
- Anchor reference too old/invalid
- ZK proof invalid
- Sequencer mempool full

### Withdrawal Failing

1. Verify block is confirmed
2. Check output index is correct
3. Verify KZG proof is valid
4. Ensure not already withdrawn

### Lost Private Key

If you lose your ZK private key:
- Notes are unrecoverable
- Eth-keyed notes can be recovered with Ethereum key
- Keep secure backups!

## Security Best Practices

1. **Backup your keys** securely
2. **Verify addresses** before sending
3. **Use multiple notes** for large amounts
4. **Wait before withdrawing** after deposits
5. **Keep software updated**
6. **Use hardware wallets** for eth-keyed accounts
