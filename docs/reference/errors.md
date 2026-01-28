# Error Reference

Complete reference for all custom errors in PGP contracts.

## Sequencer Errors

### `NotAllowed()`
Sequencer cannot submit in current window.

**Causes:**
- Not active sequencer
- Insufficient stake
- Wrong epoch period (closed/open mismatch)
- Not priority sequencer during closed period

**Resolution:**
- Register and stake sufficient ETH
- Wait for appropriate submission window

---

### `SequencerNotActive()`
Sequencer is not currently active.

**Causes:**
- Never registered
- Already exited
- Was slashed

---

### `AlreadyChallenged()`
Sequencer has already been challenged.

**Causes:**
- Attempting to stake after being challenged
- Fraud was detected

---

### `AlreadyStaked()`
Attempting to register when already staked.

---

### `ExitWindowNotElapsed()`
Exit delay hasn't passed yet.

**Causes:**
- Calling `exit()` before challenge window
- Must wait for CHALLENGE_WINDOW after `registerExit()`

---

## Block Errors

### `WrongNumberOfDeposits()`
Block deposit count doesn't match pending deposits. This error is thrown at submission time, rejecting the block before it enters the chain.

**Causes:**
- Sequencer's `numDeposits` doesn't match `perBlockDeposits[blockNr].length`

**Resolution:**
- Ensure you're including exactly the deposits pending for this block number

---

### `BlockNotIncluded()`
Referenced block is not in the chain.

**Causes:**
- Block hash doesn't match stored root
- Block was rolled back

---

### `BlockNotConfirmed()`
Block hasn't passed challenge period.

**Causes:**
- Attempting withdrawal before confirmation
- Must wait for CHALLENGE_WINDOW after block submission

---

### `TxIndexOutOfBounds()`
Transaction index exceeds `numTransactions`.

---

### `UpdateIndexOutOfBounds()`
Update index exceeds available updates.

---

## Challenge Errors

### `NoFraud()`
Challenge failed - no fraud detected.

**Causes:**
- Submitted data matches expected values
- Proof validates correctly

---

### `SameNullifierLocation()`
Nullifier challenge uses same location twice.

**Causes:**
- Both loaders point to same (block, tx, which)

---

### `InvalidNullifierOrder()`
First occurrence must be before second.

**Causes:**
- `first.blockNr > second.blockNr`

---

### `InvalidZKProof()`
ZK proof verification failed.

**Causes:**
- Proof doesn't match public inputs
- Corrupted proof data

---

### `InvalidAnchorBlockInfo()`
Prior anchor block info doesn't match.

**Causes:**
- Wrong block data provided
- Block number mismatch

---

### `ZeroEthKey()`
Transaction has zero eth key but proof is valid.

**Context:**
- In transaction challenge, if proof validates and eth key is zero, there's no fraud

---

### `ChallengeWindowNotElapsed()`
Cannot claim challenge reward yet.

**Causes:**
- Must wait for CHALLENGE_WINDOW after challenge

---

## Region Errors

### `EmptyRegion()`
Region has zero length.

---

### `RegionBlobHashMismatch()`
Region blob hash doesn't match block's blobhashes.

---

### `RegionMemoryAddressMismatch()`
Region start address doesn't match expected.

---

### `RegionLengthMismatch()`
Total region length doesn't match expected.

---

### `RegionNotAtBlobBoundary()`
Extension region required but main region doesn't end at blob boundary.

---

### `ExtensionMemoryNotZero()`
Extension region must start at address 0.

---

### `RegionDataLengthMismatch()`
Region data/proof arrays have wrong length.

---

## KZG Errors

### `InvalidProof()`
KZG point evaluation failed.

**Causes:**
- Proof doesn't validate against commitment
- Data mismatch at claimed index

---

## Deposit Errors

### `InvalidLeafWhich()`
Leaf index must be 0, 1, or 2.

---

### `InvalidNullifierWhich()`
Nullifier index must be 0 or 1.

---

### `InvalidDepositNumber()`
Deposit number exceeds range.

---

## Withdrawal Errors

### `AlreadyWithdrawn()`
Output has already been withdrawn.

---

### `PublicKeyNotZero()`
Cannot withdraw - `publicKey != 0`.

**Resolution:**
- Create transaction with `publicKey = 0` output first

---

## Yield Errors

### `NotBridge()`
Caller is not the bridge contract.

---

### `TokenNotTransferred()`
Expected tokens not received.

---

### `TokenNotEnabled()`
No yield source configured for token.

---

### `AlreadyPaid()`
Sequencer already claimed this epoch's yield.

---

### `SequencerChallenged()`
Cannot claim yield while challenged.

---

### `EpochNotFinished()`
Epoch hasn't ended yet.

---

## Error Handling

### In Solidity

```solidity
try entrypoint.post(data, indices) {
    // Success
} catch (bytes memory reason) {
    // Parse error
    if (bytes4(reason) == NotAllowed.selector) {
        // Handle not allowed
    }
}
```

### In Rust (Alloy)

```rust
match entrypoint.post(data, indices).call().await {
    Ok(_) => { /* Success */ }
    Err(e) => {
        if let Some(revert) = e.as_revert() {
            // Parse revert reason
        }
    }
}
```

### In JavaScript (Ethers)

```javascript
try {
    await entrypoint.post(data, indices);
} catch (error) {
    if (error.errorName === 'NotAllowed') {
        // Handle not allowed
    }
}
```
