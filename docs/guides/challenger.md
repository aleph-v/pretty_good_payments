# Running a Challenger

This guide explains how to run a PGP challenger node to monitor for fraud and earn rewards.

## Overview

A challenger:
- Monitors NewRoot events
- Fetches and validates blob data
- Detects fraudulent blocks
- Submits challenge transactions
- Earns 50% of slashed stakes

## Requirements

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 500 GB SSD | 1+ TB NVMe |
| Network | 100 Mbps | 1+ Gbps |

Storage is critical for:
- Blob data caching
- Nullifier database
- Block history

### Software

- Rust 1.70+
- Node.js 18+ (for snarkjs ZK proofs)
- Python 3.9+ (for KZG proofs)
- Access to Ethereum RPC
- Access to beacon chain API

### Capital

- **Gas**: ETH for challenge transactions (~200k-700k gas each)
- **No stake required**: Anyone can challenge

## Installation

### 1. Clone and Build

```bash
git clone https://github.com/your-org/pretty_good_payments.git
cd pretty_good_payments/offchain
cargo build --release
```

### 2. Install Dependencies

```bash
# Python dependencies
pip install ckzg eth-abi

# Node.js dependencies
npm install -g snarkjs
```

### 3. Download Circuit Files

```bash
mkdir -p circuits/outputs
cd circuits/outputs

# Download predictableUpdate circuit for tree update challenges
# - predictableUpdate.wasm
# - predictableUpdate.zkey
# - predictableUpdateVKey.json

# Download transfer circuit verification key
# - transferVKey.json
```

## Configuration

Create `config.toml`:

```toml
# Network
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
beacon_url = "https://beacon-mainnet.g.alchemy.com/v2/YOUR_KEY"
chain_id = 1

# Contracts
entrypoint_address = "0x..."
deposits_address = "0x..."
transaction_registry_address = "0x..."

# Paths
database_path = "./pgp-state.db"
transfer_vk = "./circuits/outputs/transfer/transferVKey.json"
update_vk = "./circuits/outputs/predictableUpdate/predictableUpdateVKey.json"
circuit_wasm = "./circuits/outputs/predictableUpdate/predictableUpdate.wasm"
circuit_zkey = "./circuits/outputs/predictableUpdate/predictableUpdate.zkey"
snarkjs_path = "snarkjs"

# Challenge settings
dry_run = false  # Set true to validate without submitting
max_challenge_retries = 3
blob_cache_size = 1000

# Private key for challenge submission
private_key = "0x..."  # Or use environment variable
```

## Running

### Basic Start

```bash
./target/release/challenger --config config.toml
```

### Dry Run Mode

Validate without submitting challenges (for testing):

```bash
./target/release/challenger --config config.toml --dry-run
```

### With Environment Variables

```bash
PGP_PRIVATE_KEY=0x... \
PGP_RPC_URL=https://... \
./target/release/challenger --config config.toml
```

### As a Systemd Service

Create `/etc/systemd/system/pgp-challenger.service`:

```ini
[Unit]
Description=PGP Challenger
After=network.target

[Service]
Type=simple
User=pgp
WorkingDirectory=/opt/pgp
ExecStart=/opt/pgp/challenger --config /opt/pgp/config.toml
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable pgp-challenger
sudo systemctl start pgp-challenger
```

## Validation Process

### Event Monitoring

The challenger listens for:

```solidity
event NewRoot(
    BlockWithHash data,  // Block data + L2 hash
    bytes32 anchor       // New merkle root
);
```

### Per-Block Validation

For each new block:

1. **Fetch expected deposits**
   ```rust
   let deposits = fetch_expected_deposits(block_nr).await?;
   ```

2. **Retrieve blob data**
   ```rust
   let blobs = blob_provider.get_blobs(l1_block, blobhashes).await?;
   ```

3. **Parse blob content**
   ```rust
   let parsed = ParsedBlock::from_blobs(&blobs, num_deposits, num_txs)?;
   ```

4. **Run validators**
   - Deposit validator
   - Nullifier validator
   - Transaction validator
   - Tree update validator

5. **Submit challenges** (if fraud found)

### Fraud Types Detected

| Type | Detection Method |
|------|------------------|
| Wrong deposit leaf | Compare blob vs L1 contract |
| Deposit padding | Check unused slots are zero |
| Double-spend | Track all nullifiers |
| Invalid ZK proof | Verify Groth16 proof |
| Invalid anchor | Check reference exists |
| Missing eth-key auth | Query registry |
| Wrong tree update | Compute correct root via ZK |

## Challenge Submission

### Building Challenges

Each fraud type requires different data:

**Deposit Challenge**:
```rust
ChallengeBuilder::build_deposit_challenge(
    fraud_evidence,
    blob_data,
    prior_block
)
```

**Nullifier Challenge**:
```rust
ChallengeBuilder::build_nullifier_challenge(
    fraud_evidence,
    first_block_blobs,
    second_block_blobs,
    first_block_data,
    second_block_data,
    prior_block
)
```

**Transaction Challenge**:
```rust
ChallengeBuilder::build_transaction_challenge(
    fraud_evidence,
    current_blobs,
    anchor,
    anchor_block,
    anchor_blobs,
    anchor_field_index,
    prior_block
)
```

**Tree Update Challenge**:
```rust
// Generate ZK proof first
let (true_anchor, zk_proof) = snarkjs_prover
    .generate_update_proof(
        prior_anchor,
        block_root_before,
        leaves,
        block_index,
        in_block_index,
        nonzero_field,
        block_proofs,
        root_path
    ).await?;

ChallengeBuilder::build_tree_update_challenge(
    fraud_evidence,
    current_blobs,
    prior_anchor,
    prior_anchor_blobs,
    prior_anchor_field_index,
    true_anchor,
    zk_proof,
    prior_block
)
```

### Retry Logic

Failed challenges are queued for retry:

```rust
// On failure
state.save_pending_challenge(
    block_nr,
    l1_block_number,
    fraud_type,
    serialized_data,
    error_message
)?;

// Periodic retry
challenger.retry_pending_challenges().await?;
```

## Database

The challenger maintains persistent state:

### Tables

```sql
-- Track processing progress
state: key -> value

-- Store known nullifiers
nullifiers: hash -> (block_nr, tx_index, which)

-- Store anchors for lookup
anchors: (block_nr, update_nr, is_deposit) -> anchor

-- Cache block data
blocks: block_nr -> (l1_block_number, data)

-- Track root tree
block_roots: tree_index -> (block_nr, root)

-- Pending challenge queue
pending_challenges: id -> challenge_data
```

### Backup

Regularly backup the database:

```bash
sqlite3 challenger.db ".backup backup.db"
```

## Blob Storage

### Caching Strategy

```
Request blob -> Check memory cache
                     |
                     v
              Check database cache
                     |
                     v
              Fetch from beacon chain
                     |
                     v
              Store in caches
```

### Beacon Chain Requirements

The beacon chain only stores blobs for ~18 days. For historical blobs:
- Run your own beacon archive
- Use a blob archival service
- Cache blobs locally as they arrive

## Monitoring

### Logs

Key log messages:

```
# Successful validation
INFO Block 1234 validated successfully

# Fraud detected
WARN Detected 1 deposit fraud(s) in block 1234

# Challenge submitted
INFO Deposit challenge submitted: 0x...

# Blob retrieval
DEBUG Retrieved 2 blob(s) for block 1234
```

### Metrics

Track:

| Metric | Description |
|--------|-------------|
| `blocks_validated` | Total blocks checked |
| `fraud_detected` | Fraud instances found |
| `challenges_submitted` | Challenges sent |
| `challenges_successful` | Challenges that succeeded |
| `blob_cache_hits` | Cache hit rate |

### Alerts

Set up alerts for:

- Validation errors
- Challenge submission failures
- Database errors
- Beacon API connectivity issues
- Memory/disk usage

## Claiming Rewards

### After Successful Challenge

1. Wait for challenge window to elapse:
   ```bash
   cast call $ENTRYPOINT "sequencers(address)" $SLASHED_SEQUENCER
   # Check timestampChallenged
   ```

2. Claim reward:
   ```bash
   cast send $ENTRYPOINT "claimChallengeReward(address)" $SLASHED_SEQUENCER \
     --private-key $PRIVATE_KEY
   ```

3. Receive 50% of slashed stake

### Multiple Challengers

If multiple challengers detect the same fraud:
- First challenger (by transaction inclusion) wins
- Others get nothing
- Submit challenges quickly!

## Troubleshooting

### Blob Retrieval Failing

```
ERROR Failed to retrieve blobs: ...
```

Check:
- Beacon API connectivity
- Block is within 18-day window
- Blob hashes are correct

### ZK Proof Generation Failing

```
ERROR Failed to generate update proof: ...
```

Check:
- snarkjs is installed
- Circuit files are present
- Input data is valid

### Database Errors

```
ERROR Database error: ...
```

Check:
- Disk space
- File permissions
- Database integrity: `sqlite3 db "PRAGMA integrity_check"`

### Out of Sync

If falling behind:

1. Check last processed block:
   ```bash
   sqlite3 challenger.db "SELECT value FROM state WHERE key='last_processed_block'"
   ```

2. Compare with chain:
   ```bash
   cast call $ENTRYPOINT "getCurrentBlocknumber()"
   ```

3. If far behind, consider:
   - Increasing resources
   - Running multiple instances
   - Parallel validation

### False Positives

If detecting fraud that isn't fraud:
- Check your circuit files match contract
- Verify verification keys are correct
- Check database isn't corrupted
- Run in dry-run mode to debug

## Advanced Configuration

### Multiple Challengers

Run challengers with different focus:

```toml
# challenger-deposits.toml
validators = ["deposits"]

# challenger-nullifiers.toml
validators = ["nullifiers"]

# challenger-full.toml
validators = ["deposits", "nullifiers", "transactions", "tree_updates"]
```

### High Availability

For production:
- Run multiple challenger instances
- Use separate RPC endpoints
- Geographic distribution
- Automatic failover
