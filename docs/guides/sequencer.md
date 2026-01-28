# Running a Sequencer

This guide explains how to run a PGP sequencer node.

## Overview

A sequencer:
- Accepts transactions from users
- Batches transactions into blobs
- Submits blocks to L1
- Earns yield from deposited funds

## Requirements

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 100 GB SSD | 500+ GB NVMe |
| Network | 100 Mbps | 1+ Gbps |

### Software

- Rust 1.70+
- Node.js 18+ (for snarkjs)
- Python 3.9+ (for KZG)
- Access to Ethereum RPC
- Access to beacon chain API

### Capital

- **Stake**: Required amount varies per network (check `requiredStake`)
- **Gas**: ETH for transaction fees
- **Buffer**: Extra ETH for gas price spikes

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
# Download verification keys and compiled circuits
mkdir -p circuits/outputs
cd circuits/outputs
# Download transfer and predictableUpdate circuits
```

## Configuration

Create a configuration file `config.toml`:

```toml
# Network
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
beacon_url = "https://beacon-mainnet.g.alchemy.com/v2/YOUR_KEY"
chain_id = 1

# Contracts
entrypoint_address = "0x..."
deposits_address = "0x..."

# Keys
private_key = "0x..."  # Or use environment variable

# Paths
database_path = "./pgp-state.db"
transfer_vk = "./circuits/outputs/transfer/transferVKey.json"
update_vk = "./circuits/outputs/predictableUpdate/predictableUpdateVKey.json"
snarkjs_path = "snarkjs"

# API
api_host = "0.0.0.0"
api_port = 8080

# Block building
min_transactions_per_block = 10
max_wait_seconds = 30
```

## Staking

Before running the sequencer, register and stake:

```bash
# Using cast
cast send $ENTRYPOINT "fund()" --value $REQUIRED_STAKE --private-key $PRIVATE_KEY

# Verify registration
cast call $ENTRYPOINT "sequencers(address)" $SEQUENCER_ADDRESS
```

### Priority Registration

To become a priority sequencer (optional):

```bash
# Owner must add you
cast send $ENTRYPOINT "addFirstLook(address)" $SEQUENCER_ADDRESS --private-key $OWNER_KEY
```

## Running

### Start the Sequencer

```bash
./target/release/sequencer --config config.toml
```

### With Environment Variables

```bash
PGP_PRIVATE_KEY=0x... \
PGP_RPC_URL=https://... \
./target/release/sequencer --config config.toml
```

### As a Systemd Service

Create `/etc/systemd/system/pgp-sequencer.service`:

```ini
[Unit]
Description=PGP Sequencer
After=network.target

[Service]
Type=simple
User=pgp
WorkingDirectory=/opt/pgp
ExecStart=/opt/pgp/sequencer --config /opt/pgp/config.toml
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable pgp-sequencer
sudo systemctl start pgp-sequencer
```

## API Endpoints

The sequencer exposes these endpoints:

### POST /submit

Submit a transaction:

```bash
curl -X POST http://localhost:8080/submit \
  -H "Content-Type: application/json" \
  -d '{
    "proof": [...],
    "anchor_info": "0x...",
    "nullifier0": "0x...",
    "nullifier1": "0x...",
    "leaf0": "0x...",
    "leaf1": "0x...",
    "leaf2": "0x..."
  }'
```

### POST /poke

Force immediate block submission:

```bash
curl -X POST http://localhost:8080/poke
```

### GET /stats

Get mempool statistics:

```bash
curl http://localhost:8080/stats
```

Response:
```json
{
  "pending": 150,
  "max_pending": 10000,
  "oldest_age_ms": 5000,
  "blobs_worth": 0,
  "pending_nullifiers": 300
}
```

### GET /health

Health check:

```bash
curl http://localhost:8080/health
```

## Block Building

The sequencer builds blocks automatically:

### Trigger Conditions

1. **Full blob**: 273+ transactions ready
2. **Poke**: Manual trigger via API
3. **Timeout**: Max wait time exceeded (configurable)

### Block Submission Flow

```
1. Wait for submission window
   - Priority sequencer: Closed period of assigned epoch
   - Regular sequencer: Open period of any epoch

2. Fetch pending deposits from contract

3. Take transactions from mempool

4. Build blob data:
   - Layout deposits
   - Layout transactions
   - Compute merkle updates

5. Create blob transaction

6. Submit to L1 and wait for receipt

7. Verify NewRoot event
```

### Multi-Blob Blocks

If data exceeds one blob (4096 fields):

```
Blob 1: [deposits][transactions 0-272]
Blob 2: [transactions 273-545]
...
```

Up to 6 blobs per transaction (EIP-4844 limit).

## Monitoring

### Logs

Watch logs for:

```
# Successful submission
INFO Block 1234 submitted successfully (hash: 0x...)

# Waiting for window
DEBUG Waiting for submission window...

# Mempool status
INFO Mempool: 150 pending, 2 blobs worth
```

### Metrics

Track these metrics:

| Metric | Description |
|--------|-------------|
| `pending_transactions` | Mempool size |
| `blocks_submitted` | Total blocks submitted |
| `submission_latency_ms` | Time to submit block |
| `gas_used` | Gas per submission |
| `blob_usage_percent` | How full blobs are |

### Alerts

Set up alerts for:

- Mempool growing too large
- Submission failures
- Gas price spikes
- Challenger events
- Low ETH balance

## Epoch Management

### Priority Sequencers

If you're a priority sequencer:

```
Epoch Structure:
|<-- Closed (half) -->|<-- Open (half) -->|
        Your turn              Anyone

Benefits:
- Exclusive window
- 2x yield credit
- No competition
```

### Regular Sequencers

```
Strategy:
- Monitor open period start
- Submit quickly when window opens
- Have transactions ready
- Consider gas price competition
```

## Yield Collection

### Checking Earnings

```bash
cast call $ENTRYPOINT "getPercentInEpoch(address,uint256)" $ADDRESS $EPOCH
```

### Claiming Yield

```bash
cast send $YIELD_ROUTER "withdrawMany(address,uint256[])" \
  $ADDRESS "[100,101,102]" \
  --private-key $PRIVATE_KEY
```

## Exiting

### Graceful Exit

1. Stop accepting transactions
2. Submit remaining blocks
3. Register exit:
   ```bash
   cast send $ENTRYPOINT "registerExit()" --private-key $PRIVATE_KEY
   ```
4. Wait for the challenge period to elapse
5. Claim stake:
   ```bash
   cast send $ENTRYPOINT "exit(address)" $ADDRESS
   ```

### Emergency Considerations

- If challenged, stake is at risk
- Cannot exit while challenged
- Claim any pending yield before exiting

## Troubleshooting

### Transaction Rejected

Check:
- Nullifier not already spent
- Anchor reference valid
- ZK proof verifies
- Mempool not full

### Block Submission Failed

Check:
- Sufficient ETH for gas
- Within submission window
- Deposit count matches
- Network connectivity

### Slashed

If you see challenge events:
- Stop submitting immediately
- Investigate the fraud claim
- If legitimate, stake is forfeit
- If false, contact team

### Sync Issues

If falling behind:
- Check RPC endpoint health
- Verify beacon API connectivity
- Check database integrity
- Consider increasing resources
