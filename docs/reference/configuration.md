# Configuration Reference

Complete configuration reference for PGP off-chain components.

## Sequencer Configuration

### Configuration File (TOML)

```toml
# =============================================================================
# Network Configuration
# =============================================================================

# Ethereum RPC endpoint (required)
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"

# Beacon chain API endpoint (required for blob retrieval)
beacon_url = "https://beacon-mainnet.g.alchemy.com/v2/YOUR_KEY"

# Chain ID (required)
chain_id = 1

# =============================================================================
# Contract Addresses
# =============================================================================

# Entrypoint contract address (required)
entrypoint_address = "0x..."

# Deposits contract address (usually same as entrypoint)
deposits_address = "0x..."

# Transaction registry address (for eth-keyed transactions)
transaction_registry_address = "0x..."

# =============================================================================
# Keys
# =============================================================================

# Sequencer private key (required)
# Can also be set via PGP_PRIVATE_KEY environment variable
private_key = "0x..."

# =============================================================================
# Paths
# =============================================================================

# Database path for state persistence
# IMPORTANT: Sequencer and challenger MUST share the same database
# The sequencer uses it for mempool validation (nullifiers, anchors)
# The challenger uses it to track processed blocks and detected fraud
database_path = "./pgp-state.db"

# ZK verification key paths
transfer_vk = "./circuits/outputs/transfer/transferVKey.json"
update_vk = "./circuits/outputs/predictableUpdate/predictableUpdateVKey.json"

# Snarkjs binary path
snarkjs_path = "snarkjs"

# =============================================================================
# API Configuration
# =============================================================================

# API server host
api_host = "0.0.0.0"

# API server port
api_port = 8080

# =============================================================================
# Block Building
# =============================================================================

# Minimum transactions before building block (optional)
min_transactions_per_block = 10

# Maximum wait time before forcing block submission (seconds)
max_wait_seconds = 30

# Use SimpleCoder for blob encoding (for Anvil testing only)
anvil_mode = false

# =============================================================================
# Mempool
# =============================================================================

# Maximum pending transactions
max_pending = 10000

# =============================================================================
# Blob Cache
# =============================================================================

# Number of blobs to cache in memory
blob_cache_size = 100
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PGP_PRIVATE_KEY` | Sequencer private key | `0x...` |
| `PGP_RPC_URL` | Override RPC URL | `https://...` |
| `PGP_BEACON_URL` | Override beacon URL | `https://...` |
| `RUST_LOG` | Log level | `info`, `debug`, `trace` |

---

## Challenger Configuration

### Configuration File (TOML)

```toml
# =============================================================================
# Network Configuration
# =============================================================================

rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
beacon_url = "https://beacon-mainnet.g.alchemy.com/v2/YOUR_KEY"
chain_id = 1

# =============================================================================
# Contract Addresses
# =============================================================================

entrypoint_address = "0x..."
deposits_address = "0x..."
transaction_registry_address = "0x..."

# =============================================================================
# Keys (for challenge submission)
# =============================================================================

# Private key for submitting challenges
# Can also be set via PGP_PRIVATE_KEY environment variable
private_key = "0x..."

# =============================================================================
# Paths
# =============================================================================

# Database path for persistent state
# IMPORTANT: Must be the same database used by the sequencer
database_path = "./pgp-state.db"

# ZK verification keys
transfer_vk = "./circuits/outputs/transfer/transferVKey.json"
update_vk = "./circuits/outputs/predictableUpdate/predictableUpdateVKey.json"

# Circuit files for tree update challenge proofs
circuit_wasm = "./circuits/outputs/predictableUpdate/predictableUpdate.wasm"
circuit_zkey = "./circuits/outputs/predictableUpdate/predictableUpdate.zkey"

# Snarkjs binary path
snarkjs_path = "snarkjs"

# =============================================================================
# Challenge Settings
# =============================================================================

# Dry run mode - validate but don't submit challenges
dry_run = false

# Maximum retry attempts for failed challenges
max_challenge_retries = 3

# =============================================================================
# Blob Storage
# =============================================================================

# Number of blobs to cache in memory
blob_cache_size = 1000
```

---

## Common Configuration

### Logging

Control log output with `RUST_LOG`:

```bash
# Basic info logs
RUST_LOG=info ./sequencer

# Debug logs for specific module
RUST_LOG=pgp_sequencer=debug ./sequencer

# Trace all
RUST_LOG=trace ./sequencer

# Multiple levels
RUST_LOG=info,pgp_challenger::validators=debug ./challenger
```

### Database

SQLite database options:

```toml
# File-based (persistent)
database_path = "./data/pgp.db"

# In-memory (testing only)
database_path = ":memory:"
```

---

## Contract Configuration

### Foundry (foundry.toml)

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
ffi = true
via_ir = true
optimizer = true
optimizer_runs = 20000

# File system permissions
fs_permissions = [
  { access = "read", path = "./" },
  { access = "read", path = "/tmp" },
  { access = "write", path = "./config" }
]

# Lints to ignore
[lint]
exclude_lints = [
    "mixed-case-variable",
    "mixed-case-function"
]

# Production profile with external Poseidon libraries
[profile.production]
libraries = [
    "lib/poseidon-solidity/contracts/PoseidonT3.sol:PoseidonT3:0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93",
    "lib/poseidon-solidity/contracts/PoseidonT5.sol:PoseidonT5:0x555333f3f677Ca3930Bf7c56ffc75144c51D9767"
]
```

---

## Network-Specific Settings

### Mainnet

```toml
chain_id = 1
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/..."
beacon_url = "https://beacon-mainnet.g.alchemy.com/v2/..."

# Use production blob encoding
anvil_mode = false

# Longer timeouts for reliability
submission_timeout_seconds = 60
```

### Sepolia Testnet

```toml
chain_id = 11155111
rpc_url = "https://eth-sepolia.g.alchemy.com/v2/..."
beacon_url = "https://beacon-sepolia.g.alchemy.com/v2/..."

anvil_mode = false
```

### Local (Anvil)

```toml
chain_id = 31337
rpc_url = "http://localhost:8545"
beacon_url = "http://localhost:5052"  # If running beacon simulator

# Required for Anvil blob handling
anvil_mode = true
```

---

## Security Configuration

### Private Key Handling

**Recommended: Environment Variable**
```bash
export PGP_PRIVATE_KEY="0x..."
./sequencer --config config.toml
```

**Alternative: File with Permissions**
```bash
chmod 600 /path/to/key.txt
./sequencer --config config.toml --key-file /path/to/key.txt
```

**Never:**
- Commit private keys to git
- Log private keys
- Store in plaintext config files

### Network Security

```toml
# API binding - localhost only for internal access
api_host = "127.0.0.1"

# Use TLS proxy (nginx, traefik) for external access
```

---

## Performance Tuning

### High Throughput

```toml
# Larger mempool
max_pending = 50000

# Larger blob cache
blob_cache_size = 5000

# Build blocks more frequently
max_wait_seconds = 15
min_transactions_per_block = 100
```

### Low Latency

```toml
# Smaller batches, faster submission
min_transactions_per_block = 1
max_wait_seconds = 5

# More responsive API
api_worker_threads = 8
```

### Memory Constrained

```toml
# Smaller caches
blob_cache_size = 100
max_pending = 5000

# Use disk-backed database
database_path = "/data/pgp.db"
```

---

## Configuration Validation

The sequencer validates configuration on startup:

```
INFO Validating configuration...
INFO   RPC URL: https://eth-mainnet...
INFO   Chain ID: 1
INFO   Entrypoint: 0x...
INFO   Database: ./sequencer.db
INFO Configuration valid
```

Check for:
- Valid URLs
- Existing file paths
- Valid addresses (checksum)
- Reasonable numeric values
