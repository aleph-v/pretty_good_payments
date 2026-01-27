//! Configuration loading with TOML files and environment variable overrides.

use alloy_primitives::Address;
use eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Common configuration shared between challenger and sequencer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonConfig {
    /// Ethereum RPC endpoint URL
    pub rpc_url: String,
    /// Chain ID for transaction signing
    pub chain_id: u64,
    /// Entrypoint contract address
    pub entrypoint_address: Address,
    /// Deposits contract address
    pub deposits_address: Address,
    /// Path to the circuits directory (for verification keys)
    pub circuits_path: Option<String>,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 31337, // Anvil default
            entrypoint_address: Address::ZERO,
            deposits_address: Address::ZERO,
            circuits_path: None,
        }
    }
}

/// Challenger-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengerConfig {
    /// Common configuration
    #[serde(flatten)]
    pub common: CommonConfig,
    /// Private key for signing challenge transactions (hex-encoded)
    pub private_key: Option<String>,
    /// Path to SQLite database for nullifier tracking
    #[serde(default = "default_database_path")]
    pub database_path: String,
    /// Whether to only monitor without submitting challenges
    #[serde(default)]
    pub dry_run: bool,
    /// Polling interval for new blocks (milliseconds)
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// Number of confirmations before processing a block
    #[serde(default = "default_confirmations")]
    pub confirmations: u64,
    /// Number of blocks to look back on startup for catching up
    #[serde(default = "default_lookback_blocks")]
    pub lookback_blocks: u64,
    /// TransactionRegistry contract address for eth-key authorization queries
    pub transaction_registry_address: Option<Address>,
    /// Path to transfer circuit verification key (snarkjs JSON)
    pub transfer_verification_key: Option<String>,
    /// Path to predictableUpdate circuit verification key (snarkjs JSON)
    pub update_verification_key: Option<String>,
    /// Path to snarkjs command (e.g., "npx snarkjs")
    pub snarkjs_path: Option<String>,
    /// Path to predictableUpdate circuit WASM
    pub circuit_wasm_path: Option<String>,
    /// Path to predictableUpdate circuit zkey
    pub circuit_zkey_path: Option<String>,
    /// Beacon chain API URL (for blob retrieval)
    pub beacon_api_url: Option<String>,
    /// Maximum retry attempts for failed challenge submissions
    #[serde(default = "default_max_challenge_retries")]
    pub max_challenge_retries: u32,
    /// Number of blobs to cache in memory (reduces beacon chain/database lookups)
    #[serde(default = "default_blob_cache_size")]
    pub blob_cache_size: usize,
}

fn default_database_path() -> String {
    "challenger.db".to_string()
}

fn default_poll_interval_ms() -> u64 {
    1000
}

fn default_confirmations() -> u64 {
    6
}

fn default_lookback_blocks() -> u64 {
    1000
}

fn default_max_challenge_retries() -> u32 {
    5
}

fn default_blob_cache_size() -> usize {
    16
}

impl Default for ChallengerConfig {
    fn default() -> Self {
        Self {
            common: CommonConfig::default(),
            private_key: None,
            database_path: "challenger.db".to_string(),
            dry_run: false,
            poll_interval_ms: 1000,
            confirmations: 6,      // 6 confirmations is safer for production (was 1)
            lookback_blocks: 1000, // Look back further for recovery (was 100)
            transaction_registry_address: None,
            transfer_verification_key: None,
            update_verification_key: None,
            snarkjs_path: None,
            circuit_wasm_path: None,
            circuit_zkey_path: None,
            beacon_api_url: None,
            max_challenge_retries: 5, // Maximum retry attempts for failed challenges
            blob_cache_size: 16,      // Cache ~2MB of blobs (16 * 131KB)
        }
    }
}

/// Sequencer-specific configuration
///
/// The sequencer also runs challenger logic to track state and validate blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerConfig {
    /// Common configuration
    #[serde(flatten)]
    pub common: CommonConfig,
    /// Private key for signing block submission transactions (hex-encoded)
    pub private_key: Option<String>,
    /// REST API listen address
    pub api_listen_addr: String,
    /// Maximum transactions per block
    pub max_tx_per_block: usize,
    /// Block building interval (milliseconds)
    pub block_interval_ms: u64,
    /// Minimum transactions to build a block (0 = always build)
    pub min_tx_per_block: usize,

    // === Integrated challenger configuration ===
    /// Path to SQLite database for state tracking (shared with challenger logic)
    #[serde(default = "default_sequencer_database_path")]
    pub database_path: String,
    /// Beacon chain API URL (for blob retrieval during validation)
    pub beacon_api_url: Option<String>,
    /// Number of confirmations before processing a block for validation
    #[serde(default = "default_sequencer_confirmations")]
    pub confirmations: u64,
    /// Number of blocks to look back on startup for state recovery
    #[serde(default = "default_sequencer_lookback_blocks")]
    pub lookback_blocks: u64,
    /// Path to transfer circuit verification key (for transaction validation)
    pub transfer_verification_key: Option<String>,
    /// Path to update circuit verification key (for tree update validation)
    pub update_verification_key: Option<String>,
    /// Number of blobs to cache in memory
    #[serde(default = "default_sequencer_blob_cache_size")]
    pub blob_cache_size: usize,
    /// TransactionRegistry contract address for eth-key authorization queries
    pub transaction_registry_address: Option<Address>,
    /// Path to snarkjs command (e.g., "npx snarkjs")
    pub snarkjs_path: Option<String>,
    /// Path to predictableUpdate circuit WASM
    pub circuit_wasm_path: Option<String>,
    /// Path to predictableUpdate circuit zkey
    pub circuit_zkey_path: Option<String>,
    /// Maximum retry attempts for failed challenge submissions
    #[serde(default = "default_sequencer_max_challenge_retries")]
    pub max_challenge_retries: u32,

    // === Mempool configuration ===
    /// Maximum transactions to hold in mempool (backpressure limit)
    #[serde(default = "default_mempool_max_pending")]
    pub mempool_max_pending: usize,
}

fn default_sequencer_database_path() -> String {
    "sequencer.db".to_string()
}

fn default_sequencer_confirmations() -> u64 {
    1 // Sequencer needs faster confirmation than standalone challenger
}

fn default_sequencer_lookback_blocks() -> u64 {
    100
}

fn default_sequencer_blob_cache_size() -> usize {
    16
}

fn default_sequencer_max_challenge_retries() -> u32 {
    3
}

fn default_mempool_max_pending() -> usize {
    10000 // Allow ~10k pending transactions
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            common: CommonConfig::default(),
            private_key: None,
            api_listen_addr: "127.0.0.1:8080".to_string(),
            max_tx_per_block: 1024,
            block_interval_ms: 12000,
            min_tx_per_block: 0,
            // Integrated challenger config
            database_path: default_sequencer_database_path(),
            beacon_api_url: None,
            confirmations: default_sequencer_confirmations(),
            lookback_blocks: default_sequencer_lookback_blocks(),
            transfer_verification_key: None,
            update_verification_key: None,
            blob_cache_size: default_sequencer_blob_cache_size(),
            transaction_registry_address: None,
            snarkjs_path: None,
            circuit_wasm_path: None,
            circuit_zkey_path: None,
            max_challenge_retries: default_sequencer_max_challenge_retries(),
            // Mempool config
            mempool_max_pending: default_mempool_max_pending(),
        }
    }
}

/// Load configuration from a TOML file with environment variable overrides
pub fn load_config<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("Failed to read config file: {}", path.display()))?;

    let config: T = toml::from_str(&contents)
        .wrap_err_with(|| format!("Failed to parse config file: {}", path.display()))?;

    Ok(config)
}

/// Load configuration with optional file, falling back to defaults
pub fn load_config_or_default<T: serde::de::DeserializeOwned + Default>(
    path: Option<&Path>,
) -> Result<T> {
    match path {
        Some(p) => load_config(p),
        None => Ok(T::default()),
    }
}

/// Apply environment variable overrides to a config
/// Environment variables are prefixed with `PGP_` and use uppercase with underscores
/// Example: `PGP_RPC_URL`, `PGP_CHAIN_ID`, `PGP_PRIVATE_KEY`
pub trait EnvOverride {
    fn apply_env_overrides(&mut self) -> Result<()>;
}

impl EnvOverride for CommonConfig {
    fn apply_env_overrides(&mut self) -> Result<()> {
        if let Ok(val) = std::env::var("PGP_RPC_URL") {
            self.rpc_url = val;
        }
        if let Ok(val) = std::env::var("PGP_CHAIN_ID") {
            self.chain_id = val.parse().wrap_err("Invalid PGP_CHAIN_ID")?;
        }
        if let Ok(val) = std::env::var("PGP_ENTRYPOINT_ADDRESS") {
            self.entrypoint_address = val.parse().wrap_err("Invalid PGP_ENTRYPOINT_ADDRESS")?;
        }
        if let Ok(val) = std::env::var("PGP_DEPOSITS_ADDRESS") {
            self.deposits_address = val.parse().wrap_err("Invalid PGP_DEPOSITS_ADDRESS")?;
        }
        if let Ok(val) = std::env::var("PGP_CIRCUITS_PATH") {
            self.circuits_path = Some(val);
        }
        Ok(())
    }
}

impl EnvOverride for ChallengerConfig {
    fn apply_env_overrides(&mut self) -> Result<()> {
        self.common.apply_env_overrides()?;

        if let Ok(val) = std::env::var("PGP_PRIVATE_KEY") {
            self.private_key = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_DATABASE_PATH") {
            self.database_path = val;
        }
        if let Ok(val) = std::env::var("PGP_DRY_RUN") {
            self.dry_run = val.parse().unwrap_or(false);
        }
        if let Ok(val) = std::env::var("PGP_POLL_INTERVAL_MS") {
            self.poll_interval_ms = val.parse().wrap_err("Invalid PGP_POLL_INTERVAL_MS")?;
        }
        if let Ok(val) = std::env::var("PGP_CONFIRMATIONS") {
            self.confirmations = val.parse().wrap_err("Invalid PGP_CONFIRMATIONS")?;
        }
        if let Ok(val) = std::env::var("PGP_LOOKBACK_BLOCKS") {
            self.lookback_blocks = val.parse().wrap_err("Invalid PGP_LOOKBACK_BLOCKS")?;
        }
        if let Ok(val) = std::env::var("PGP_TRANSACTION_REGISTRY_ADDRESS") {
            self.transaction_registry_address = Some(
                val.parse()
                    .wrap_err("Invalid PGP_TRANSACTION_REGISTRY_ADDRESS")?,
            );
        }
        if let Ok(val) = std::env::var("PGP_TRANSFER_VERIFICATION_KEY") {
            self.transfer_verification_key = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_UPDATE_VERIFICATION_KEY") {
            self.update_verification_key = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_SNARKJS_PATH") {
            self.snarkjs_path = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_CIRCUIT_WASM_PATH") {
            self.circuit_wasm_path = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_CIRCUIT_ZKEY_PATH") {
            self.circuit_zkey_path = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_BEACON_API_URL") {
            self.beacon_api_url = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_MAX_CHALLENGE_RETRIES") {
            self.max_challenge_retries =
                val.parse().wrap_err("Invalid PGP_MAX_CHALLENGE_RETRIES")?;
        }
        if let Ok(val) = std::env::var("PGP_BLOB_CACHE_SIZE") {
            self.blob_cache_size = val.parse().wrap_err("Invalid PGP_BLOB_CACHE_SIZE")?;
        }
        Ok(())
    }
}

impl EnvOverride for SequencerConfig {
    fn apply_env_overrides(&mut self) -> Result<()> {
        self.common.apply_env_overrides()?;

        if let Ok(val) = std::env::var("PGP_PRIVATE_KEY") {
            self.private_key = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_API_LISTEN_ADDR") {
            self.api_listen_addr = val;
        }
        if let Ok(val) = std::env::var("PGP_MAX_TX_PER_BLOCK") {
            self.max_tx_per_block = val.parse().wrap_err("Invalid PGP_MAX_TX_PER_BLOCK")?;
        }
        if let Ok(val) = std::env::var("PGP_BLOCK_INTERVAL_MS") {
            self.block_interval_ms = val.parse().wrap_err("Invalid PGP_BLOCK_INTERVAL_MS")?;
        }
        if let Ok(val) = std::env::var("PGP_MIN_TX_PER_BLOCK") {
            self.min_tx_per_block = val.parse().wrap_err("Invalid PGP_MIN_TX_PER_BLOCK")?;
        }
        // Integrated challenger config overrides
        if let Ok(val) = std::env::var("PGP_DATABASE_PATH") {
            self.database_path = val;
        }
        if let Ok(val) = std::env::var("PGP_BEACON_API_URL") {
            self.beacon_api_url = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_CONFIRMATIONS") {
            self.confirmations = val.parse().wrap_err("Invalid PGP_CONFIRMATIONS")?;
        }
        if let Ok(val) = std::env::var("PGP_LOOKBACK_BLOCKS") {
            self.lookback_blocks = val.parse().wrap_err("Invalid PGP_LOOKBACK_BLOCKS")?;
        }
        if let Ok(val) = std::env::var("PGP_TRANSFER_VERIFICATION_KEY") {
            self.transfer_verification_key = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_UPDATE_VERIFICATION_KEY") {
            self.update_verification_key = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_BLOB_CACHE_SIZE") {
            self.blob_cache_size = val.parse().wrap_err("Invalid PGP_BLOB_CACHE_SIZE")?;
        }
        if let Ok(val) = std::env::var("PGP_MEMPOOL_MAX_PENDING") {
            self.mempool_max_pending = val.parse().wrap_err("Invalid PGP_MEMPOOL_MAX_PENDING")?;
        }
        Ok(())
    }
}

// ============================================================================
// ChallengerRunnerConfig Trait
// ============================================================================

/// Configuration trait that both ChallengerConfig and SequencerConfig implement.
/// This allows the ChallengerRunner to accept either config type.
pub trait ChallengerRunnerConfig {
    /// Entrypoint contract address
    fn entrypoint_address(&self) -> Address;
    /// Deposits contract address
    fn deposits_address(&self) -> Address;
    /// RPC URL for Ethereum provider
    fn rpc_url(&self) -> &str;
    /// Chain ID
    fn chain_id(&self) -> u64;
    /// TransactionRegistry contract address
    fn transaction_registry_address(&self) -> Option<Address>;
    /// Path to SQLite database
    fn database_path(&self) -> &str;
    /// Polling interval in milliseconds
    fn poll_interval_ms(&self) -> u64;
    /// Number of confirmations before processing
    fn confirmations(&self) -> u64;
    /// Number of blocks to look back on startup
    fn lookback_blocks(&self) -> u64;
    /// Path to transfer circuit verification key
    fn transfer_verification_key(&self) -> Option<&str>;
    /// Path to update circuit verification key
    fn update_verification_key(&self) -> Option<&str>;
    /// Path to snarkjs command
    fn snarkjs_path(&self) -> Option<&str>;
    /// Path to circuit WASM
    fn circuit_wasm_path(&self) -> Option<&str>;
    /// Path to circuit zkey
    fn circuit_zkey_path(&self) -> Option<&str>;
    /// Beacon chain API URL
    fn beacon_api_url(&self) -> Option<&str>;
    /// Maximum challenge retry attempts
    fn max_challenge_retries(&self) -> u32;
    /// Number of blobs to cache
    fn blob_cache_size(&self) -> usize;
    /// Whether running in dry-run mode
    fn dry_run(&self) -> bool;
}

impl ChallengerRunnerConfig for ChallengerConfig {
    fn entrypoint_address(&self) -> Address {
        self.common.entrypoint_address
    }
    fn deposits_address(&self) -> Address {
        self.common.deposits_address
    }
    fn rpc_url(&self) -> &str {
        &self.common.rpc_url
    }
    fn chain_id(&self) -> u64 {
        self.common.chain_id
    }
    fn transaction_registry_address(&self) -> Option<Address> {
        self.transaction_registry_address
    }
    fn database_path(&self) -> &str {
        &self.database_path
    }
    fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }
    fn confirmations(&self) -> u64 {
        self.confirmations
    }
    fn lookback_blocks(&self) -> u64 {
        self.lookback_blocks
    }
    fn transfer_verification_key(&self) -> Option<&str> {
        self.transfer_verification_key.as_deref()
    }
    fn update_verification_key(&self) -> Option<&str> {
        self.update_verification_key.as_deref()
    }
    fn snarkjs_path(&self) -> Option<&str> {
        self.snarkjs_path.as_deref()
    }
    fn circuit_wasm_path(&self) -> Option<&str> {
        self.circuit_wasm_path.as_deref()
    }
    fn circuit_zkey_path(&self) -> Option<&str> {
        self.circuit_zkey_path.as_deref()
    }
    fn beacon_api_url(&self) -> Option<&str> {
        self.beacon_api_url.as_deref()
    }
    fn max_challenge_retries(&self) -> u32 {
        self.max_challenge_retries
    }
    fn blob_cache_size(&self) -> usize {
        self.blob_cache_size
    }
    fn dry_run(&self) -> bool {
        self.dry_run
    }
}

impl ChallengerRunnerConfig for SequencerConfig {
    fn entrypoint_address(&self) -> Address {
        self.common.entrypoint_address
    }
    fn deposits_address(&self) -> Address {
        self.common.deposits_address
    }
    fn rpc_url(&self) -> &str {
        &self.common.rpc_url
    }
    fn chain_id(&self) -> u64 {
        self.common.chain_id
    }
    fn transaction_registry_address(&self) -> Option<Address> {
        self.transaction_registry_address
    }
    fn database_path(&self) -> &str {
        &self.database_path
    }
    fn poll_interval_ms(&self) -> u64 {
        self.block_interval_ms // Sequencer uses block_interval_ms for polling
    }
    fn confirmations(&self) -> u64 {
        self.confirmations
    }
    fn lookback_blocks(&self) -> u64 {
        self.lookback_blocks
    }
    fn transfer_verification_key(&self) -> Option<&str> {
        self.transfer_verification_key.as_deref()
    }
    fn update_verification_key(&self) -> Option<&str> {
        self.update_verification_key.as_deref()
    }
    fn snarkjs_path(&self) -> Option<&str> {
        self.snarkjs_path.as_deref()
    }
    fn circuit_wasm_path(&self) -> Option<&str> {
        self.circuit_wasm_path.as_deref()
    }
    fn circuit_zkey_path(&self) -> Option<&str> {
        self.circuit_zkey_path.as_deref()
    }
    fn beacon_api_url(&self) -> Option<&str> {
        self.beacon_api_url.as_deref()
    }
    fn max_challenge_retries(&self) -> u32 {
        self.max_challenge_retries
    }
    fn blob_cache_size(&self) -> usize {
        self.blob_cache_size
    }
    fn dry_run(&self) -> bool {
        false // Sequencer doesn't have a dry_run field by default, but CLI args can override
    }
}

/// Wrapper that allows overriding dry_run for SequencerConfig
pub struct SequencerConfigWithDryRun<'a> {
    pub config: &'a SequencerConfig,
    pub dry_run: bool,
}

impl ChallengerRunnerConfig for SequencerConfigWithDryRun<'_> {
    fn entrypoint_address(&self) -> Address {
        self.config.entrypoint_address()
    }
    fn deposits_address(&self) -> Address {
        self.config.deposits_address()
    }
    fn rpc_url(&self) -> &str {
        self.config.rpc_url()
    }
    fn chain_id(&self) -> u64 {
        self.config.chain_id()
    }
    fn transaction_registry_address(&self) -> Option<Address> {
        self.config.transaction_registry_address()
    }
    fn database_path(&self) -> &str {
        self.config.database_path()
    }
    fn poll_interval_ms(&self) -> u64 {
        self.config.poll_interval_ms()
    }
    fn confirmations(&self) -> u64 {
        self.config.confirmations()
    }
    fn lookback_blocks(&self) -> u64 {
        self.config.lookback_blocks()
    }
    fn transfer_verification_key(&self) -> Option<&str> {
        self.config.transfer_verification_key()
    }
    fn update_verification_key(&self) -> Option<&str> {
        self.config.update_verification_key()
    }
    fn snarkjs_path(&self) -> Option<&str> {
        self.config.snarkjs_path()
    }
    fn circuit_wasm_path(&self) -> Option<&str> {
        self.config.circuit_wasm_path()
    }
    fn circuit_zkey_path(&self) -> Option<&str> {
        self.config.circuit_zkey_path()
    }
    fn beacon_api_url(&self) -> Option<&str> {
        self.config.beacon_api_url()
    }
    fn max_challenge_retries(&self) -> u32 {
        self.config.max_challenge_retries()
    }
    fn blob_cache_size(&self) -> usize {
        self.config.blob_cache_size()
    }
    fn dry_run(&self) -> bool {
        self.dry_run
    }
}

/// Validate that required configuration is present
pub fn validate_challenger_config(config: &ChallengerConfig) -> Result<()> {
    if config.common.entrypoint_address == Address::ZERO {
        return Err(eyre!("Entrypoint address must be configured"));
    }
    if config.common.deposits_address == Address::ZERO {
        return Err(eyre!("Deposits address must be configured"));
    }
    if !config.dry_run && config.private_key.is_none() {
        return Err(eyre!("Private key must be configured for non-dry-run mode"));
    }
    Ok(())
}

pub fn validate_sequencer_config(config: &SequencerConfig) -> Result<()> {
    if config.common.entrypoint_address == Address::ZERO {
        return Err(eyre!("Entrypoint address must be configured"));
    }
    if config.private_key.is_none() {
        return Err(eyre!("Private key must be configured"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_challenger_config() {
        let config = ChallengerConfig::default();
        assert_eq!(config.common.rpc_url, "http://localhost:8545");
        assert_eq!(config.common.chain_id, 31337);
        assert!(!config.dry_run);
    }

    #[test]
    fn test_load_config_from_toml() {
        let toml_content = r#"
rpc_url = "http://example.com:8545"
chain_id = 1
entrypoint_address = "0x1234567890123456789012345678901234567890"
deposits_address = "0xabcdef0123456789abcdef0123456789abcdef01"
database_path = "test.db"
dry_run = true
poll_interval_ms = 2000
confirmations = 3
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let config: ChallengerConfig = load_config(file.path()).unwrap();
        assert_eq!(config.common.rpc_url, "http://example.com:8545");
        assert_eq!(config.common.chain_id, 1);
        assert!(config.dry_run);
        assert_eq!(config.poll_interval_ms, 2000);
    }

    #[test]
    fn test_env_override() {
        std::env::set_var("PGP_RPC_URL", "http://override:8545");
        std::env::set_var("PGP_CHAIN_ID", "42");

        let mut config = CommonConfig::default();
        config.apply_env_overrides().unwrap();

        assert_eq!(config.rpc_url, "http://override:8545");
        assert_eq!(config.chain_id, 42);

        // Cleanup
        std::env::remove_var("PGP_RPC_URL");
        std::env::remove_var("PGP_CHAIN_ID");
    }

    #[test]
    fn test_validate_challenger_config() {
        let mut config = ChallengerConfig::default();
        assert!(validate_challenger_config(&config).is_err());

        config.common.entrypoint_address = Address::repeat_byte(0x12);
        config.common.deposits_address = Address::repeat_byte(0x34);
        config.dry_run = true;
        assert!(validate_challenger_config(&config).is_ok());
    }
}
