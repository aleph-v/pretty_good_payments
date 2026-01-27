//! Configuration loading with TOML files and environment variable overrides.

use alloy_primitives::Address;
use eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ============================================================================
// Unified Configuration
// ============================================================================

/// Unified configuration for both sequencer and challenger.
///
/// A single config file can run either binary. Fields are organized by section
/// for clarity, matching the TOML structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Contract addresses
    #[serde(default)]
    pub contracts: ContractsConfig,

    /// Private keys (separate for sequencer and challenger)
    #[serde(default)]
    pub keys: KeysConfig,

    /// Sequencer-specific configuration
    #[serde(default)]
    pub sequencer: SequencerSectionConfig,

    /// Challenger-specific configuration
    #[serde(default)]
    pub challenger: ChallengerSectionConfig,

    /// ZK circuit paths
    #[serde(default)]
    pub circuits: CircuitsConfig,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Ethereum RPC endpoint URL
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    /// Beacon chain API URL (for blob retrieval)
    #[serde(default = "default_beacon_url")]
    pub beacon_url: String,
    /// Chain ID for transaction signing
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            rpc_url: default_rpc_url(),
            beacon_url: default_beacon_url(),
            chain_id: default_chain_id(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractsConfig {
    /// Entrypoint contract address
    #[serde(default)]
    pub entrypoint: Address,
    /// Deposits contract address
    #[serde(default)]
    pub deposits: Address,
    /// TransactionRegistry contract address (optional)
    pub transaction_registry: Option<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeysConfig {
    /// Private key for sequencer (block submission)
    pub sequencer_private_key: Option<String>,
    /// Private key for challenger (fraud proof submission)
    pub challenger_private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerSectionConfig {
    /// REST API listen host
    #[serde(default = "default_api_host")]
    pub api_host: String,
    /// REST API listen port
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    /// Block building interval (milliseconds)
    #[serde(default = "default_block_interval_ms")]
    pub block_interval_ms: u64,
    /// Maximum transactions to hold in mempool
    #[serde(default = "default_mempool_max_pending")]
    pub mempool_max_pending: usize,
}

impl Default for SequencerSectionConfig {
    fn default() -> Self {
        Self {
            api_host: default_api_host(),
            api_port: default_api_port(),
            block_interval_ms: default_block_interval_ms(),
            mempool_max_pending: default_mempool_max_pending(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengerSectionConfig {
    /// Polling interval for new blocks (milliseconds)
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// Number of confirmations before processing a block
    #[serde(default = "default_confirmations")]
    pub confirmations: u64,
    /// Number of blocks to look back on startup
    #[serde(default = "default_lookback_blocks")]
    pub lookback_blocks: u64,
    /// Whether to only monitor without submitting challenges
    #[serde(default)]
    pub dry_run: bool,
    /// Maximum retry attempts for failed challenge submissions
    #[serde(default = "default_max_challenge_retries")]
    pub max_challenge_retries: u32,
}

impl Default for ChallengerSectionConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: default_poll_interval_ms(),
            confirmations: default_confirmations(),
            lookback_blocks: default_lookback_blocks(),
            dry_run: false,
            max_challenge_retries: default_max_challenge_retries(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitsConfig {
    /// Path to transfer circuit verification key (snarkjs JSON)
    #[serde(default = "default_transfer_verification_key")]
    pub transfer_verification_key: String,
    /// Path to predictableUpdate circuit verification key (snarkjs JSON)
    #[serde(default = "default_update_verification_key")]
    pub update_verification_key: String,
    /// Path to snarkjs command
    #[serde(default = "default_snarkjs_path")]
    pub snarkjs_path: String,
    /// Path to predictableUpdate circuit WASM
    #[serde(default = "default_circuit_wasm_path")]
    pub circuit_wasm_path: String,
    /// Path to predictableUpdate circuit zkey
    #[serde(default = "default_circuit_zkey_path")]
    pub circuit_zkey_path: String,
}

impl Default for CircuitsConfig {
    fn default() -> Self {
        Self {
            transfer_verification_key: default_transfer_verification_key(),
            update_verification_key: default_update_verification_key(),
            snarkjs_path: default_snarkjs_path(),
            circuit_wasm_path: default_circuit_wasm_path(),
            circuit_zkey_path: default_circuit_zkey_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to SQLite database
    #[serde(default = "default_database_path")]
    pub database_path: String,
    /// Number of blobs to cache in memory
    #[serde(default = "default_blob_cache_size")]
    pub blob_cache_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: default_database_path(),
            blob_cache_size: default_blob_cache_size(),
        }
    }
}

// ============================================================================
// Default value functions
// ============================================================================

fn default_rpc_url() -> String {
    "http://localhost:8545".to_string()
}

fn default_beacon_url() -> String {
    "http://localhost:5052".to_string()
}

fn default_chain_id() -> u64 {
    31337 // Anvil default
}

fn default_api_host() -> String {
    "127.0.0.1".to_string()
}

fn default_api_port() -> u16 {
    8080
}

fn default_block_interval_ms() -> u64 {
    12000
}

fn default_mempool_max_pending() -> usize {
    10000
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

fn default_database_path() -> String {
    "./data/pgp.db".to_string()
}

fn default_blob_cache_size() -> usize {
    16
}

fn default_transfer_verification_key() -> String {
    "circuits/outputs/transfer/transferVKey.json".to_string()
}

fn default_update_verification_key() -> String {
    "circuits/outputs/predictableUpdate/predictableUpdateVKey.json".to_string()
}

fn default_snarkjs_path() -> String {
    "snarkjs".to_string()
}

fn default_circuit_wasm_path() -> String {
    "circuits/outputs/predictableUpdate/predictableUpdate_js/predictableUpdate.wasm".to_string()
}

fn default_circuit_zkey_path() -> String {
    "circuits/outputs/predictableUpdate/predictableUpdate.zkey".to_string()
}

// ============================================================================
// Config loading
// ============================================================================

/// Load configuration from a TOML file
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

// ============================================================================
// Environment variable overrides
// ============================================================================

/// Apply environment variable overrides to a config.
/// Environment variables are prefixed with `PGP_` and use uppercase with underscores.
pub trait EnvOverride {
    fn apply_env_overrides(&mut self) -> Result<()>;
}

impl EnvOverride for Config {
    fn apply_env_overrides(&mut self) -> Result<()> {
        // Network
        if let Ok(val) = std::env::var("PGP_RPC_URL") {
            self.network.rpc_url = val;
        }
        if let Ok(val) = std::env::var("PGP_BEACON_URL") {
            self.network.beacon_url = val;
        }
        if let Ok(val) = std::env::var("PGP_CHAIN_ID") {
            self.network.chain_id = val.parse().wrap_err("Invalid PGP_CHAIN_ID")?;
        }

        // Contracts
        if let Ok(val) = std::env::var("PGP_ENTRYPOINT_ADDRESS") {
            self.contracts.entrypoint = val.parse().wrap_err("Invalid PGP_ENTRYPOINT_ADDRESS")?;
        }
        if let Ok(val) = std::env::var("PGP_DEPOSITS_ADDRESS") {
            self.contracts.deposits = val.parse().wrap_err("Invalid PGP_DEPOSITS_ADDRESS")?;
        }
        if let Ok(val) = std::env::var("PGP_TRANSACTION_REGISTRY_ADDRESS") {
            self.contracts.transaction_registry = Some(
                val.parse()
                    .wrap_err("Invalid PGP_TRANSACTION_REGISTRY_ADDRESS")?,
            );
        }

        // Keys
        if let Ok(val) = std::env::var("PGP_SEQUENCER_PRIVATE_KEY") {
            self.keys.sequencer_private_key = Some(val);
        }
        if let Ok(val) = std::env::var("PGP_CHALLENGER_PRIVATE_KEY") {
            self.keys.challenger_private_key = Some(val);
        }

        // Sequencer
        if let Ok(val) = std::env::var("PGP_API_HOST") {
            self.sequencer.api_host = val;
        }
        if let Ok(val) = std::env::var("PGP_API_PORT") {
            self.sequencer.api_port = val.parse().wrap_err("Invalid PGP_API_PORT")?;
        }
        if let Ok(val) = std::env::var("PGP_BLOCK_INTERVAL_MS") {
            self.sequencer.block_interval_ms =
                val.parse().wrap_err("Invalid PGP_BLOCK_INTERVAL_MS")?;
        }
        if let Ok(val) = std::env::var("PGP_MEMPOOL_MAX_PENDING") {
            self.sequencer.mempool_max_pending =
                val.parse().wrap_err("Invalid PGP_MEMPOOL_MAX_PENDING")?;
        }

        // Challenger
        if let Ok(val) = std::env::var("PGP_POLL_INTERVAL_MS") {
            self.challenger.poll_interval_ms =
                val.parse().wrap_err("Invalid PGP_POLL_INTERVAL_MS")?;
        }
        if let Ok(val) = std::env::var("PGP_CONFIRMATIONS") {
            self.challenger.confirmations = val.parse().wrap_err("Invalid PGP_CONFIRMATIONS")?;
        }
        if let Ok(val) = std::env::var("PGP_LOOKBACK_BLOCKS") {
            self.challenger.lookback_blocks =
                val.parse().wrap_err("Invalid PGP_LOOKBACK_BLOCKS")?;
        }
        if let Ok(val) = std::env::var("PGP_DRY_RUN") {
            self.challenger.dry_run = val.parse().unwrap_or(false);
        }
        if let Ok(val) = std::env::var("PGP_MAX_CHALLENGE_RETRIES") {
            self.challenger.max_challenge_retries =
                val.parse().wrap_err("Invalid PGP_MAX_CHALLENGE_RETRIES")?;
        }

        // Circuits
        if let Ok(val) = std::env::var("PGP_TRANSFER_VERIFICATION_KEY") {
            self.circuits.transfer_verification_key = val;
        }
        if let Ok(val) = std::env::var("PGP_UPDATE_VERIFICATION_KEY") {
            self.circuits.update_verification_key = val;
        }
        if let Ok(val) = std::env::var("PGP_SNARKJS_PATH") {
            self.circuits.snarkjs_path = val;
        }
        if let Ok(val) = std::env::var("PGP_CIRCUIT_WASM_PATH") {
            self.circuits.circuit_wasm_path = val;
        }
        if let Ok(val) = std::env::var("PGP_CIRCUIT_ZKEY_PATH") {
            self.circuits.circuit_zkey_path = val;
        }

        // Storage
        if let Ok(val) = std::env::var("PGP_DATABASE_PATH") {
            self.storage.database_path = val;
        }
        if let Ok(val) = std::env::var("PGP_BLOB_CACHE_SIZE") {
            self.storage.blob_cache_size = val.parse().wrap_err("Invalid PGP_BLOB_CACHE_SIZE")?;
        }

        Ok(())
    }
}

// ============================================================================
// ChallengerRunnerConfig Trait
// ============================================================================

/// Configuration trait for the ChallengerRunner.
/// The unified Config implements this trait.
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
    fn transfer_verification_key(&self) -> &str;
    /// Path to update circuit verification key
    fn update_verification_key(&self) -> &str;
    /// Path to snarkjs command
    fn snarkjs_path(&self) -> &str;
    /// Path to circuit WASM
    fn circuit_wasm_path(&self) -> &str;
    /// Path to circuit zkey
    fn circuit_zkey_path(&self) -> &str;
    /// Beacon chain API URL
    fn beacon_api_url(&self) -> &str;
    /// Maximum challenge retry attempts
    fn max_challenge_retries(&self) -> u32;
    /// Number of blobs to cache
    fn blob_cache_size(&self) -> usize;
    /// Whether running in dry-run mode
    fn dry_run(&self) -> bool;
}

impl ChallengerRunnerConfig for Config {
    fn entrypoint_address(&self) -> Address {
        self.contracts.entrypoint
    }
    fn deposits_address(&self) -> Address {
        self.contracts.deposits
    }
    fn rpc_url(&self) -> &str {
        &self.network.rpc_url
    }
    fn chain_id(&self) -> u64 {
        self.network.chain_id
    }
    fn transaction_registry_address(&self) -> Option<Address> {
        self.contracts.transaction_registry
    }
    fn database_path(&self) -> &str {
        &self.storage.database_path
    }
    fn poll_interval_ms(&self) -> u64 {
        self.challenger.poll_interval_ms
    }
    fn confirmations(&self) -> u64 {
        self.challenger.confirmations
    }
    fn lookback_blocks(&self) -> u64 {
        self.challenger.lookback_blocks
    }
    fn transfer_verification_key(&self) -> &str {
        &self.circuits.transfer_verification_key
    }
    fn update_verification_key(&self) -> &str {
        &self.circuits.update_verification_key
    }
    fn snarkjs_path(&self) -> &str {
        &self.circuits.snarkjs_path
    }
    fn circuit_wasm_path(&self) -> &str {
        &self.circuits.circuit_wasm_path
    }
    fn circuit_zkey_path(&self) -> &str {
        &self.circuits.circuit_zkey_path
    }
    fn beacon_api_url(&self) -> &str {
        &self.network.beacon_url
    }
    fn max_challenge_retries(&self) -> u32 {
        self.challenger.max_challenge_retries
    }
    fn blob_cache_size(&self) -> usize {
        self.storage.blob_cache_size
    }
    fn dry_run(&self) -> bool {
        self.challenger.dry_run
    }
}

/// Wrapper that allows overriding dry_run for Config (used by sequencer CLI)
pub struct ConfigWithDryRun<'a> {
    pub config: &'a Config,
    pub dry_run: bool,
}

impl ChallengerRunnerConfig for ConfigWithDryRun<'_> {
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
    fn transfer_verification_key(&self) -> &str {
        self.config.transfer_verification_key()
    }
    fn update_verification_key(&self) -> &str {
        self.config.update_verification_key()
    }
    fn snarkjs_path(&self) -> &str {
        self.config.snarkjs_path()
    }
    fn circuit_wasm_path(&self) -> &str {
        self.config.circuit_wasm_path()
    }
    fn circuit_zkey_path(&self) -> &str {
        self.config.circuit_zkey_path()
    }
    fn beacon_api_url(&self) -> &str {
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

// ============================================================================
// Validation
// ============================================================================

/// Validate configuration for running as challenger
pub fn validate_challenger_config(config: &Config) -> Result<()> {
    if config.contracts.entrypoint == Address::ZERO {
        return Err(eyre!("Entrypoint address must be configured"));
    }
    if config.contracts.deposits == Address::ZERO {
        return Err(eyre!("Deposits address must be configured"));
    }
    if !config.challenger.dry_run && config.keys.challenger_private_key.is_none() {
        return Err(eyre!(
            "challenger_private_key must be configured for non-dry-run mode"
        ));
    }
    Ok(())
}

/// Validate configuration for running as sequencer
pub fn validate_sequencer_config(config: &Config) -> Result<()> {
    if config.contracts.entrypoint == Address::ZERO {
        return Err(eyre!("Entrypoint address must be configured"));
    }
    if config.contracts.deposits == Address::ZERO {
        return Err(eyre!("Deposits address must be configured"));
    }
    if config.keys.sequencer_private_key.is_none() {
        return Err(eyre!("sequencer_private_key must be configured"));
    }
    Ok(())
}

// ============================================================================
// Legacy type aliases for backwards compatibility during migration
// ============================================================================

/// Common configuration - now embedded in Config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub entrypoint_address: Address,
    pub deposits_address: Address,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            rpc_url: default_rpc_url(),
            chain_id: default_chain_id(),
            entrypoint_address: Address::ZERO,
            deposits_address: Address::ZERO,
        }
    }
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network.rpc_url, "http://localhost:8545");
        assert_eq!(config.network.chain_id, 31337);
        assert!(!config.challenger.dry_run);
    }

    #[test]
    fn test_load_unified_config() {
        let toml_content = r#"
[network]
rpc_url = "http://example.com:8545"
chain_id = 1

[contracts]
entrypoint = "0x1234567890123456789012345678901234567890"
deposits = "0xabcdef0123456789abcdef0123456789abcdef01"

[keys]
sequencer_private_key = "0xseq123"
challenger_private_key = "0xchal456"

[sequencer]
api_port = 9090
mempool_max_pending = 5000

[challenger]
poll_interval_ms = 2000
confirmations = 3
dry_run = true

[storage]
database_path = "test.db"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let config: Config = load_config(file.path()).unwrap();
        assert_eq!(config.network.rpc_url, "http://example.com:8545");
        assert_eq!(config.network.chain_id, 1);
        assert_eq!(
            config.keys.sequencer_private_key,
            Some("0xseq123".to_string())
        );
        assert_eq!(
            config.keys.challenger_private_key,
            Some("0xchal456".to_string())
        );
        assert_eq!(config.sequencer.api_port, 9090);
        assert!(config.challenger.dry_run);
        assert_eq!(config.challenger.poll_interval_ms, 2000);
    }

    #[test]
    fn test_env_override() {
        std::env::set_var("PGP_RPC_URL", "http://override:8545");
        std::env::set_var("PGP_CHAIN_ID", "42");
        std::env::set_var("PGP_SEQUENCER_PRIVATE_KEY", "0xoverride_seq");
        std::env::set_var("PGP_CHALLENGER_PRIVATE_KEY", "0xoverride_chal");

        let mut config = Config::default();
        config.apply_env_overrides().unwrap();

        assert_eq!(config.network.rpc_url, "http://override:8545");
        assert_eq!(config.network.chain_id, 42);
        assert_eq!(
            config.keys.sequencer_private_key,
            Some("0xoverride_seq".to_string())
        );
        assert_eq!(
            config.keys.challenger_private_key,
            Some("0xoverride_chal".to_string())
        );

        // Cleanup
        std::env::remove_var("PGP_RPC_URL");
        std::env::remove_var("PGP_CHAIN_ID");
        std::env::remove_var("PGP_SEQUENCER_PRIVATE_KEY");
        std::env::remove_var("PGP_CHALLENGER_PRIVATE_KEY");
    }

    #[test]
    fn test_validate_challenger_config() {
        let mut config = Config::default();
        assert!(validate_challenger_config(&config).is_err());

        config.contracts.entrypoint = Address::repeat_byte(0x12);
        config.contracts.deposits = Address::repeat_byte(0x34);
        config.challenger.dry_run = true;
        assert!(validate_challenger_config(&config).is_ok());
    }

    #[test]
    fn test_validate_sequencer_config() {
        let mut config = Config::default();
        assert!(validate_sequencer_config(&config).is_err());

        config.contracts.entrypoint = Address::repeat_byte(0x12);
        config.contracts.deposits = Address::repeat_byte(0x34);
        config.keys.sequencer_private_key = Some("0xkey".to_string());
        assert!(validate_sequencer_config(&config).is_ok());
    }

    #[test]
    fn test_challenger_runner_config_trait() {
        let mut config = Config::default();
        config.contracts.entrypoint = Address::repeat_byte(0x12);
        config.contracts.deposits = Address::repeat_byte(0x34);
        config.network.rpc_url = "http://test:8545".to_string();

        assert_eq!(config.entrypoint_address(), Address::repeat_byte(0x12));
        assert_eq!(config.deposits_address(), Address::repeat_byte(0x34));
        assert_eq!(config.rpc_url(), "http://test:8545");
    }
}
