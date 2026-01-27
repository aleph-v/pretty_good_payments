//! PGP Sequencer - Block building, submission, and validation for Pretty Good Payments
//!
//! This binary provides:
//! - Block building and submission to the Entrypoint contract
//! - Full challenger functionality: validates all blocks and submits fraud proofs
//!
//! When running a sequencer, you are also running a full challenger that:
//! - Validates all deposits against L1 contract data
//! - Tracks nullifiers and detects double-spends
//! - Verifies transaction ZK proofs (if verification keys configured)
//! - Validates merkle tree updates
//! - Submits fraud challenges when violations are detected

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use clap::Parser;
use eyre::Result;
use pgp_common::{load_config_or_default, Config, ConfigWithDryRun, EnvOverride};
use pgp_sequencer::{
    block_submitter::{create_config, create_wallet, BlockSubmitter},
    mempool::MempoolConfig,
    start_api_server, try_build_and_submit_block, BlockBuildResult, BlockBuilderConfig, Mempool,
    TRANSACTIONS_PER_BLOB,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use pgp_challenger::{
    events::{EventListener, EventListenerConfig},
    runner::ChallengerRunner,
    state::StateManager,
};

#[derive(Parser, Debug)]
#[command(name = "sequencer")]
#[command(about = "PGP block building, submission, and validation (integrated challenger)")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Run in single-shot mode (submit one block and exit)
    #[arg(long)]
    single_shot: bool,

    /// Dry run mode (validate only, don't submit blocks or challenges)
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting PGP Sequencer (with integrated challenger)");

    // Load configuration
    let mut config: Config = load_config_or_default(args.config.as_deref())?;
    config.apply_env_overrides()?;

    // Compute API listen address
    let api_listen_addr = format!(
        "{}:{}",
        config.sequencer.api_host, config.sequencer.api_port
    );

    info!("Configuration loaded:");
    info!("  RPC URL: {}", config.network.rpc_url);
    info!("  Chain ID: {}", config.network.chain_id);
    info!("  Entrypoint: {:?}", config.contracts.entrypoint);
    info!("  Deposits: {:?}", config.contracts.deposits);
    info!("  Database: {}", config.storage.database_path);
    info!("  API listen: {}", api_listen_addr);
    info!(
        "  Mempool max pending: {}",
        config.sequencer.mempool_max_pending
    );
    info!("  Dry run: {}", args.dry_run);

    // Validate configuration
    if config.contracts.entrypoint == Address::ZERO {
        return Err(eyre::eyre!("Entrypoint address must be configured"));
    }
    if config.contracts.deposits == Address::ZERO {
        return Err(eyre::eyre!("Deposits address must be configured"));
    }

    // Validate private key requirement for block submission
    if !args.dry_run && config.keys.sequencer_private_key.is_none() {
        return Err(eyre::eyre!(
            "sequencer_private_key required for block submission"
        ));
    }

    // Initialize state manager for challenger
    let state = StateManager::open(&config.storage.database_path)?;
    info!("State database opened: {}", config.storage.database_path);

    // Open a separate StateManager for mempool validation (shares same database file)
    // SQLite supports concurrent readers, and the mempool only needs read access
    let mempool_state = StateManager::open(&config.storage.database_path)?;
    info!("Mempool state opened (sharing database with challenger)");

    // Create read-only provider for validation and event listening
    let provider = ProviderBuilder::new().connect_http(config.network.rpc_url.parse()?);
    info!("Connected to RPC: {}", config.network.rpc_url);

    // Log sequencer address if available
    if let Some(private_key) = &config.keys.sequencer_private_key {
        if let Ok(submitter_config) = create_config(private_key, config.contracts.entrypoint) {
            info!(
                "Sequencer address: {:?}",
                submitter_config.sequencer_address
            );
        }
    }

    // Create challenger runner with dry_run override based on CLI args
    let config_with_dry_run = ConfigWithDryRun {
        config: &config,
        dry_run: args.dry_run,
    };
    let mut runner = ChallengerRunner::new(provider.clone(), state, &config_with_dry_run).await?;

    // Perform health checks
    runner.perform_health_checks(&config_with_dry_run).await?;

    // Initialize event listener
    let event_config = EventListenerConfig {
        entrypoint_address: config.contracts.entrypoint,
        lookback_blocks: config.challenger.lookback_blocks,
        poll_interval_ms: config.sequencer.block_interval_ms,
        confirmations: config.challenger.confirmations,
    };
    let mut event_listener = EventListener::new(provider.clone(), event_config);

    // Initialize from persisted state
    let start_block = runner.load_last_processed_block()?;
    event_listener.init(start_block).await?;

    // Get genesis anchor
    let genesis_anchor: alloy::primitives::B256 = {
        use pgp_common::contracts::Entrypoint;
        let entrypoint = Entrypoint::new(config.contracts.entrypoint, &provider);
        entrypoint.GENESIS_ANCHOR().call().await?
    };
    info!("Genesis anchor: {:?}", genesis_anchor);

    // Load verification keys for ZK proof validation
    let transfer_vk_path = &config.circuits.transfer_verification_key;
    let update_vk_path = &config.circuits.update_verification_key;

    info!("Loading verification keys...");
    info!("  Transfer VK: {}", transfer_vk_path);
    info!("  Update VK: {}", update_vk_path);

    let zk_verifier = pgp_challenger::Groth16Verifier::new(
        std::path::Path::new(transfer_vk_path),
        std::path::Path::new(update_vk_path),
    )
    .map_err(|e| eyre::eyre!("Failed to load verification keys: {}", e))?;
    info!("ZK verifier initialized");

    // Initialize mempool with state for nullifier validation and ZK verification
    let mempool_config = MempoolConfig {
        max_pending: config.sequencer.mempool_max_pending,
    };
    let mempool = Arc::new(Mempool::new(mempool_config, mempool_state, zk_verifier));
    info!(
        "Mempool initialized (max pending: {}, nullifier & anchor & ZK validation enabled)",
        config.sequencer.mempool_max_pending
    );

    // Set up graceful shutdown
    let shutdown = pgp_common::setup_shutdown_handler();

    // Initialize block submitter (unless dry run)
    // Open a separate StateManager for reading state (SQLite allows concurrent readers)
    let block_builder_ctx = if !args.dry_run {
        let private_key = config.keys.sequencer_private_key.as_ref().unwrap();
        let submitter_config = create_config(private_key, config.contracts.entrypoint)
            .map_err(|e| eyre::eyre!("Failed to create config: {}", e))?;
        let wallet: EthereumWallet = create_wallet(&submitter_config.signer);
        let wallet_provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(config.network.rpc_url.parse()?);
        let mut block_submitter = BlockSubmitter::new(submitter_config, wallet_provider);

        // Initialize the epoch watcher by syncing with the blockchain
        block_submitter
            .init()
            .await
            .map_err(|e| eyre::eyre!("Failed to initialize block submitter: {}", e))?;
        info!("Block submitter initialized (epoch watcher synced)");

        // Log priority sequencer behavior
        if block_submitter.is_priority_sequencer() {
            info!("Running as PRIORITY SEQUENCER:");
            info!("  - Will HOLD transactions during open period");
            info!("  - Will DRAIN mempool during exclusive closed period (up to 10 blobs)");
        } else {
            info!("Running as standard sequencer (submits during open period)");
        }

        // Open a second StateManager for reading - shares the same database file
        // SQLite supports multiple concurrent readers
        let block_builder_state = StateManager::open(&config.storage.database_path)?;
        info!("Block builder state opened (sharing database with challenger)");

        let builder_config = BlockBuilderConfig {
            min_deposits: 0,                         // Submit as soon as deposits are available
            min_transactions: TRANSACTIONS_PER_BLOB, // Require full blob to submit
            max_transactions: TRANSACTIONS_PER_BLOB, // One blob per automatic build
            check_interval: Duration::from_secs(5),
        };

        Some((
            block_submitter,
            block_builder_state,
            builder_config,
            mempool.clone(),
        ))
    } else {
        None
    };

    // Start API server (unless dry run)
    let _api_handle = if !args.dry_run {
        let handle = start_api_server(&api_listen_addr, mempool.clone()).await?;
        Some(handle)
    } else {
        info!("API server disabled (dry_run mode)");
        None
    };

    // Run the main event loop (challenger functionality)
    // Block building is integrated via the per-iteration hook
    let loop_config = pgp_challenger::EventLoopConfig {
        poll_interval: Duration::from_millis(config.sequencer.block_interval_ms),
        dry_run: args.dry_run,
        service_name: "Sequencer",
    };

    pgp_challenger::run_event_loop(
        &mut runner,
        &mut event_listener,
        shutdown,
        loop_config,
        || {
            // Block building logic runs each iteration
            let ctx = &block_builder_ctx;
            let genesis = genesis_anchor;
            async move {
                if let Some((ref submitter, ref state, ref config, ref mempool)) = ctx {
                    // Check if a forced submission was requested (via /poke endpoint)
                    let force = mempool.check_and_clear_force_submit();
                    if force {
                        info!("Force submit triggered via /poke endpoint");
                    }
                    match try_build_and_submit_block(submitter, state, config, genesis, mempool, force).await {
                        BlockBuildResult::Submitted { block_nr, anchor, num_deposits, num_transactions, .. } => {
                            info!(
                                "Submitted block {} with {} deposits, {} transactions (anchor: {:?})",
                                block_nr, num_deposits, num_transactions, anchor
                            );
                        }
                        BlockBuildResult::NoDeposits => {
                            // Normal - no deposits available yet
                        }
                        BlockBuildResult::InsufficientDeposits { .. } => {
                            // Waiting for more deposits
                        }
                        BlockBuildResult::InsufficientTransactions { .. } => {
                            // Waiting for more transactions to fill a blob
                        }
                        BlockBuildResult::NotAllowed => {
                            // Waiting for open epoch period
                        }
                        BlockBuildResult::HoldingForPriorityPeriod => {
                            // Priority sequencer holding for exclusive period
                        }
                        BlockBuildResult::Error(e) => {
                            warn!("Block building error: {}", e);
                        }
                    }
                }
            }
        },
    )
    .await;

    Ok(())
}
