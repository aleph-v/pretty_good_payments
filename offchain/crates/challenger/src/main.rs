//! PGP Challenger - Fraud detection and challenge submission for Pretty Good Payments
//!
//! This binary monitors L2 blocks, validates their correctness, and submits
//! fraud proofs when violations are detected.

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use clap::Parser;
use eyre::Result;
use pgp_common::{load_config_or_default, ChallengerConfig, EnvOverride};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use pgp_challenger::{
    events::{EventListener, EventListenerConfig},
    runner::ChallengerRunner,
    state::StateManager,
};

#[derive(Parser, Debug)]
#[command(name = "challenger")]
#[command(about = "PGP fraud detection and challenge submission")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Dry run mode (monitor only, don't submit challenges)
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

    info!("Starting PGP Challenger");

    // Load configuration
    let mut config: ChallengerConfig = load_config_or_default(args.config.as_deref())?;
    config.apply_env_overrides()?;

    if args.dry_run {
        config.dry_run = true;
    }

    info!("Configuration loaded:");
    info!("  RPC URL: {}", config.common.rpc_url);
    info!("  Chain ID: {}", config.common.chain_id);
    info!("  Entrypoint: {:?}", config.common.entrypoint_address);
    info!("  Deposits: {:?}", config.common.deposits_address);
    info!("  Database: {}", config.database_path);
    info!("  Dry run: {}", config.dry_run);

    // Validate configuration
    if config.common.entrypoint_address == Address::ZERO {
        error!("Entrypoint address must be configured");
        return Err(eyre::eyre!("Entrypoint address not configured"));
    }
    if config.common.deposits_address == Address::ZERO {
        error!("Deposits address must be configured");
        return Err(eyre::eyre!("Deposits address not configured"));
    }

    // Initialize state manager
    let state = StateManager::open(&config.database_path)?;
    info!("State database opened: {}", config.database_path);

    // Connect to RPC provider
    let provider = ProviderBuilder::new()
        .connect(&config.common.rpc_url)
        .await?;
    info!("Connected to RPC: {}", config.common.rpc_url);

    // Create challenger runner
    let mut runner = ChallengerRunner::new(provider.clone(), state, &config).await?;

    // Perform health checks
    runner.perform_health_checks(&config).await?;

    // Initialize event listener
    let event_config = EventListenerConfig {
        entrypoint_address: config.common.entrypoint_address,
        lookback_blocks: config.lookback_blocks,
        poll_interval_ms: config.poll_interval_ms,
        confirmations: config.confirmations,
    };
    let mut event_listener = EventListener::new(provider.clone(), event_config);

    // Initialize from persisted state
    let start_block = runner.load_last_processed_block()?;
    event_listener.init(start_block).await?;

    // Set up graceful shutdown
    let shutdown = pgp_common::setup_shutdown_handler();

    // Run the main event loop
    let loop_config = pgp_challenger::EventLoopConfig {
        poll_interval: Duration::from_millis(config.poll_interval_ms),
        dry_run: config.dry_run,
        service_name: "Challenger",
    };

    pgp_challenger::run_event_loop(
        &mut runner,
        &mut event_listener,
        shutdown,
        loop_config,
        || async {}, // No additional per-iteration work for challenger
    )
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let args = Args::parse_from(["challenger", "--dry-run", "-v"]);
        assert!(args.dry_run);
        assert!(args.verbose);
    }
}
