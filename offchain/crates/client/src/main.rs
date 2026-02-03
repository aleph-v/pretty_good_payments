//! PGP Client CLI for sending transactions.

use clap::{Parser, Subcommand};
use eyre::Result;
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// Use the library modules instead of inline mod declarations.
// This ensures the binary uses the same compiled code as the library,
// including the rust-witness generated native code linked via build.rs.
use pgp_client::commands::{
    consolidate, deposit, status, sync, transfer, wallet as wallet_cmd, withdraw, withdraw_execute,
};
use pgp_client::config;

/// PGP Client - Command line interface for Pretty Good Payments
#[derive(Parser)]
#[command(name = "pgp-client")]
#[command(about = "CLI for interacting with Pretty Good Payments L2")]
#[command(version)]
struct Cli {
    /// Path to wallet file
    #[arg(short, long, default_value = "~/.pgp/wallet.json")]
    wallet: String,

    /// Sequencer API URL (default is localhost for development)
    #[arg(
        short,
        long,
        default_value = "http://localhost:8080",
        env = "PGP_SEQUENCER_URL"
    )]
    sequencer: String,

    /// Ethereum RPC URL (required for deposits/withdrawals)
    #[arg(short, long, env = "ETH_RPC_URL")]
    rpc: Option<String>,

    /// Ethereum private key for signing L1 transactions (required for deposits/withdrawals)
    #[arg(long, env = "ETH_PRIVATE_KEY")]
    eth_key: Option<String>,

    /// PGP Entrypoint contract address (required for deposits/withdrawals)
    #[arg(long, env = "PGP_ENTRYPOINT")]
    entrypoint: Option<String>,

    /// PGP Withdraw contract address (required for L1 withdrawal execution)
    #[arg(long, env = "PGP_WITHDRAW")]
    withdraw_contract: Option<String>,

    /// Path to circuits outputs directory
    #[arg(short = 'c', long, default_value = "circuits/outputs")]
    circuits: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show wallet and system status overview
    Status,
    /// Wallet management commands
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Sync merkle state from sequencer
    Sync {
        /// Perform full sync (re-fetch all proofs)
        #[arg(long)]
        full: bool,
    },
    /// Transfer tokens on L2
    Transfer {
        /// Recipient public key (hex)
        to: String,
        /// Amount to transfer
        amount: String,
        /// Asset address (defaults to native token)
        #[arg(long)]
        asset: Option<String>,
    },
    /// Deposit from L1 to L2
    Deposit {
        /// Amount to deposit
        amount: String,
        /// Asset address (defaults to native token)
        #[arg(long)]
        asset: Option<String>,
    },
    /// Withdraw from L2 to L1
    Withdraw {
        /// L1 recipient address
        to: String,
        /// Amount to withdraw
        amount: String,
        /// Asset address (defaults to native token)
        #[arg(long)]
        asset: Option<String>,
    },
    /// Consolidate multiple notes into fewer notes
    Consolidate {
        /// Asset address to consolidate (consolidates all assets if not specified)
        #[arg(long)]
        asset: Option<String>,
    },
    /// Execute a pending L1 withdrawal (Stage 2)
    WithdrawExecute {
        /// Index of the pending withdrawal to execute
        #[arg(long)]
        index: Option<usize>,
    },
    /// List pending withdrawals
    WithdrawList,
    /// Update a pending withdrawal with block info
    WithdrawUpdate {
        /// Index of the pending withdrawal to update
        index: usize,
        /// Block number where the withdrawal was included
        #[arg(long)]
        block_nr: u64,
        /// Transaction index within the block
        #[arg(long)]
        tx_nr: u64,
        /// Output index within the transaction (0, 1, or 2)
        #[arg(long)]
        output_index: u8,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Seed phrase (BIP39 mnemonic)
        #[arg(long)]
        seed: Option<String>,
    },
    /// Show wallet info
    Info,
    /// Export seed phrase
    Export,
    /// Import wallet from seed phrase
    Import {
        /// Seed phrase (BIP39 mnemonic)
        seed: String,
    },
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

/// Parse an address from a CLI argument with a descriptive error message.
fn parse_address_arg(s: &str, arg_name: &str) -> Result<alloy_primitives::Address> {
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s)
        .map_err(|e| eyre::eyre!("Invalid {} address '{}': not valid hex. {}", arg_name, s, e))?;
    if bytes.len() != 20 {
        eyre::bail!(
            "Invalid {} address '{}': expected 20 bytes (40 hex chars), got {} bytes",
            arg_name,
            s,
            bytes.len()
        );
    }
    Ok(alloy_primitives::Address::from_slice(&bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    let wallet_path = expand_tilde(&cli.wallet);
    let circuits_path = expand_tilde(&cli.circuits);

    // Parse entrypoint address if provided
    let entrypoint_address = cli
        .entrypoint
        .as_ref()
        .map(|s| parse_address_arg(s, "entrypoint"))
        .transpose()?;

    // Parse withdraw contract address if provided
    let withdraw_address = cli
        .withdraw_contract
        .as_ref()
        .map(|s| parse_address_arg(s, "withdraw contract"))
        .transpose()?;

    let config = config::ClientConfig {
        wallet_path,
        sequencer_url: cli.sequencer,
        rpc_url: cli.rpc,
        eth_private_key: cli.eth_key,
        entrypoint_address,
        withdraw_address,
        circuits_path: Some(circuits_path),
    };

    match cli.command {
        Commands::Status => {
            status::run(&config).await?;
        }
        Commands::Wallet { command } => match command {
            WalletCommands::Create { seed } => {
                wallet_cmd::create(&config, seed.as_deref()).await?;
            }
            WalletCommands::Info => {
                wallet_cmd::info(&config).await?;
            }
            WalletCommands::Export => {
                wallet_cmd::export(&config).await?;
            }
            WalletCommands::Import { seed } => {
                wallet_cmd::import(&config, &seed).await?;
            }
        },
        Commands::Sync { full } => {
            sync::run(&config, full).await?;
        }
        Commands::Transfer { to, amount, asset } => {
            transfer::run(&config, &to, &amount, asset.as_deref()).await?;
        }
        Commands::Deposit { amount, asset } => {
            deposit::run(&config, &amount, asset.as_deref()).await?;
        }
        Commands::Withdraw { to, amount, asset } => {
            withdraw::run(&config, &to, &amount, asset.as_deref()).await?;
        }
        Commands::Consolidate { asset } => {
            consolidate::run(&config, asset.as_deref()).await?;
        }
        Commands::WithdrawExecute { index } => {
            withdraw_execute::run(&config, index).await?;
        }
        Commands::WithdrawList => {
            withdraw_execute::list(&config).await?;
        }
        Commands::WithdrawUpdate {
            index,
            block_nr,
            tx_nr,
            output_index,
        } => {
            withdraw_execute::update(&config, index, block_nr, tx_nr, output_index).await?;
        }
    }

    Ok(())
}
