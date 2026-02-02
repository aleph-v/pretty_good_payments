//! PGP Client CLI for sending transactions.

use clap::{Parser, Subcommand};
use eyre::Result;
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod api;
mod cache;
mod commands;
mod config;
mod proof;
mod wallet;

use commands::{balance, deposit, sync, transfer, wallet as wallet_cmd, withdraw};

/// PGP Client - Command line interface for Pretty Good Payments
#[derive(Parser)]
#[command(name = "pgp-client")]
#[command(about = "CLI for interacting with Pretty Good Payments L2")]
#[command(version)]
struct Cli {
    /// Path to wallet file
    #[arg(short, long, default_value = "~/.pgp/wallet.json")]
    wallet: String,

    /// Sequencer API URL
    #[arg(short, long, default_value = "http://localhost:8080")]
    sequencer: String,

    /// Ethereum RPC URL
    #[arg(short, long, env = "ETH_RPC_URL")]
    rpc: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    /// Show wallet balance
    Balance {
        /// Filter by asset address
        #[arg(long)]
        asset: Option<String>,
    },
    /// Show transaction history
    History {
        /// Maximum number of transactions to show
        #[arg(long, default_value = "10")]
        limit: usize,
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
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
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
    let config = config::ClientConfig {
        wallet_path,
        sequencer_url: cli.sequencer,
        rpc_url: cli.rpc,
    };

    match cli.command {
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
        Commands::Balance { asset } => {
            balance::run(&config, asset.as_deref()).await?;
        }
        Commands::History { limit } => {
            println!("Transaction history (limit: {limit}) - not yet implemented");
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
    }

    Ok(())
}
