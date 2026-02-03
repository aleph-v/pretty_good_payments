//! Client configuration.

use alloy_primitives::Address;
use std::path::PathBuf;

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Path to the wallet file
    pub wallet_path: PathBuf,
    /// Sequencer API URL
    pub sequencer_url: String,
    /// Ethereum RPC URL (optional, required for deposits/withdrawals)
    pub rpc_url: Option<String>,
    /// Ethereum private key (optional, required for deposits/withdrawals)
    pub eth_private_key: Option<String>,
    /// PGP Entrypoint contract address (optional, required for deposits/withdrawals)
    pub entrypoint_address: Option<Address>,
    /// PGP Withdraw contract address (optional, required for L1 withdrawal execution)
    pub withdraw_address: Option<Address>,
    /// Path to circuits outputs directory (for zkey files)
    pub circuits_path: Option<PathBuf>,
}

impl ClientConfig {
    /// Get the path to the proof cache file (derived from wallet path)
    pub fn cache_path(&self) -> PathBuf {
        let mut path = self.wallet_path.clone();
        path.set_extension("cache.json");
        path
    }

    /// Get the path to the pending withdrawals file (derived from wallet path)
    pub fn pending_withdrawals_path(&self) -> PathBuf {
        let mut path = self.wallet_path.clone();
        path.set_extension("pending_withdrawals.json");
        path
    }

    /// Get the path to the transfer circuit zkey file.
    pub fn transfer_zkey_path(&self) -> PathBuf {
        self.circuits_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("circuits/outputs"))
            .join("transfer/transfer.zkey")
    }
}
