//! Client configuration.

use std::path::PathBuf;

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Path to the wallet file
    pub wallet_path: PathBuf,
    /// Sequencer API URL
    pub sequencer_url: String,
    /// Ethereum RPC URL (optional)
    pub rpc_url: Option<String>,
}

impl ClientConfig {
    /// Get the path to the proof cache file (derived from wallet path)
    pub fn cache_path(&self) -> PathBuf {
        let mut path = self.wallet_path.clone();
        path.set_extension("cache.json");
        path
    }
}
