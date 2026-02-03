//! HTTP client for the sequencer sync API.

use crate::api::types::*;
use eyre::{Result, WrapErr};
use pgp_common::types::ParsedTransaction;
use reqwest::Client;

/// HTTP client for interacting with the sequencer API.
pub struct SequencerClient {
    base_url: String,
    client: Client,
}

impl SequencerClient {
    /// Create a new sequencer client.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }

    /// Get sync status from the sequencer.
    pub async fn get_sync_status(&self) -> Result<SyncStatusResponse> {
        let url = format!("{}/sync/status", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to connect to sequencer")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eyre::bail!("Sync status request failed: {} - {}", status, body);
        }

        response
            .json()
            .await
            .wrap_err("Failed to parse sync status response")
    }

    /// Get day roots for a range of days.
    pub async fn get_day_roots(&self, from_day: u16, to_day: u16) -> Result<DayRootsResponse> {
        let url = format!(
            "{}/sync/day-roots?from={}&to={}",
            self.base_url, from_day, to_day
        );
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to get day roots")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eyre::bail!("Day roots request failed: {} - {}", status, body);
        }

        response
            .json()
            .await
            .wrap_err("Failed to parse day roots response")
    }

    /// Get block roots for a specific day.
    pub async fn get_block_roots(&self, day: u16) -> Result<BlockRootsResponse> {
        let url = format!("{}/sync/block-roots?day={}", self.base_url, day);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to get block roots")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eyre::bail!("Block roots request failed: {} - {}", status, body);
        }

        response
            .json()
            .await
            .wrap_err("Failed to parse block roots response")
    }

    /// Get the day path (15-level siblings from day to global root).
    pub async fn get_day_path(&self, day: u16) -> Result<DayPathResponse> {
        let url = format!("{}/sync/day-path?day={}", self.base_url, day);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to get day path")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eyre::bail!("Day path request failed: {} - {}", status, body);
        }

        response
            .json()
            .await
            .wrap_err("Failed to parse day path response")
    }

    /// Get the block-in-day path (13-level siblings from block to day root).
    pub async fn get_block_path(
        &self,
        day: u16,
        block_in_day: u16,
    ) -> Result<BlockInDayPathResponse> {
        let url = format!(
            "{}/sync/block-path?day={}&block={}",
            self.base_url, day, block_in_day
        );
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to get block path")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eyre::bail!("Block path request failed: {} - {}", status, body);
        }

        response
            .json()
            .await
            .wrap_err("Failed to parse block path response")
    }

    /// Get the 16-level block tree proof for a specific leaf.
    pub async fn get_block_tree_proof(
        &self,
        block_nr: u64,
        leaf_index: u32,
    ) -> Result<BlockTreeProofResponse> {
        let url = format!(
            "{}/sync/block-tree-proof?block_nr={}&leaf_index={}",
            self.base_url, block_nr, leaf_index
        );
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to get block tree proof")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eyre::bail!("Block tree proof request failed: {} - {}", status, body);
        }

        response
            .json()
            .await
            .wrap_err("Failed to parse block tree proof response")
    }

    /// Get the full 44-level proof for a specific leaf.
    pub async fn get_full_proof(
        &self,
        block_nr: u64,
        leaf_index: u32,
    ) -> Result<FullProofResponse> {
        let url = format!(
            "{}/sync/full-proof?block_nr={}&leaf_index={}",
            self.base_url, block_nr, leaf_index
        );
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to get full proof")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eyre::bail!("Full proof request failed: {} - {}", status, body);
        }

        response
            .json()
            .await
            .wrap_err("Failed to parse full proof response")
    }

    /// Submit a transaction to the mempool.
    pub async fn submit_transaction(&self, tx: ParsedTransaction) -> Result<SubmitTxResponse> {
        let url = format!("{}/tx", self.base_url);
        let request = SubmitTxRequest { transaction: tx };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .wrap_err("Failed to submit transaction")?;

        let status = response.status();
        let body: SubmitTxResponse = response
            .json()
            .await
            .wrap_err("Failed to parse transaction response")?;

        if !status.is_success() && !body.accepted {
            eyre::bail!("Transaction rejected: {}", body.message);
        }

        Ok(body)
    }

    /// Get a withdrawal proof for executing an L1 withdrawal.
    ///
    /// This searches for a leaf commitment in a specific block and returns
    /// the KZG proof needed to withdraw on L1.
    pub async fn get_withdrawal_proof(
        &self,
        leaf_commitment: alloy_primitives::B256,
        block_nr: u64,
    ) -> Result<WithdrawalProofResponse> {
        let url = format!("{}/withdrawal-proof", self.base_url);
        let request = WithdrawalProofRequest {
            leaf_commitment,
            block_nr,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .wrap_err("Failed to get withdrawal proof")?;

        response
            .json()
            .await
            .wrap_err("Failed to parse withdrawal proof response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = SequencerClient::new("http://localhost:8080");
        assert_eq!(client.base_url, "http://localhost:8080");

        // Trailing slash should be trimmed
        let client2 = SequencerClient::new("http://localhost:8080/");
        assert_eq!(client2.base_url, "http://localhost:8080");
    }
}
