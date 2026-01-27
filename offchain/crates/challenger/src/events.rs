//! Event listener for monitoring Entrypoint contract events.
//!
//! Monitors:
//! - `NewRoot` events for new L2 blocks
//! - `Rollback` events for chain reorgs
//!
//! Note: Deposit tracking is done via direct contract calls to `perBlockDeposits`
//! rather than events, as events are prone to missed slots or ordering errors.

use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use eyre::{eyre, Result, WrapErr};
use std::collections::VecDeque;
use tracing::{debug, info};

use pgp_common::contracts::{BlockData, Entrypoint};

/// Parsed NewRoot event data
#[derive(Debug, Clone)]
pub struct NewRootEvent {
    /// L2 block number
    pub block_number: U256,
    /// Merkle anchor (root) after this block
    pub anchor: B256,
    /// Hash of the L2 block data
    pub l2_block_hash: B256,
    /// Full block data
    pub block_data: BlockData,
    /// L1 block number where this event was emitted
    pub l1_block_number: u64,
    /// Transaction hash that emitted this event
    pub tx_hash: B256,
}

/// Parsed Rollback event data
#[derive(Debug, Clone)]
pub struct RollbackEvent {
    /// Block number to roll back from
    pub from: U256,
    /// Block number to roll back to
    pub to: U256,
    /// L1 block number where this event was emitted
    pub l1_block_number: u64,
}

/// Event listener configuration
#[derive(Debug, Clone)]
pub struct EventListenerConfig {
    /// Entrypoint contract address
    pub entrypoint_address: Address,
    /// Number of blocks to look back on startup
    pub lookback_blocks: u64,
    /// Polling interval in milliseconds
    pub poll_interval_ms: u64,
    /// Number of confirmations before processing
    pub confirmations: u64,
}

impl Default for EventListenerConfig {
    fn default() -> Self {
        Self {
            entrypoint_address: Address::ZERO,
            lookback_blocks: 1000, // Match ChallengerConfig default
            poll_interval_ms: 1000,
            confirmations: 6, // Match ChallengerConfig default (safer for production)
        }
    }
}

/// Event listener that polls for new events
pub struct EventListener<P> {
    provider: P,
    config: EventListenerConfig,
    last_processed_block: u64,
    #[allow(dead_code)] // Reserved for future batched event processing
    pending_events: VecDeque<ChainEvent>,
}

/// Union type for all monitored events
#[derive(Debug, Clone)]
pub enum ChainEvent {
    NewRoot(NewRootEvent),
    Rollback(RollbackEvent),
}

/// Result of polling for events, including any parse failures
#[derive(Debug, Clone, Default)]
pub struct PollResult {
    /// Successfully parsed events
    pub events: Vec<ChainEvent>,
    /// Number of NewRoot logs that failed to parse
    pub new_root_parse_failures: usize,
    /// Number of Rollback logs that failed to parse
    pub rollback_parse_failures: usize,
}

impl PollResult {
    /// Check if any parse failures occurred
    pub fn has_parse_failures(&self) -> bool {
        self.new_root_parse_failures > 0 || self.rollback_parse_failures > 0
    }

    /// Total number of parse failures
    pub fn total_parse_failures(&self) -> usize {
        self.new_root_parse_failures + self.rollback_parse_failures
    }
}

impl<P: Provider + Clone> EventListener<P> {
    /// Create a new event listener
    pub fn new(provider: P, config: EventListenerConfig) -> Self {
        Self {
            provider,
            config,
            last_processed_block: 0,
            pending_events: VecDeque::new(),
        }
    }

    /// Initialize the listener, optionally starting from a specific block
    pub async fn init(&mut self, start_block: Option<u64>) -> Result<()> {
        let current_block = self.provider.get_block_number().await?;

        self.last_processed_block = match start_block {
            Some(block) => block,
            None => current_block.saturating_sub(self.config.lookback_blocks),
        };

        info!(
            "Event listener initialized, starting from block {}",
            self.last_processed_block
        );

        Ok(())
    }

    /// Poll for new events since last processed block
    ///
    /// Returns a PollResult containing successfully parsed events and counts of any parse failures.
    /// Parse failures are logged as errors and counted, but don't abort the polling operation.
    pub async fn poll(&mut self) -> Result<PollResult> {
        let current_block = self.provider.get_block_number().await?;

        // Apply confirmations
        let safe_block = current_block.saturating_sub(self.config.confirmations);

        if safe_block <= self.last_processed_block {
            return Ok(PollResult::default());
        }

        let from_block = self.last_processed_block + 1;
        let to_block = safe_block;

        debug!(
            "Polling for events from block {} to {}",
            from_block, to_block
        );

        let mut result = PollResult::default();

        // Fetch NewRoot events
        let (new_root_events, new_root_failures) =
            self.fetch_new_root_events(from_block, to_block).await?;
        result
            .events
            .extend(new_root_events.into_iter().map(ChainEvent::NewRoot));
        result.new_root_parse_failures = new_root_failures;

        // Fetch Rollback events
        let (rollback_events, rollback_failures) =
            self.fetch_rollback_events(from_block, to_block).await?;
        result
            .events
            .extend(rollback_events.into_iter().map(ChainEvent::Rollback));
        result.rollback_parse_failures = rollback_failures;

        // Sort events by L1 block number
        result.events.sort_by_key(|e| match e {
            ChainEvent::NewRoot(e) => e.l1_block_number,
            ChainEvent::Rollback(e) => e.l1_block_number,
        });

        self.last_processed_block = to_block;

        if !result.events.is_empty() {
            info!(
                "Found {} events in blocks {}-{}",
                result.events.len(),
                from_block,
                to_block
            );
        }

        if result.has_parse_failures() {
            // Log as error so it's more visible in production
            tracing::error!(
                "Event parse failures in blocks {}-{}: {} NewRoot, {} Rollback",
                from_block,
                to_block,
                result.new_root_parse_failures,
                result.rollback_parse_failures
            );
        }

        Ok(result)
    }

    /// Fetch NewRoot events from the Entrypoint contract
    ///
    /// Returns (events, failure_count) where failure_count is the number of logs that failed to parse.
    async fn fetch_new_root_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<(Vec<NewRootEvent>, usize)> {
        let filter = Filter::new()
            .address(self.config.entrypoint_address)
            .event_signature(Entrypoint::NewRoot::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.provider.get_logs(&filter).await?;

        let mut events = Vec::new();
        let mut failures = 0;
        for log in logs {
            match self.parse_new_root_log(&log) {
                Ok(event) => events.push(event),
                Err(e) => {
                    // Log each failure with full details for debugging
                    tracing::error!(
                        "Failed to parse NewRoot log at block {:?}, tx {:?}: {}",
                        log.block_number,
                        log.transaction_hash,
                        e
                    );
                    failures += 1;
                }
            }
        }

        Ok((events, failures))
    }

    /// Parse a NewRoot log into a structured event
    fn parse_new_root_log(&self, log: &Log) -> Result<NewRootEvent> {
        let decoded = Entrypoint::NewRoot::decode_log(log.as_ref())
            .wrap_err("Failed to decode NewRoot event")?;

        Ok(NewRootEvent {
            block_number: decoded.data.blocknumber,
            anchor: decoded.data.anchor,
            l2_block_hash: decoded.data.l2BlockHash,
            block_data: decoded.data.data,
            l1_block_number: log
                .block_number
                .ok_or_else(|| eyre!("Missing block number"))?,
            tx_hash: log
                .transaction_hash
                .ok_or_else(|| eyre!("Missing tx hash"))?,
        })
    }

    /// Fetch Rollback events
    ///
    /// Returns (events, failure_count) where failure_count is the number of logs that failed to parse.
    async fn fetch_rollback_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<(Vec<RollbackEvent>, usize)> {
        let filter = Filter::new()
            .address(self.config.entrypoint_address)
            .event_signature(Entrypoint::Rollback::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.provider.get_logs(&filter).await?;

        let mut events = Vec::new();
        let mut failures = 0;
        for log in logs {
            match self.parse_rollback_log(&log) {
                Ok(event) => events.push(event),
                Err(e) => {
                    // Log each failure with full details for debugging
                    tracing::error!(
                        "Failed to parse Rollback log at block {:?}, tx {:?}: {}",
                        log.block_number,
                        log.transaction_hash,
                        e
                    );
                    failures += 1;
                }
            }
        }

        Ok((events, failures))
    }

    /// Parse a Rollback log
    fn parse_rollback_log(&self, log: &Log) -> Result<RollbackEvent> {
        let decoded = Entrypoint::Rollback::decode_log(log.as_ref())
            .wrap_err("Failed to decode Rollback event")?;

        Ok(RollbackEvent {
            from: decoded.data.from,
            to: decoded.data.to,
            l1_block_number: log
                .block_number
                .ok_or_else(|| eyre!("Missing block number"))?,
        })
    }

    /// Get the last processed block number
    pub fn last_processed_block(&self) -> u64 {
        self.last_processed_block
    }

    /// Set the last processed block number (for recovery)
    pub fn set_last_processed_block(&mut self, block: u64) {
        self.last_processed_block = block;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_listener_config_default() {
        let config = EventListenerConfig::default();
        assert_eq!(config.entrypoint_address, Address::ZERO);
        assert_eq!(config.lookback_blocks, 1000); // Updated for production
        assert_eq!(config.poll_interval_ms, 1000);
        assert_eq!(config.confirmations, 6); // Updated for production
    }
}
