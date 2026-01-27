//! Epoch timing utilities for submission window management.
//!
//! The SequencerRegistry defines epochs of 10 seconds:
//! - Closed period (0-5s): Only priority sequencers can submit
//! - Open period (5-10s): Any active sequencer with stake can submit
//!
//! This module computes epoch timing locally using the system clock after
//! fetching the contract's START time at initialization.

use crate::error::SequencerError;
use alloy::providers::Provider;
use alloy_primitives::Address;
use pgp_common::contracts::{Entrypoint, SequencerRegistry};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{debug, info};

/// Epoch duration in seconds (from SequencerRegistry.sol).
pub const EPOCH_LENGTH: u64 = 10;

/// Duration of the closed period within an epoch (first half).
pub const CLOSED_PERIOD: u64 = EPOCH_LENGTH / 2;

/// Get current Unix timestamp in seconds.
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_secs()
}

/// Watcher for epoch timing to coordinate block submissions.
///
/// After initialization, all epoch calculations are performed locally using
/// the system clock, avoiding repeated RPC calls.
pub struct EpochWatcher<P: Provider + Clone> {
    /// The contract address (Entrypoint inherits SequencerRegistry).
    registry_address: Address,
    /// The sequencer address to check permissions for.
    sequencer_address: Address,
    /// Provider for RPC calls.
    provider: P,
    /// The contract's START timestamp, fetched during initialization.
    /// This is the immutable value from the Spine contract that defines epoch 0.
    start_time: Option<u64>,
    /// Offset to convert local time to chain time (chain_time - local_time at init).
    /// This handles cases where chain time differs from local time (e.g., Anvil time manipulation).
    time_offset: i64,
    /// Whether this sequencer is in the priority list (cached at init).
    /// Priority sequencers get exclusive access during closed periods.
    is_priority: bool,
}

impl<P: Provider + Clone> EpochWatcher<P> {
    /// Create a new EpochWatcher.
    ///
    /// # Arguments
    /// * `registry_address` - The SequencerRegistry/Entrypoint contract address
    /// * `sequencer_address` - The address of this sequencer
    /// * `provider` - Provider for RPC calls
    pub fn new(registry_address: Address, sequencer_address: Address, provider: P) -> Self {
        Self {
            registry_address,
            sequencer_address,
            provider,
            start_time: None,
            time_offset: 0,
            is_priority: false,
        }
    }

    /// Get the registry contract instance.
    fn registry(&self) -> SequencerRegistry::SequencerRegistryInstance<&P> {
        SequencerRegistry::new(self.registry_address, &self.provider)
    }

    /// Get the entrypoint contract instance (for accessing START).
    fn entrypoint(&self) -> Entrypoint::EntrypointInstance<&P> {
        Entrypoint::new(self.registry_address, &self.provider)
    }

    /// Initialize the epoch watcher by fetching the contract's START time.
    ///
    /// This fetches the START timestamp from the contract and also the current
    /// block timestamp to compute the offset between local time and chain time.
    /// This handles cases where chain time differs from system time (e.g., in tests
    /// using Anvil with time manipulation).
    ///
    /// Also fetches the sequencer's priority status from the contract.
    pub async fn init(&mut self) -> Result<(), SequencerError> {
        // Query the contract's START time directly
        let entrypoint = self.entrypoint();
        let start_u256 = entrypoint.START().call().await.map_err(|e| {
            SequencerError::ContractError(format!("Failed to fetch contract START time: {e}"))
        })?;

        let start: u64 = start_u256.try_into().map_err(|_| {
            SequencerError::ContractError("START time too large for u64".to_string())
        })?;

        // Get the current block timestamp from the chain
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .map_err(|e| {
                SequencerError::ContractError(format!("Failed to fetch latest block: {e}"))
            })?
            .ok_or_else(|| SequencerError::ContractError("Latest block not found".to_string()))?;

        let chain_time: u64 = block.header.timestamp;
        let local_time = current_unix_timestamp();

        // Compute offset: positive means chain is ahead of local time
        self.time_offset = chain_time as i64 - local_time as i64;
        self.start_time = Some(start);

        // Fetch sequencer priority status
        let (is_active, is_priority, stake_amount) = self.get_sequencer_status().await?;
        self.is_priority = is_priority;

        let effective_time = (local_time as i64 + self.time_offset) as u64;
        let time_since_start = effective_time.saturating_sub(start);
        let current_epoch = time_since_start / EPOCH_LENGTH;

        info!(
            "Epoch watcher initialized: contract START={}, chain_time={}, local_time={}, offset={}, current_epoch={}",
            start, chain_time, local_time, self.time_offset, current_epoch
        );
        info!(
            "Sequencer status: active={}, priority={}, stake={}",
            is_active, is_priority, stake_amount
        );

        Ok(())
    }

    /// Get the effective chain time by applying the offset to local time.
    fn effective_chain_time(&self) -> u64 {
        let local_time = current_unix_timestamp();
        (local_time as i64 + self.time_offset) as u64
    }

    /// Get the current epoch and whether we're in the closed period.
    ///
    /// This uses the local clock after initialization, making no RPC calls.
    /// The time offset computed during init ensures calculations match chain time.
    ///
    /// # Returns
    /// A tuple of (epoch_number, is_closed).
    /// - `epoch_number`: The current epoch since contract start.
    /// - `is_closed`: True if in the first half (priority-only period).
    pub fn current_epoch(&self) -> Result<(u64, bool), SequencerError> {
        let start = self.start_time.ok_or_else(|| {
            SequencerError::ContractError("EpochWatcher not initialized".to_string())
        })?;

        let effective_time = self.effective_chain_time();
        let time_since_start = effective_time.saturating_sub(start);

        let epoch = time_since_start / EPOCH_LENGTH;
        let elapsed = time_since_start % EPOCH_LENGTH;
        let is_closed = elapsed < CLOSED_PERIOD;

        Ok((epoch, is_closed))
    }

    /// Get the time remaining until the next period transition.
    ///
    /// # Returns
    /// Duration until the next transition (closed->open or open->closed).
    pub fn time_until_transition(&self) -> Result<Duration, SequencerError> {
        let start = self.start_time.ok_or_else(|| {
            SequencerError::ContractError("EpochWatcher not initialized".to_string())
        })?;

        let effective_time = self.effective_chain_time();
        let time_since_start = effective_time.saturating_sub(start);
        let elapsed = time_since_start % EPOCH_LENGTH;

        let remaining = if elapsed < CLOSED_PERIOD {
            // In closed period, time until open
            CLOSED_PERIOD - elapsed
        } else {
            // In open period, time until next closed
            EPOCH_LENGTH - elapsed
        };

        Ok(Duration::from_secs(remaining))
    }

    /// Get the time remaining until the next open period.
    ///
    /// If already in the open period, returns Duration::ZERO.
    pub fn time_until_open(&self) -> Result<Duration, SequencerError> {
        let (_, is_closed) = self.current_epoch()?;

        if !is_closed {
            return Ok(Duration::ZERO);
        }

        self.time_until_transition()
    }

    /// Check if this sequencer is allowed to submit right now.
    ///
    /// Note: This still requires an RPC call as it checks on-chain state
    /// (sequencer active status, stake amount, priority list).
    pub async fn is_allowed(&self) -> Result<bool, SequencerError> {
        let registry = self.registry();
        let allowed = registry
            .isAllowed(self.sequencer_address)
            .call()
            .await
            .map_err(|e| {
                SequencerError::ContractError(format!("Failed to check if allowed: {e}"))
            })?;

        Ok(allowed)
    }

    /// Get the sequencer's status from the chain.
    ///
    /// Note: This requires an RPC call as it reads on-chain state.
    pub async fn get_sequencer_status(&self) -> Result<(bool, bool, u64), SequencerError> {
        let registry = self.registry();
        let status = registry
            .sequencers(self.sequencer_address)
            .call()
            .await
            .map_err(|e| {
                SequencerError::ContractError(format!("Failed to get sequencer status: {e}"))
            })?;

        Ok((status.isActive, status.isPriority, status.stakeAmount))
    }

    /// Check if this sequencer is in the priority list.
    ///
    /// This returns the cached value from initialization. Priority sequencers
    /// get exclusive access during the closed period of their assigned epoch.
    pub fn is_priority_sequencer(&self) -> bool {
        self.is_priority
    }

    /// Check if this is currently our priority turn.
    ///
    /// Returns true if:
    /// 1. We're in the closed period (first half of epoch), AND
    /// 2. We're allowed to submit (meaning we're the priority sequencer for this epoch)
    ///
    /// Note: This requires an RPC call to verify we're allowed.
    pub async fn is_our_priority_turn(&self) -> Result<bool, SequencerError> {
        let (_, is_closed) = self.current_epoch()?;

        if !is_closed {
            // Not in closed period, so not our priority turn
            return Ok(false);
        }

        // We're in closed period - check if we're allowed (only priority sequencer for this epoch is)
        self.is_allowed().await
    }

    /// Wait until we're in an open period and allowed to submit.
    ///
    /// This minimizes RPC calls by using local time calculations for epoch
    /// timing and only checking `isAllowed()` when entering an open period.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for an open period.
    ///
    /// # Returns
    /// Ok(()) if we're in an open period and allowed, Err if timeout.
    pub async fn wait_for_submission_window(
        &self,
        timeout: Duration,
    ) -> Result<(), SequencerError> {
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(SequencerError::EpochTimeout);
            }

            let (epoch, is_closed) = self.current_epoch()?;

            if is_closed {
                // Wait for open period using local time calculation
                let wait_time = self.time_until_open()?;
                debug!(
                    "Epoch {}: closed period, waiting {:?} for open period",
                    epoch, wait_time
                );

                // Add small buffer to ensure we're past the boundary
                sleep(wait_time + Duration::from_millis(100)).await;
                continue;
            }

            // We're in open period - now check if allowed (requires RPC)
            let allowed = self.is_allowed().await?;
            if allowed {
                debug!("Sequencer is allowed to submit in epoch {}", epoch);
                return Ok(());
            }

            debug!(
                "Epoch {}: open period but not allowed, waiting for next epoch",
                epoch
            );

            // Wait for next epoch
            let wait_time = self.time_until_transition()?;
            sleep(wait_time + Duration::from_millis(100)).await;
        }
    }

    /// Wait for the next open period (second half of an epoch).
    ///
    /// This uses only local time calculations, no RPC calls.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait.
    pub async fn wait_for_open_period(&self, timeout: Duration) -> Result<(), SequencerError> {
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(SequencerError::EpochTimeout);
            }

            let (epoch, is_closed) = self.current_epoch()?;

            if !is_closed {
                info!("Entered open period for epoch {}", epoch);
                return Ok(());
            }

            let wait_time = self.time_until_open()?;
            debug!(
                "Epoch {} still in closed period, waiting {:?}...",
                epoch, wait_time
            );

            // Sleep until open period (with small buffer)
            sleep(wait_time + Duration::from_millis(50)).await;
        }
    }

    /// Re-fetch the START time from the contract if needed.
    ///
    /// Since START is immutable, this will return the same value, but can be
    /// useful to verify connectivity or reset the watcher state.
    pub async fn resync(&mut self) -> Result<(), SequencerError> {
        info!("Re-fetching START time from contract...");
        self.init().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_constants() {
        assert_eq!(EPOCH_LENGTH, 10);
        assert_eq!(CLOSED_PERIOD, 5);
    }

    #[test]
    fn test_current_unix_timestamp() {
        let ts = current_unix_timestamp();
        // Should be a reasonable timestamp (after 2020)
        assert!(ts > 1577836800); // Jan 1, 2020
    }

    #[test]
    fn test_epoch_calculation_logic() {
        // Test the epoch calculation logic directly
        let base_time = 1000u64; // Simulated START time

        // At time 1005 (5 seconds after start):
        // epoch = (1005 - 1000) / 10 = 0
        // elapsed = (1005 - 1000) % 10 = 5
        // is_closed = 5 < 5 = false (open period)
        let time = 1005u64;
        let time_since_start = time - base_time;
        let epoch = time_since_start / EPOCH_LENGTH;
        let elapsed = time_since_start % EPOCH_LENGTH;
        let is_closed = elapsed < CLOSED_PERIOD;

        assert_eq!(epoch, 0);
        assert_eq!(elapsed, 5);
        assert!(!is_closed);

        // At time 1003 (3 seconds after start):
        // epoch = 0, elapsed = 3, is_closed = true
        let time = 1003u64;
        let time_since_start = time - base_time;
        let elapsed = time_since_start % EPOCH_LENGTH;
        let is_closed = elapsed < CLOSED_PERIOD;

        assert_eq!(elapsed, 3);
        assert!(is_closed);

        // At time 1015 (15 seconds after start):
        // epoch = 1, elapsed = 5, is_closed = false
        let time = 1015u64;
        let time_since_start = time - base_time;
        let epoch = time_since_start / EPOCH_LENGTH;
        let elapsed = time_since_start % EPOCH_LENGTH;
        let is_closed = elapsed < CLOSED_PERIOD;

        assert_eq!(epoch, 1);
        assert_eq!(elapsed, 5);
        assert!(!is_closed);
    }
}
