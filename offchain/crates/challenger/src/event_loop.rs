//! Shared event loop for challenger and sequencer binaries.
//!
//! This module provides a reusable event processing loop that handles:
//! - Polling for chain events
//! - Processing events through the ChallengerRunner
//! - Submitting fraud challenges
//! - Transaction management (begin/commit/rollback)
//! - Graceful shutdown handling

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::events::{ChainEvent, EventListener, PollResult};
use crate::runner::{fraud_type_name, ChallengerRunner, FraudWithContext};
use alloy::providers::Provider;
use pgp_common::contracts::BlockData;

/// Configuration for the event loop
#[derive(Debug, Clone)]
pub struct EventLoopConfig {
    /// Polling interval between event checks
    pub poll_interval: Duration,
    /// Whether to skip challenge submission (monitoring mode)
    pub dry_run: bool,
    /// Name for logging (e.g., "Challenger", "Sequencer")
    pub service_name: &'static str,
}

/// Result of running the event loop
#[derive(Debug)]
pub enum EventLoopExit {
    /// Shutdown signal received
    Shutdown,
    /// Fatal error occurred
    Error(String),
}

/// Run the main event processing loop.
///
/// This function encapsulates the common event loop logic used by both the
/// challenger and sequencer binaries. It handles:
/// - Retrying pending challenges
/// - Polling for new events
/// - Processing events and detecting fraud
/// - Submitting challenges
/// - Transaction management
/// - Graceful shutdown
///
/// # Arguments
/// * `runner` - The ChallengerRunner instance for event processing
/// * `event_listener` - The EventListener for polling chain events
/// * `shutdown` - Atomic flag for shutdown signaling
/// * `config` - Event loop configuration
/// * `per_iteration_hook` - Optional async callback called each iteration (for sequencer block submission)
///
/// # Returns
/// Returns `EventLoopExit` indicating how the loop terminated.
pub async fn run_event_loop<P, F, Fut>(
    runner: &mut ChallengerRunner<P>,
    event_listener: &mut EventListener<P>,
    shutdown: Arc<AtomicBool>,
    config: EventLoopConfig,
    mut per_iteration_hook: F,
) -> EventLoopExit
where
    P: Provider + Clone,
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut prior_block: Option<BlockData> = None;

    info!(
        "{}: Starting event loop, polling every {:?} (Ctrl+C to stop)",
        config.service_name, config.poll_interval
    );

    while !shutdown.load(Ordering::SeqCst) {
        // Retry pending challenges
        if !config.dry_run {
            if let Err(e) = runner.retry_pending_challenges().await {
                error!("Error retrying pending challenges: {e}");
            }
        }

        // Poll for events
        match event_listener.poll().await {
            Ok(poll_result) => {
                process_poll_result(
                    runner,
                    event_listener,
                    &poll_result,
                    &mut prior_block,
                    &shutdown,
                    &config,
                )
                .await;
            }
            Err(e) => {
                error!("Error polling for events: {e}");
            }
        }

        // Run per-iteration hook (e.g., block submission for sequencer)
        per_iteration_hook().await;

        // Sleep between polls with shutdown check
        if !interruptible_sleep(config.poll_interval, &shutdown).await {
            break;
        }
    }

    // Final state save
    info!(
        "{}: Saving final state before shutdown...",
        config.service_name
    );
    if let Err(e) = runner.save_progress(event_listener.last_processed_block()) {
        error!("Failed to save final state: {e}");
    }

    info!("{}: Shutdown complete", config.service_name);
    EventLoopExit::Shutdown
}

/// Process a poll result, handling events and submitting challenges.
async fn process_poll_result<P: Provider + Clone>(
    runner: &mut ChallengerRunner<P>,
    event_listener: &EventListener<P>,
    poll_result: &PollResult,
    prior_block: &mut Option<BlockData>,
    shutdown: &Arc<AtomicBool>,
    config: &EventLoopConfig,
) {
    // Log parse failures
    if poll_result.has_parse_failures() {
        warn!(
            "Had {} event parse failures this poll",
            poll_result.total_parse_failures()
        );
    }

    // Nothing to process
    if poll_result.events.is_empty() {
        return;
    }

    // Begin transaction
    if let Err(e) = runner.begin_transaction() {
        error!("Failed to begin transaction: {e}");
        return;
    }

    let mut transaction_ok = true;

    // Process each event
    for event in &poll_result.events {
        if shutdown.load(Ordering::SeqCst) {
            info!("Shutdown requested, stopping event processing");
            transaction_ok = false;
            break;
        }

        transaction_ok &= process_single_event(runner, event, prior_block, config).await;
    }

    // Save progress
    if transaction_ok {
        if let Err(e) = runner.save_progress(event_listener.last_processed_block()) {
            error!("Failed to save progress: {e}");
            transaction_ok = false;
        }
    }

    // Commit or rollback
    if transaction_ok {
        if let Err(e) = runner.commit_transaction() {
            error!("Failed to commit transaction: {e}");
            let _ = runner.rollback_transaction();
        }
    } else {
        info!("Rolling back transaction due to processing error or shutdown");
        let _ = runner.rollback_transaction();
    }
}

/// Process a single event and submit any detected fraud challenges.
/// Returns true if processing succeeded, false otherwise.
async fn process_single_event<P: Provider + Clone>(
    runner: &mut ChallengerRunner<P>,
    event: &ChainEvent,
    prior_block: &mut Option<BlockData>,
    config: &EventLoopConfig,
) -> bool {
    match runner.process_event(event, prior_block).await {
        Ok(fraud_list) => {
            // Submit challenges for detected fraud
            if !fraud_list.is_empty() && !config.dry_run {
                submit_fraud_challenges(runner, &fraud_list).await;
            }
            true
        }
        Err(e) => {
            error!("Error processing event: {e}");
            true // Continue processing other events
        }
    }
}

/// Submit challenges for all detected fraud, saving failures for retry.
async fn submit_fraud_challenges<P: Provider + Clone>(
    runner: &mut ChallengerRunner<P>,
    fraud_list: &[FraudWithContext],
) {
    for fraud_ctx in fraud_list {
        match runner.submit_challenge(fraud_ctx).await {
            Ok(tx_hash) => {
                info!("Challenge submitted successfully! tx: {tx_hash:?}");
            }
            Err(e) => {
                error!("Failed to submit challenge: {e}");
                let fraud_type = fraud_type_name(&fraud_ctx.fraud);
                if let Err(save_err) = runner.save_pending_challenge(fraud_ctx, &e.to_string()) {
                    error!("Failed to save pending challenge ({fraud_type}): {save_err}");
                }
            }
        }
    }
}

/// Sleep for the given duration, but return early if shutdown is requested.
/// Returns true if sleep completed normally, false if interrupted by shutdown.
async fn interruptible_sleep(duration: Duration, shutdown: &Arc<AtomicBool>) -> bool {
    tokio::select! {
        _ = sleep(duration) => true,
        _ = wait_for_shutdown(shutdown) => false,
    }
}

/// Wait until shutdown is requested.
async fn wait_for_shutdown(shutdown: &Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(100)).await;
    }
}
