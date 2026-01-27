//! Graceful shutdown signal handling utilities.
//!
//! Provides a unified way to handle shutdown signals (Ctrl+C, SIGTERM) across
//! both the challenger and sequencer binaries.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info};

/// Sets up graceful shutdown signal handling for Ctrl+C and SIGTERM.
///
/// Returns an `Arc<AtomicBool>` that becomes `true` when a shutdown signal is received.
/// The calling code should periodically check this flag and initiate cleanup when set.
///
/// # Example
///
/// ```ignore
/// let shutdown = setup_shutdown_handler();
///
/// while !shutdown.load(Ordering::SeqCst) {
///     // Main loop work...
/// }
///
/// // Cleanup after shutdown signal
/// ```
pub fn setup_shutdown_handler() -> Arc<AtomicBool> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let ctrl_c = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => info!("Received Ctrl+C, initiating graceful shutdown..."),
                Err(e) => error!("Failed to listen for Ctrl+C: {e}"),
            }
        };

        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                    info!("Received SIGTERM, initiating graceful shutdown...");
                }
                Err(e) => {
                    error!("Failed to listen for SIGTERM: {e}");
                    std::future::pending::<()>().await;
                }
            }
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate => {}
        }

        shutdown_clone.store(true, Ordering::SeqCst);
    });

    shutdown
}

/// Check if shutdown has been requested.
///
/// Convenience wrapper around `shutdown.load(Ordering::SeqCst)`.
#[inline]
pub fn is_shutdown_requested(shutdown: &Arc<AtomicBool>) -> bool {
    shutdown.load(Ordering::SeqCst)
}
