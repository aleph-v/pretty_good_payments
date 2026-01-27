//! PGP Sequencer - Block building and submission for Pretty Good Payments.
//!
//! This crate provides the core components for sequencing L2 blocks:
//! - `BlobBuilder`: Constructs blob data from deposits and transactions
//! - `BlockSubmitter`: Submits blocks to the Entrypoint contract
//! - `EpochWatcher`: Monitors epoch timing for submission windows
//! - `BlockBuilderConfig`: Configuration and orchestration for block building
//! - `Mempool`: FIFO queue for pending transactions with batched submission
//! - `api`: REST API for transaction submission
//!
//! State is shared with the challenger via `pgp_challenger::StateManager`.
//! Anchor computation uses `BlockTreeBuilder` and `RootTreeTracker` from the challenger.

pub mod api;
pub mod blob_builder;
pub mod block_builder_loop;
pub mod block_submitter;
pub mod epoch;
pub mod error;
pub mod mempool;

pub use api::{create_router, start_api_server, ApiState};
pub use blob_builder::{
    combine_blobs_into_sidecar, combine_blobs_into_sidecar_simple, create_raw_sidecar, BlobBuilder,
    BuiltBlob, BuiltBlock, MAX_BLOBS_PER_BLOCK,
};
pub use block_builder_loop::{
    run_block_builder, try_build_and_submit_block, BlockBuildResult, BlockBuilderConfig,
    MAX_TRANSACTIONS_10_BLOBS,
};
pub use block_submitter::{
    create_config, create_wallet, BlockSubmitter, SubmissionResult, SubmitterConfig,
};
pub use epoch::EpochWatcher;
pub use error::SequencerError;
pub use mempool::{
    AddResult, Mempool, MempoolConfig, MempoolTransaction, ValidationError, TRANSACTIONS_PER_BLOB,
};
