//! PGP Challenger library - Fraud detection for Pretty Good Payments
//!
//! This library provides fraud detection and validation for L2 blocks.

// Allow clippy lints for complex domain-specific code
#![allow(clippy::too_many_arguments)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::type_complexity)]

pub mod beacon;
pub mod challenge;
pub mod circom_prover;
pub mod contracts;
pub mod event_loop;
pub mod events;
pub mod groth16;
pub mod kzg;
pub mod runner;
pub mod state;
pub mod validators;

pub use beacon::{
    create_production_blob_provider, BeaconBlobProvider, BlobProvider, CachingBlobProvider,
    DatabaseBlobProvider, ExecutionBlobProvider, FallbackBlobProvider,
};
pub use challenge::{
    memory, BlobWithHash, ChallengeBuilder, ChallengeSubmitter, DepositChallengeParams,
    NullifierChallengeParams, TransactionChallengeParams, TreeUpdateChallengeParams,
};
pub use circom_prover::{generate_tree_update_proof, RustCircomProver};
pub use event_loop::{run_event_loop, EventLoopConfig, EventLoopExit};
pub use events::{ChainEvent, EventListener, EventListenerConfig, PollResult};
pub use groth16::{Groth16Verifier, TransferPublicInputs, UpdatePublicInputs};
pub use kzg::{KzgFieldProof, KzgProver};
pub use runner::{default_block_data, fraud_type_name, ChallengerRunner, FraudWithContext};
pub use state::{PendingChallenge, StateManager};
pub use validators::{
    compute_anchor_from_path, AnchorLookup, BlockTreeTracker, DepositValidator, FraudEvidence,
    NullifierValidator, RootTreeTracker, TransactionValidator, TreeUpdateMerkleData,
    TreeUpdateValidator, BLOCKS_PER_DAY,
};
// ChallengerRunnerConfig is re-exported from pgp_common
