//! Common types, blob parsing, configuration, and contract bindings for PGP off-chain components.

// Allow too_many_arguments from sol! macro generated code
#![allow(clippy::too_many_arguments)]

pub mod blob;
pub mod config;
pub mod contracts;
pub mod shutdown;
pub mod types;

pub use blob::*;
pub use config::*;
pub use shutdown::*;
pub use types::*;
