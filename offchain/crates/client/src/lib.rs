//! PGP Client library for interacting with the sequencer.
//!
//! This crate provides:
//! - Wallet management (key derivation, note tracking)
//! - Proof cache for merkle proofs fetched from the sequencer
//! - HTTP client for the sequencer sync API
//! - Transaction building utilities

pub mod api;
pub mod cache;
pub mod commands;
pub mod proof;
pub mod wallet;

pub mod config;
