//! Contract interaction helpers for the challenger.
//!
//! Provides async functions to fetch data from L1 contracts, particularly
//! the expected deposits for each L2 block from the Deposits contract.

use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use eyre::Result;
use tracing::debug;

use pgp_common::contracts::{Deposits, Entrypoint};

/// Fetches all expected deposits for a given L2 block number from the Entrypoint contract.
///
/// Uses the `getDepositArray` function to fetch all deposits in a single call.
///
/// # Arguments
/// * `provider` - The Ethereum provider
/// * `entrypoint_address` - Address of the Entrypoint contract (which handles deposits)
/// * `block_nr` - The L2 block number to fetch deposits for
///
/// # Returns
/// A vector of deposit leaf hashes in the order they were added
pub async fn fetch_expected_deposits<P: Provider + Clone>(
    provider: P,
    entrypoint_address: Address,
    block_nr: U256,
) -> Result<Vec<B256>> {
    let deposits_contract = Deposits::new(entrypoint_address, provider);

    let expected_deposits = deposits_contract.getDepositArray(block_nr).call().await?;

    debug!(
        "Fetched {} expected deposits for block {}",
        expected_deposits.len(),
        block_nr
    );

    Ok(expected_deposits)
}

/// Fetches a single deposit at a specific index for a block.
///
/// Returns None if the deposit doesn't exist (contract reverts).
pub async fn fetch_deposit_at_index<P: Provider + Clone>(
    provider: P,
    entrypoint_address: Address,
    block_nr: U256,
    index: U256,
) -> Result<Option<B256>> {
    let deposits_contract = Deposits::new(entrypoint_address, provider);

    match deposits_contract
        .perBlockDeposits(block_nr, index)
        .call()
        .await
    {
        Ok(leaf_hash) => Ok(Some(leaf_hash)),
        Err(_) => Ok(None),
    }
}

/// Fetches the genesis anchor from the Entrypoint contract.
///
/// The genesis anchor is the initial merkle root, set at contract deployment.
/// It's used as the prior anchor for the first update in the first block.
pub async fn fetch_genesis_anchor<P: Provider + Clone>(
    provider: P,
    entrypoint_address: Address,
) -> Result<B256> {
    let entrypoint = Entrypoint::new(entrypoint_address, provider);
    let genesis_anchor = entrypoint.GENESIS_ANCHOR().call().await?;
    debug!("Fetched genesis anchor: {:?}", genesis_anchor);
    Ok(genesis_anchor)
}

#[cfg(test)]
mod tests {
    // Contract interaction tests require a live RPC or mock provider
    // These would be integration tests rather than unit tests
}
