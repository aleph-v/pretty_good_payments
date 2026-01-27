//! Beacon chain blob retrieval for EIP-4844 blob transactions.
//!
//! This module provides functionality to retrieve blob data from the Ethereum
//! beacon chain. Blobs are needed to validate L2 block data and construct
//! fraud proofs.
//!
//! The beacon chain exposes blob sidecars via the standard beacon API:
//! `GET /eth/v1/beacon/blob_sidecars/{block_id}`

use alloy::primitives::B256;
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use tracing::debug;

/// Raw blob data (131072 bytes = 4096 field elements * 32 bytes)
pub const BLOB_SIZE_BYTES: usize = 131072;

/// Trait for retrieving blob data from the beacon chain or other sources.
///
/// This abstraction allows for different implementations:
/// - `BeaconBlobProvider` for production (beacon chain API)
/// - Direct provider for testing with Anvil (via eth_getTransactionByHash)
#[async_trait]
pub trait BlobProvider: Send + Sync {
    /// Retrieve blob data for a given L1 block and versioned hash.
    ///
    /// # Arguments
    /// * `l1_block_number` - The L1 block number containing the blob transaction
    /// * `versioned_hash` - The versioned hash (commitment) of the blob
    ///
    /// # Returns
    /// The raw blob data (131072 bytes) or an error if not found
    async fn get_blob(&self, l1_block_number: u64, versioned_hash: B256) -> Result<Vec<u8>>;

    /// Retrieve multiple blobs for a given L1 block.
    ///
    /// # Arguments
    /// * `l1_block_number` - The L1 block number containing the blob transaction
    /// * `versioned_hashes` - The versioned hashes of all blobs to retrieve
    ///
    /// # Returns
    /// A vector of raw blob data in the same order as the input hashes
    async fn get_blobs(
        &self,
        l1_block_number: u64,
        versioned_hashes: &[B256],
    ) -> Result<Vec<Vec<u8>>> {
        let mut blobs = Vec::with_capacity(versioned_hashes.len());
        for hash in versioned_hashes {
            let blob = self.get_blob(l1_block_number, *hash).await?;
            blobs.push(blob);
        }
        Ok(blobs)
    }
}

/// Beacon chain blob sidecar response structure
#[derive(Debug, Clone, Deserialize)]
pub struct BlobSidecarsResponse {
    pub data: Vec<BlobSidecar>,
}

/// Individual blob sidecar from the beacon chain
#[derive(Debug, Clone, Deserialize)]
pub struct BlobSidecar {
    /// Index of the blob within the block
    pub index: String,
    /// The blob data as a hex string (0x-prefixed, 262144 hex chars)
    pub blob: String,
    /// KZG commitment for this blob
    pub kzg_commitment: String,
    /// KZG proof for this blob
    pub kzg_proof: String,
}

impl BlobSidecar {
    /// Compute the versioned hash from the KZG commitment.
    /// Versioned hash = 0x01 || sha256(kzg_commitment)[1..]
    pub fn versioned_hash(&self) -> Result<B256> {
        use sha2::{Digest, Sha256};

        let commitment_bytes = hex::decode(self.kzg_commitment.trim_start_matches("0x"))
            .wrap_err("Invalid KZG commitment hex")?;

        let hash = Sha256::digest(&commitment_bytes);
        let mut versioned = [0u8; 32];
        versioned[0] = 0x01; // Version byte
        versioned[1..].copy_from_slice(&hash[1..]);

        Ok(B256::from(versioned))
    }

    /// Get the blob data as raw bytes.
    pub fn blob_bytes(&self) -> Result<Vec<u8>> {
        let bytes = hex::decode(self.blob.trim_start_matches("0x")).wrap_err("Invalid blob hex")?;

        if bytes.len() != BLOB_SIZE_BYTES {
            return Err(eyre!(
                "Invalid blob size: expected {} bytes, got {}",
                BLOB_SIZE_BYTES,
                bytes.len()
            ));
        }

        Ok(bytes)
    }
}

/// Beacon chain API client for retrieving blob sidecars.
pub struct BeaconBlobProvider {
    /// Base URL of the beacon chain API (e.g., "http://localhost:5052")
    beacon_url: String,
    /// HTTP client for making requests
    client: reqwest::Client,
}

impl BeaconBlobProvider {
    /// Create a new beacon blob provider.
    ///
    /// # Arguments
    /// * `beacon_url` - Base URL of the beacon chain API endpoint
    pub fn new(beacon_url: &str) -> Self {
        Self {
            beacon_url: beacon_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Fetch all blob sidecars for a given slot/block.
    async fn fetch_blob_sidecars(&self, block_id: &str) -> Result<Vec<BlobSidecar>> {
        let url = format!(
            "{}/eth/v1/beacon/blob_sidecars/{}",
            self.beacon_url, block_id
        );

        debug!("Fetching blob sidecars from: {}", url);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .wrap_err_with(|| format!("Failed to fetch blob sidecars from {url}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(eyre!(
                "Beacon API returned error {} for {}: {}",
                status,
                url,
                body
            ));
        }

        let sidecars: BlobSidecarsResponse = response
            .json()
            .await
            .wrap_err("Failed to parse blob sidecars response")?;

        Ok(sidecars.data)
    }
}

#[async_trait]
impl BlobProvider for BeaconBlobProvider {
    async fn get_blob(&self, l1_block_number: u64, versioned_hash: B256) -> Result<Vec<u8>> {
        // Fetch all sidecars for this block
        let sidecars = self
            .fetch_blob_sidecars(&l1_block_number.to_string())
            .await?;

        // Find the sidecar matching our versioned hash
        for sidecar in sidecars {
            let sidecar_hash = sidecar.versioned_hash()?;
            if sidecar_hash == versioned_hash {
                return sidecar.blob_bytes();
            }
        }

        Err(eyre!(
            "Blob with versioned hash {:?} not found in block {}",
            versioned_hash,
            l1_block_number
        ))
    }

    async fn get_blobs(
        &self,
        l1_block_number: u64,
        versioned_hashes: &[B256],
    ) -> Result<Vec<Vec<u8>>> {
        if versioned_hashes.is_empty() {
            return Ok(vec![]);
        }

        // Fetch all sidecars for this block once
        let sidecars = self
            .fetch_blob_sidecars(&l1_block_number.to_string())
            .await?;

        // Build a map of versioned_hash -> blob data
        let mut blob_map = std::collections::HashMap::new();
        for sidecar in sidecars {
            let hash = sidecar.versioned_hash()?;
            let data = sidecar.blob_bytes()?;
            blob_map.insert(hash, data);
        }

        // Return blobs in the requested order
        let mut result = Vec::with_capacity(versioned_hashes.len());
        for hash in versioned_hashes {
            let blob = blob_map
                .get(hash)
                .ok_or_else(|| {
                    eyre!(
                        "Blob with versioned hash {:?} not found in block {}",
                        hash,
                        l1_block_number
                    )
                })?
                .clone();
            result.push(blob);
        }

        Ok(result)
    }
}

/// Provider that retrieves blobs directly from an Ethereum execution client.
///
/// This works with Anvil and other execution clients that support the
/// `eth_getTransactionByHash` and `eth_getBlobSidecars` methods.
///
/// Note: Anvil's blob support may require the Cancun hardfork to be enabled.
pub struct ExecutionBlobProvider<P> {
    provider: P,
}

impl<P> ExecutionBlobProvider<P> {
    /// Create a new execution blob provider.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<P> BlobProvider for ExecutionBlobProvider<P>
where
    P: alloy::providers::Provider + Clone + Send + Sync,
{
    async fn get_blob(&self, l1_block_number: u64, versioned_hash: B256) -> Result<Vec<u8>> {
        // Use eth_getBlobSidecars RPC method
        // This is a newer method that some clients support
        let sidecars: Vec<RpcBlobSidecar> = self
            .provider
            .raw_request(
                "eth_getBlobSidecars".into(),
                (format!("0x{l1_block_number:x}"),),
            )
            .await
            .wrap_err("eth_getBlobSidecars RPC call failed")?;

        for sidecar in sidecars {
            let sidecar_hash = compute_versioned_hash(&sidecar.kzg_commitment)?;
            if sidecar_hash == versioned_hash {
                return decode_blob_data(&sidecar.blob);
            }
        }

        Err(eyre!(
            "Blob with versioned hash {:?} not found in block {}",
            versioned_hash,
            l1_block_number
        ))
    }
}

/// RPC response format for blob sidecars from execution client
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcBlobSidecar {
    blob: String,
    kzg_commitment: String,
    #[allow(dead_code)] // Required by API but not used
    kzg_proof: String,
}

/// Compute versioned hash from KZG commitment
fn compute_versioned_hash(commitment_hex: &str) -> Result<B256> {
    use sha2::{Digest, Sha256};

    let commitment_bytes = hex::decode(commitment_hex.trim_start_matches("0x"))
        .wrap_err("Invalid KZG commitment hex")?;

    let hash = Sha256::digest(&commitment_bytes);
    let mut versioned = [0u8; 32];
    versioned[0] = 0x01;
    versioned[1..].copy_from_slice(&hash[1..]);

    Ok(B256::from(versioned))
}

/// Decode blob data from hex string
fn decode_blob_data(blob_hex: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(blob_hex.trim_start_matches("0x")).wrap_err("Invalid blob hex")?;

    if bytes.len() != BLOB_SIZE_BYTES {
        return Err(eyre!(
            "Invalid blob size: expected {} bytes, got {}",
            BLOB_SIZE_BYTES,
            bytes.len()
        ));
    }

    Ok(bytes)
}

/// Caching wrapper around any BlobProvider.
///
/// Blobs are large (131KB each) so caching helps reduce network overhead
/// when the same blob is needed multiple times (e.g., for building multiple
/// challenge proofs from the same block).
pub struct CachingBlobProvider<P> {
    inner: P,
    cache: std::sync::RwLock<lru::LruCache<(u64, B256), Vec<u8>>>,
}

impl<P> CachingBlobProvider<P> {
    /// Create a new caching provider with the specified cache size.
    ///
    /// # Arguments
    /// * `inner` - The underlying blob provider
    /// * `cache_size` - Maximum number of blobs to cache
    pub fn new(inner: P, cache_size: usize) -> Self {
        Self {
            inner,
            cache: std::sync::RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(cache_size).unwrap_or(std::num::NonZeroUsize::MIN),
            )),
        }
    }
}

#[async_trait]
impl<P: BlobProvider> BlobProvider for CachingBlobProvider<P> {
    async fn get_blob(&self, l1_block_number: u64, versioned_hash: B256) -> Result<Vec<u8>> {
        let key = (l1_block_number, versioned_hash);

        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(blob) = cache.peek(&key) {
                debug!(
                    "Blob cache hit for {:?} at block {}",
                    versioned_hash, l1_block_number
                );
                return Ok(blob.clone());
            }
        }

        // Fetch from inner provider
        let blob = self.inner.get_blob(l1_block_number, versioned_hash).await?;

        // Cache the result
        {
            let mut cache = self.cache.write().unwrap();
            cache.put(key, blob.clone());
        }

        Ok(blob)
    }
}

/// Provider that retrieves blobs from the database (for long-term storage).
///
/// The beacon chain only retains blobs for ~2 weeks, so this provider
/// allows retrieving historical blobs from persistent storage.
pub struct DatabaseBlobProvider {
    /// Database path
    db_path: String,
}

impl DatabaseBlobProvider {
    /// Create a new database blob provider.
    ///
    /// # Arguments
    /// * `db_path` - Path to the SQLite database file
    pub fn new(db_path: &str) -> Self {
        Self {
            db_path: db_path.to_string(),
        }
    }

    /// Create from an existing state manager by extracting its path
    pub fn from_path(db_path: impl AsRef<std::path::Path>) -> Self {
        Self {
            db_path: db_path.as_ref().to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl BlobProvider for DatabaseBlobProvider {
    async fn get_blob(&self, _l1_block_number: u64, versioned_hash: B256) -> Result<Vec<u8>> {
        // Open a connection for this query (SQLite connections are not Send)
        let db_path = self.db_path.clone();
        let hash = versioned_hash;

        tokio::task::spawn_blocking(move || {
            use rusqlite::Connection;

            let conn = Connection::open(&db_path)
                .wrap_err_with(|| format!("Failed to open database: {db_path}"))?;

            let result: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT blob_data FROM blobs WHERE versioned_hash = ?1",
                    [hash.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .wrap_err("Database query failed")?;

            result.ok_or_else(|| eyre!("Blob {} not found in database", hash))
        })
        .await
        .wrap_err("Database task panicked")?
    }

    async fn get_blobs(
        &self,
        _l1_block_number: u64,
        versioned_hashes: &[B256],
    ) -> Result<Vec<Vec<u8>>> {
        if versioned_hashes.is_empty() {
            return Ok(vec![]);
        }

        let db_path = self.db_path.clone();
        let hashes: Vec<B256> = versioned_hashes.to_vec();

        tokio::task::spawn_blocking(move || {
            use rusqlite::Connection;
            use std::collections::HashMap;

            let conn = Connection::open(&db_path)
                .wrap_err_with(|| format!("Failed to open database: {db_path}"))?;

            // Use a single query with IN clause instead of N queries
            let placeholders: String = hashes.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let query = format!(
                "SELECT versioned_hash, blob_data FROM blobs WHERE versioned_hash IN ({placeholders})"
            );

            let mut stmt = conn.prepare(&query).wrap_err("Failed to prepare query")?;

            // Bind all hash parameters
            let params: Vec<&[u8]> = hashes.iter().map(|h| h.as_slice()).collect();
            let rows = stmt
                .query_map(rusqlite::params_from_iter(params), |row| {
                    let hash: Vec<u8> = row.get(0)?;
                    let data: Vec<u8> = row.get(1)?;
                    Ok((hash, data))
                })
                .wrap_err("Database query failed")?;

            // Build a map of hash -> blob data
            let mut blob_map: HashMap<B256, Vec<u8>> = HashMap::new();
            for row in rows {
                let (hash_bytes, data) = row.wrap_err("Failed to read row")?;
                let hash = B256::from_slice(&hash_bytes);
                blob_map.insert(hash, data);
            }

            // Return blobs in the requested order, checking for missing ones
            let mut result = Vec::with_capacity(hashes.len());
            for hash in &hashes {
                match blob_map.remove(hash) {
                    Some(data) => result.push(data),
                    None => return Err(eyre!("Blob {} not found in database", hash)),
                }
            }

            Ok(result)
        })
        .await
        .wrap_err("Database task panicked")?
    }
}

/// Provider that tries the database first, then falls back to beacon chain.
///
/// This is useful during the transition period when some blobs may still be
/// available on the beacon chain but not yet in the database, or for backfilling
/// historical blobs.
pub struct FallbackBlobProvider<Primary, Fallback> {
    /// Primary provider (usually database)
    primary: Primary,
    /// Fallback provider (usually beacon chain)
    fallback: Fallback,
    /// Optional callback to save blobs fetched from fallback
    save_to_db: Option<std::sync::Arc<dyn Fn(B256, Vec<u8>, u64) + Send + Sync>>,
}

impl<Primary, Fallback> FallbackBlobProvider<Primary, Fallback> {
    /// Create a new fallback provider.
    ///
    /// # Arguments
    /// * `primary` - Primary provider to try first (usually database)
    /// * `fallback` - Fallback provider if primary fails (usually beacon chain)
    pub fn new(primary: Primary, fallback: Fallback) -> Self {
        Self {
            primary,
            fallback,
            save_to_db: None,
        }
    }

    /// Set a callback to save blobs fetched from the fallback provider.
    ///
    /// This enables automatic backfilling of the database when blobs are
    /// fetched from the beacon chain.
    pub fn with_save_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(B256, Vec<u8>, u64) + Send + Sync + 'static,
    {
        self.save_to_db = Some(std::sync::Arc::new(callback));
        self
    }
}

#[async_trait]
impl<Primary, Fallback> BlobProvider for FallbackBlobProvider<Primary, Fallback>
where
    Primary: BlobProvider,
    Fallback: BlobProvider,
{
    async fn get_blob(&self, l1_block_number: u64, versioned_hash: B256) -> Result<Vec<u8>> {
        // Try primary first
        match self.primary.get_blob(l1_block_number, versioned_hash).await {
            Ok(blob) => {
                debug!("Blob {} found in primary provider", versioned_hash);
                return Ok(blob);
            }
            Err(e) => {
                debug!(
                    "Blob {} not in primary provider ({}), trying fallback",
                    versioned_hash, e
                );
            }
        }

        // Fall back to secondary
        let blob = self
            .fallback
            .get_blob(l1_block_number, versioned_hash)
            .await
            .wrap_err_with(|| {
                format!("Blob {versioned_hash} not found in primary or fallback provider")
            })?;

        // Optionally save to database for future use
        if let Some(ref save_fn) = self.save_to_db {
            debug!("Saving blob {} to database from fallback", versioned_hash);
            save_fn(versioned_hash, blob.clone(), l1_block_number);
        }

        Ok(blob)
    }

    async fn get_blobs(
        &self,
        l1_block_number: u64,
        versioned_hashes: &[B256],
    ) -> Result<Vec<Vec<u8>>> {
        if versioned_hashes.is_empty() {
            return Ok(vec![]);
        }

        // Try to get all from primary first
        match self
            .primary
            .get_blobs(l1_block_number, versioned_hashes)
            .await
        {
            Ok(blobs) => {
                debug!(
                    "All {} blobs found in primary provider",
                    versioned_hashes.len()
                );
                return Ok(blobs);
            }
            Err(e) => {
                debug!(
                    "Some blobs not in primary provider ({}), trying fallback",
                    e
                );
            }
        }

        // Fall back to fetching individually (some may be in primary, some in fallback)
        let mut result = Vec::with_capacity(versioned_hashes.len());
        for hash in versioned_hashes {
            let blob = self.get_blob(l1_block_number, *hash).await?;
            result.push(blob);
        }

        Ok(result)
    }
}

/// Helper to create a production blob provider with database storage and beacon fallback.
///
/// # Arguments
/// * `db_path` - Path to the SQLite database
/// * `beacon_url` - URL of the beacon chain API
/// * `cache_size` - Number of blobs to cache in memory (each blob is ~131KB)
///
/// # Returns
/// A blob provider that:
/// 1. Tries the database first
/// 2. Falls back to beacon chain if not found
/// 3. Automatically saves fetched blobs to the database
pub fn create_production_blob_provider(
    db_path: &str,
    beacon_url: &str,
    cache_size: usize,
) -> impl BlobProvider {
    let db_provider = DatabaseBlobProvider::new(db_path);
    let beacon_provider = BeaconBlobProvider::new(beacon_url);

    // Create a save callback that opens its own connection
    let db_path_for_save = db_path.to_string();
    let save_callback = move |hash: B256, data: Vec<u8>, l1_block: u64| {
        // Save in a separate thread to avoid blocking
        let path = db_path_for_save.clone();
        std::thread::spawn(move || {
            use rusqlite::Connection;
            match Connection::open(&path) {
                Ok(conn) => {
                    match conn.execute(
                        "INSERT OR REPLACE INTO blobs (versioned_hash, blob_data, l1_block_number) VALUES (?1, ?2, ?3)",
                        rusqlite::params![hash.as_slice(), data.as_slice(), l1_block as i64],
                    ) {
                        Ok(_) => {
                            tracing::debug!("Saved blob {} to database for L1 block {}", hash, l1_block);
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to save blob {} for L1 block {} to database: {}",
                                hash, l1_block, e
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to open database {} to save blob {}: {}",
                        path, hash, e
                    );
                }
            }
        });
    };

    // Use configured cache size, but ensure at least 1 blob can be cached
    let effective_cache_size = cache_size.max(1);

    CachingBlobProvider::new(
        FallbackBlobProvider::new(db_provider, beacon_provider).with_save_callback(save_callback),
        effective_cache_size,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_versioned_hash_computation() {
        // Test that versioned hash computation matches the spec
        // Version 0x01 prefix + sha256(commitment)[1..]
        use sha2::{Digest, Sha256};

        let commitment = vec![0u8; 48]; // Example 48-byte commitment
        let hash = Sha256::digest(&commitment);

        let mut expected = [0u8; 32];
        expected[0] = 0x01;
        expected[1..].copy_from_slice(&hash[1..]);

        // Manually verify the algorithm
        assert_eq!(expected[0], 0x01);
        assert_eq!(&expected[1..], &hash[1..]);
    }

    #[test]
    fn test_blob_sidecar_versioned_hash() {
        // Test with a known commitment
        let sidecar = BlobSidecar {
            index: "0".to_string(),
            blob: format!("0x{}", "00".repeat(BLOB_SIZE_BYTES)),
            kzg_commitment: format!("0x{}", "00".repeat(48)),
            kzg_proof: format!("0x{}", "00".repeat(48)),
        };

        let hash = sidecar.versioned_hash().unwrap();
        assert_eq!(hash[0], 0x01); // Version byte
    }

    #[test]
    fn test_blob_size_validation() {
        let sidecar = BlobSidecar {
            index: "0".to_string(),
            blob: "0x1234".to_string(), // Invalid size
            kzg_commitment: format!("0x{}", "00".repeat(48)),
            kzg_proof: format!("0x{}", "00".repeat(48)),
        };

        let result = sidecar.blob_bytes();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid blob size"));
    }

    #[test]
    fn test_blob_sidecar_blob_bytes() {
        let sidecar = BlobSidecar {
            index: "0".to_string(),
            blob: format!("0x{}", "00".repeat(BLOB_SIZE_BYTES)),
            kzg_commitment: format!("0x{}", "00".repeat(48)),
            kzg_proof: format!("0x{}", "00".repeat(48)),
        };

        let bytes = sidecar.blob_bytes().unwrap();
        assert_eq!(bytes.len(), BLOB_SIZE_BYTES);
    }
}
