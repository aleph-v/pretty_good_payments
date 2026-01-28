//! State management with SQLite persistence.
//!
//! Persists:
//! - Nullifiers for double-spend detection across restarts
//! - Last processed block for recovery
//! - Expected deposits for validation
//! - Block data for challenge submission
//! - Anchors for transaction validation

use alloy::primitives::{Address, B256, U256};
use eyre::{eyre, Result, WrapErr};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use tracing::{debug, info};

use crate::validators::nullifier::NullifierRecord;
use pgp_common::contracts::{BlockData, TimestampAndIndex};

/// A pending challenge that failed and needs to be retried
///
/// When challenge submission fails (network error, gas issue, etc.), we save
/// the block number and L1 block number. On retry, we re-fetch the block data,
/// re-validate to get fresh fraud evidence, and try again.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    /// Database ID
    pub id: i64,
    /// Block number containing the fraud
    pub block_nr: u64,
    /// L1 block number (for beacon chain blob retrieval)
    pub l1_block_number: u64,
    /// Type of fraud (e.g., "DepositWrongLeaf") - for logging/filtering
    pub fraud_type: String,
    /// Optional fraud details (JSON) - not required for retry, but useful for debugging
    pub fraud_data: Vec<u8>,
    /// Number of retry attempts
    pub retry_count: i32,
    /// Last error message
    pub last_error: Option<String>,
}

/// State manager with SQLite backend
pub struct StateManager {
    conn: Connection,
}

impl StateManager {
    /// Get a reference to the underlying connection (for advanced queries)
    pub fn conn_ref(&self) -> &Connection {
        &self.conn
    }

    /// Begin a database transaction
    ///
    /// All state changes within a transaction are atomic - either all are committed
    /// or none are. Use this to ensure consistency between nullifier saves and
    /// last_processed_block updates.
    pub fn begin_transaction(&self) -> Result<()> {
        self.conn.execute("BEGIN TRANSACTION", [])?;
        Ok(())
    }

    /// Commit the current transaction
    pub fn commit_transaction(&self) -> Result<()> {
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Rollback the current transaction
    pub fn rollback_transaction(&self) -> Result<()> {
        let _ = self.conn.execute("ROLLBACK", []);
        Ok(())
    }

    /// Execute a function within a transaction
    ///
    /// If the function succeeds, the transaction is committed.
    /// If the function fails, the transaction is rolled back.
    pub fn with_transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.begin_transaction()?;
        match f() {
            Ok(result) => {
                self.commit_transaction()?;
                Ok(result)
            }
            Err(e) => {
                self.rollback_transaction()?;
                Err(e)
            }
        }
    }
}

impl StateManager {
    /// Open or create a state database
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .wrap_err_with(|| format!("Failed to open database: {}", path.as_ref().display()))?;

        let manager = Self { conn };
        manager.init_schema()?;

        Ok(manager)
    }

    /// Create an in-memory state database (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let manager = Self { conn };
        manager.init_schema()?;
        Ok(manager)
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS nullifiers (
                hash BLOB PRIMARY KEY,
                block_nr INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                which INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS expected_deposits (
                block_nr INTEGER NOT NULL,
                deposit_index INTEGER NOT NULL,
                leaf_hash BLOB NOT NULL,
                PRIMARY KEY (block_nr, deposit_index)
            );

            CREATE TABLE IF NOT EXISTS anchors (
                block_nr INTEGER NOT NULL,
                update_nr INTEGER NOT NULL,
                is_deposit INTEGER NOT NULL,
                anchor BLOB NOT NULL,
                PRIMARY KEY (block_nr, update_nr, is_deposit)
            );

            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            -- Block data for challenge submission
            -- Stores full BlockData struct serialized as individual columns
            CREATE TABLE IF NOT EXISTS blocks (
                block_nr INTEGER PRIMARY KEY,
                anchor BLOB NOT NULL,
                timestamp BLOB NOT NULL,
                num_transactions INTEGER NOT NULL,
                num_deposits INTEGER NOT NULL,
                block_index_day INTEGER NOT NULL,
                block_index_index INTEGER NOT NULL,
                sequencer BLOB NOT NULL,
                blobhashes BLOB NOT NULL,
                l1_block_number INTEGER NOT NULL
            );

            -- Block roots for root tree tracking (28-level merkle tree of block roots)
            -- tree_index = day * 8192 + block_index_in_day (sparse tree positions)
            CREATE TABLE IF NOT EXISTS block_roots (
                tree_index INTEGER PRIMARY KEY,
                block_nr INTEGER NOT NULL,
                block_root BLOB NOT NULL
            );

            -- Pending challenges for retry after failures
            -- Stores serialized FraudEvidence along with context needed for challenge submission
            CREATE TABLE IF NOT EXISTS pending_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_nr INTEGER NOT NULL,
                l1_block_number INTEGER NOT NULL,
                fraud_type TEXT NOT NULL,
                fraud_data BLOB NOT NULL,
                retry_count INTEGER DEFAULT 0,
                last_error TEXT,
                created_at INTEGER DEFAULT (strftime('%s', 'now')),
                last_retry_at INTEGER
            );

            -- Blob data storage for long-term KZG proof generation
            -- The beacon chain only stores blobs for ~2 weeks, so we persist them here
            CREATE TABLE IF NOT EXISTS blobs (
                versioned_hash BLOB PRIMARY KEY,
                blob_data BLOB NOT NULL,
                l1_block_number INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_nullifiers_block ON nullifiers(block_nr);
            CREATE INDEX IF NOT EXISTS idx_deposits_block ON expected_deposits(block_nr);
            CREATE INDEX IF NOT EXISTS idx_anchors_block ON anchors(block_nr);
            CREATE INDEX IF NOT EXISTS idx_blobs_l1_block ON blobs(l1_block_number);
            "#,
        )?;

        Ok(())
    }

    // ========================================================================
    // Nullifier Persistence
    // ========================================================================

    /// Save a nullifier to the database
    pub fn save_nullifier(&self, nullifier: &B256, record: &NullifierRecord) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO nullifiers (hash, block_nr, tx_index, which) VALUES (?1, ?2, ?3, ?4)",
            params![
                nullifier.as_slice(),
                record.block_nr as i64,
                record.tx_index as i64,
                record.which as i32,
            ],
        )?;

        Ok(())
    }

    /// Load all nullifiers from the database
    pub fn load_nullifiers(&self) -> Result<Vec<(B256, NullifierRecord)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT hash, block_nr, tx_index, which FROM nullifiers")?;

        let rows = stmt.query_map([], |row| {
            let hash: Vec<u8> = row.get(0)?;
            let block_nr: i64 = row.get(1)?;
            let tx_index: i64 = row.get(2)?;
            let which: i32 = row.get(3)?;

            Ok((hash, block_nr, tx_index, which))
        })?;

        let mut nullifiers = Vec::new();
        for row in rows {
            let (hash, block_nr, tx_index, which) = row?;

            let nullifier = B256::from_slice(&hash);
            let record = NullifierRecord {
                block_nr: block_nr as u64,
                tx_index: tx_index as u32,
                which: which as u8,
            };

            nullifiers.push((nullifier, record));
        }

        info!("Loaded {} nullifiers from database", nullifiers.len());
        Ok(nullifiers)
    }

    /// Delete nullifiers from a specific block onwards (for rollback)
    pub fn delete_nullifiers_from(&self, from_block: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM nullifiers WHERE block_nr >= ?1",
            params![from_block as i64],
        )?;

        if count > 0 {
            info!(
                "Deleted {} nullifiers from block {} onwards",
                count, from_block
            );
        }

        Ok(count)
    }

    /// Get nullifier count
    pub fn nullifier_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM nullifiers", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Batch lookup of nullifiers - returns a map of found nullifiers to their records.
    /// Uses a single query with WHERE IN clause.
    pub fn get_nullifiers_batch(
        &self,
        nullifiers: &[B256],
    ) -> Result<std::collections::HashMap<B256, NullifierRecord>> {
        use std::collections::HashMap;

        if nullifiers.is_empty() {
            return Ok(HashMap::new());
        }

        let placeholders: Vec<&str> = nullifiers.iter().map(|_| "?").collect();
        let query = format!(
            "SELECT hash, block_nr, tx_index, which FROM nullifiers WHERE hash IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = self.conn.prepare(&query)?;

        let params: Vec<&[u8]> = nullifiers.iter().map(|n| n.as_slice()).collect();
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |row| {
            let hash: Vec<u8> = row.get(0)?;
            let block_nr: i64 = row.get(1)?;
            let tx_index: i64 = row.get(2)?;
            let which: i32 = row.get(3)?;
            Ok((hash, block_nr, tx_index, which))
        })?;

        let mut result = HashMap::new();
        for row in rows {
            let (hash, block_nr, tx_index, which) = row?;
            let nullifier = B256::from_slice(&hash);
            let record = NullifierRecord {
                block_nr: block_nr as u64,
                tx_index: tx_index as u32,
                which: which as u8,
            };
            result.insert(nullifier, record);
        }

        Ok(result)
    }

    /// Batch insert nullifiers. Wraps all inserts in a single transaction.
    pub fn save_nullifiers_batch(&self, nullifiers: &[(B256, NullifierRecord)]) -> Result<()> {
        if nullifiers.is_empty() {
            return Ok(());
        }

        self.conn.execute("BEGIN TRANSACTION", [])?;

        let result = (|| {
            let mut stmt = self.conn.prepare(
                "INSERT OR REPLACE INTO nullifiers (hash, block_nr, tx_index, which) VALUES (?1, ?2, ?3, ?4)"
            )?;

            for (nullifier, record) in nullifiers {
                stmt.execute(params![
                    nullifier.as_slice(),
                    record.block_nr as i64,
                    record.tx_index as i64,
                    record.which as i32,
                ])?;
            }

            Ok::<(), eyre::Error>(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    // ========================================================================
    // Expected Deposits Persistence
    // ========================================================================

    /// Save an expected deposit
    pub fn save_expected_deposit(
        &self,
        block_nr: u64,
        deposit_index: u64,
        leaf_hash: B256,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO expected_deposits (block_nr, deposit_index, leaf_hash) VALUES (?1, ?2, ?3)",
            params![
                block_nr as i64,
                deposit_index as i64,
                leaf_hash.as_slice(),
            ],
        )?;

        Ok(())
    }

    /// Load expected deposits for a block
    pub fn load_expected_deposits(&self, block_nr: u64) -> Result<Vec<(u64, B256)>> {
        let mut stmt = self.conn.prepare(
            "SELECT deposit_index, leaf_hash FROM expected_deposits WHERE block_nr = ?1",
        )?;

        let rows = stmt.query_map(params![block_nr as i64], |row| {
            let idx: i64 = row.get(0)?;
            let hash: Vec<u8> = row.get(1)?;
            Ok((idx, hash))
        })?;

        let mut deposits = Vec::new();
        for row in rows {
            let (idx, hash) = row?;
            deposits.push((idx as u64, B256::from_slice(&hash)));
        }

        Ok(deposits)
    }

    /// Delete expected deposits for a block
    pub fn delete_expected_deposits(&self, block_nr: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM expected_deposits WHERE block_nr = ?1",
            params![block_nr as i64],
        )?;
        Ok(count)
    }

    // ========================================================================
    // Anchor Persistence
    // ========================================================================

    /// Save an anchor for a specific (block_nr, update_nr, is_deposit) tuple
    pub fn save_anchor(
        &self,
        block_nr: u32,
        update_nr: u32,
        is_deposit: bool,
        anchor: B256,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO anchors (block_nr, update_nr, is_deposit, anchor) VALUES (?1, ?2, ?3, ?4)",
            params![
                block_nr as i64,
                update_nr as i64,
                is_deposit as i32,
                anchor.as_slice(),
            ],
        )?;

        Ok(())
    }

    /// Batch save anchors (more efficient for multiple anchors)
    pub fn save_anchors_batch(&self, anchors: &[(u32, u32, bool, B256)]) -> Result<()> {
        if anchors.is_empty() {
            return Ok(());
        }

        self.conn.execute("BEGIN TRANSACTION", [])?;

        let result = (|| {
            let mut stmt = self.conn.prepare(
                "INSERT OR REPLACE INTO anchors (block_nr, update_nr, is_deposit, anchor) VALUES (?1, ?2, ?3, ?4)"
            )?;

            for (block_nr, update_nr, is_deposit, anchor) in anchors {
                stmt.execute(params![
                    *block_nr as i64,
                    *update_nr as i64,
                    *is_deposit as i32,
                    anchor.as_slice(),
                ])?;
            }

            Ok::<(), eyre::Error>(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    /// Load an anchor by (block_nr, update_nr, is_deposit)
    pub fn load_anchor(
        &self,
        block_nr: u32,
        update_nr: u32,
        is_deposit: bool,
    ) -> Result<Option<B256>> {
        let result: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT anchor FROM anchors WHERE block_nr = ?1 AND update_nr = ?2 AND is_deposit = ?3",
                params![block_nr as i64, update_nr as i64, is_deposit as i32],
                |row| row.get(0),
            )
            .optional()?;

        match result {
            Some(bytes) => Ok(Some(B256::from_slice(&bytes))),
            None => Ok(None),
        }
    }

    /// Load all anchors for a block
    pub fn load_anchors_for_block(&self, block_nr: u32) -> Result<Vec<(u32, bool, B256)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT update_nr, is_deposit, anchor FROM anchors WHERE block_nr = ?1")?;

        let rows = stmt.query_map(params![block_nr as i64], |row| {
            let update_nr: i64 = row.get(0)?;
            let is_deposit: i32 = row.get(1)?;
            let anchor: Vec<u8> = row.get(2)?;
            Ok((update_nr, is_deposit, anchor))
        })?;

        let mut anchors = Vec::new();
        for row in rows {
            let (update_nr, is_deposit, anchor_bytes) = row?;
            anchors.push((
                update_nr as u32,
                is_deposit != 0,
                B256::from_slice(&anchor_bytes),
            ));
        }

        Ok(anchors)
    }

    /// Get the maximum update_nr for a block and is_deposit flag
    pub fn get_max_update_nr(&self, block_nr: u32, is_deposit: bool) -> Result<Option<u32>> {
        // MAX() returns NULL if no rows match, so we use Option<i64> for the column
        let result: Option<i64> = self.conn.query_row(
            "SELECT MAX(update_nr) FROM anchors WHERE block_nr = ?1 AND is_deposit = ?2",
            params![block_nr as i64, is_deposit as i32],
            |row| row.get(0),
        )?;

        Ok(result.map(|v| v as u32))
    }

    /// Delete anchors from a specific block onwards (for rollback)
    pub fn delete_anchors_from(&self, from_block: u32) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM anchors WHERE block_nr >= ?1",
            params![from_block as i64],
        )?;

        if count > 0 {
            info!(
                "Deleted {} anchors from block {} onwards",
                count, from_block
            );
        }

        Ok(count)
    }

    /// Get the count of anchors in the database
    pub fn anchor_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM anchors", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Load the latest anchor (highest block_nr, highest update_nr within that block)
    ///
    /// This returns the most recent anchor, which represents the current state root.
    pub fn load_latest_anchor(&self) -> Result<Option<B256>> {
        // First find the highest block_nr, then find the highest update_nr within it
        let result: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT anchor FROM anchors
                 WHERE block_nr = (SELECT MAX(block_nr) FROM anchors)
                 ORDER BY is_deposit ASC, update_nr DESC
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        match result {
            Some(bytes) => Ok(Some(B256::from_slice(&bytes))),
            None => Ok(None),
        }
    }

    // ========================================================================
    // Block Data Persistence
    // ========================================================================

    /// Save block data for later challenge submission
    ///
    /// This persists the BlockData struct so we can build challenges after restart
    /// without needing to re-fetch blob data from the beacon chain.
    pub fn save_block_data(&self, block_data: &BlockData, l1_block_number: u64) -> Result<()> {
        let block_nr: u64 = block_data
            .blockNr
            .try_into()
            .map_err(|_| eyre!("Block number exceeds u64::MAX"))?;

        let num_txs: u64 = block_data
            .numTransactions
            .try_into()
            .map_err(|_| eyre!("numTransactions exceeds u64::MAX"))?;

        let num_deposits: u64 = block_data
            .numDeposits
            .try_into()
            .map_err(|_| eyre!("numDeposits exceeds u64::MAX"))?;

        // Serialize blobhashes as concatenated 32-byte values
        let mut blobhashes_bytes = Vec::with_capacity(block_data.blobhashes.len() * 32);
        for hash in &block_data.blobhashes {
            blobhashes_bytes.extend_from_slice(hash.as_slice());
        }

        // Serialize timestamp as 32-byte big-endian
        let timestamp_bytes: [u8; 32] = block_data.timestamp.to_be_bytes();

        self.conn.execute(
            "INSERT OR REPLACE INTO blocks (
                block_nr, anchor, timestamp, num_transactions, num_deposits,
                block_index_day, block_index_index, sequencer, blobhashes, l1_block_number
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                block_nr as i64,
                block_data.anchor.as_slice(),
                timestamp_bytes.as_slice(),
                num_txs as i64,
                num_deposits as i64,
                block_data.blockIndex.day as i64,
                block_data.blockIndex.index as i64,
                block_data.sequencer.as_slice(),
                blobhashes_bytes,
                l1_block_number as i64,
            ],
        )?;

        debug!("Saved block data for block {}", block_nr);
        Ok(())
    }

    /// Load block data by block number
    pub fn load_block_data(&self, block_nr: u64) -> Result<Option<(BlockData, u64)>> {
        let result = self
            .conn
            .query_row(
                "SELECT anchor, timestamp, num_transactions, num_deposits,
                    block_index_day, block_index_index, sequencer, blobhashes, l1_block_number
             FROM blocks WHERE block_nr = ?1",
                params![block_nr as i64],
                |row| {
                    let anchor: Vec<u8> = row.get(0)?;
                    let timestamp: Vec<u8> = row.get(1)?;
                    let num_txs: i64 = row.get(2)?;
                    let num_deposits: i64 = row.get(3)?;
                    let block_index_day: i64 = row.get(4)?;
                    let block_index_index: i64 = row.get(5)?;
                    let sequencer: Vec<u8> = row.get(6)?;
                    let blobhashes_bytes: Vec<u8> = row.get(7)?;
                    let l1_block_number: i64 = row.get(8)?;

                    Ok((
                        anchor,
                        timestamp,
                        num_txs,
                        num_deposits,
                        block_index_day,
                        block_index_index,
                        sequencer,
                        blobhashes_bytes,
                        l1_block_number,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                anchor,
                timestamp,
                num_txs,
                num_deposits,
                day,
                index,
                sequencer,
                blobhashes_bytes,
                l1_block,
            )) => {
                // Parse blobhashes from concatenated bytes
                let mut blobhashes = Vec::new();
                for chunk in blobhashes_bytes.chunks(32) {
                    if chunk.len() == 32 {
                        blobhashes.push(B256::from_slice(chunk));
                    }
                }

                // Parse timestamp from 32-byte big-endian
                let timestamp_array: [u8; 32] = timestamp.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        1,
                        "timestamp".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;

                let block_data = BlockData {
                    anchor: B256::from_slice(&anchor),
                    timestamp: U256::from_be_bytes(timestamp_array),
                    numTransactions: U256::from(num_txs as u64),
                    numDeposits: U256::from(num_deposits as u64),
                    blockNr: U256::from(block_nr),
                    blockIndex: TimestampAndIndex {
                        day: day as u128,
                        index: index as u128,
                    },
                    sequencer: Address::from_slice(&sequencer),
                    blobhashes,
                };

                Ok(Some((block_data, l1_block as u64)))
            }
            None => Ok(None),
        }
    }

    /// Delete block data from a specific block onwards (for rollback)
    pub fn delete_blocks_from(&self, from_block: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM blocks WHERE block_nr >= ?1",
            params![from_block as i64],
        )?;

        if count > 0 {
            info!(
                "Deleted {} block records from block {} onwards",
                count, from_block
            );
        }

        Ok(count)
    }

    /// Get the count of blocks in the database
    pub fn block_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get the most recent block number in the database
    pub fn get_latest_block_nr(&self) -> Result<Option<u64>> {
        let result: Option<i64> =
            self.conn
                .query_row("SELECT MAX(block_nr) FROM blocks", [], |row| row.get(0))?;
        Ok(result.map(|v| v as u64))
    }

    // ========================================================================
    // Pending Challenges (for retry after failures)
    // ========================================================================

    /// Save a pending challenge for later retry
    ///
    /// # Arguments
    /// * `block_nr` - Block number containing the fraud
    /// * `l1_block_number` - L1 block number (for beacon chain blob retrieval)
    /// * `fraud_type` - Type of fraud (e.g., "DepositWrongLeaf", "NullifierDoubleSpend")
    /// * `fraud_data` - Serialized fraud evidence (JSON)
    /// * `error` - Optional error message from the failed attempt
    pub fn save_pending_challenge(
        &self,
        block_nr: u64,
        l1_block_number: u64,
        fraud_type: &str,
        fraud_data: &[u8],
        error: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO pending_challenges (block_nr, l1_block_number, fraud_type, fraud_data, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                block_nr as i64,
                l1_block_number as i64,
                fraud_type,
                fraud_data,
                error,
            ],
        )?;

        let id = self.conn.last_insert_rowid();
        info!(
            "Saved pending challenge id={} for block {} (type={})",
            id, block_nr, fraud_type
        );
        Ok(id)
    }

    /// Load all pending challenges
    pub fn load_pending_challenges(&self) -> Result<Vec<PendingChallenge>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, block_nr, l1_block_number, fraud_type, fraud_data, retry_count, last_error
             FROM pending_challenges
             ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(PendingChallenge {
                id: row.get(0)?,
                block_nr: row.get::<_, i64>(1)? as u64,
                l1_block_number: row.get::<_, i64>(2)? as u64,
                fraud_type: row.get(3)?,
                fraud_data: row.get(4)?,
                retry_count: row.get(5)?,
                last_error: row.get(6)?,
            })
        })?;

        let mut challenges = Vec::new();
        for row in rows {
            challenges.push(row?);
        }

        if !challenges.is_empty() {
            info!(
                "Loaded {} pending challenges from database",
                challenges.len()
            );
        }
        Ok(challenges)
    }

    /// Update a pending challenge after a retry attempt
    pub fn update_pending_challenge_retry(&self, id: i64, error: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE pending_challenges
             SET retry_count = retry_count + 1, last_error = ?1, last_retry_at = strftime('%s', 'now')
             WHERE id = ?2",
            params![error, id],
        )?;
        Ok(())
    }

    /// Delete a pending challenge (after successful submission)
    pub fn delete_pending_challenge(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_challenges WHERE id = ?1", params![id])?;
        debug!("Deleted pending challenge id={}", id);
        Ok(())
    }

    /// Delete all pending challenges for a block (e.g., after rollback)
    pub fn delete_pending_challenges_for_block(&self, block_nr: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM pending_challenges WHERE block_nr = ?1",
            params![block_nr as i64],
        )?;
        if count > 0 {
            info!(
                "Deleted {} pending challenges for block {}",
                count, block_nr
            );
        }
        Ok(count)
    }

    /// Delete all pending challenges from a block onwards (for rollback)
    pub fn delete_pending_challenges_from(&self, from_block: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM pending_challenges WHERE block_nr >= ?1",
            params![from_block as i64],
        )?;
        if count > 0 {
            info!(
                "Deleted {} pending challenges from block {} onwards",
                count, from_block
            );
        }
        Ok(count)
    }

    /// Get the count of pending challenges
    pub fn pending_challenge_count(&self) -> Result<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM pending_challenges", [], |row| {
                    row.get(0)
                })?;
        Ok(count as usize)
    }

    // ========================================================================
    // Block Root Persistence (for root tree tracking)
    // ========================================================================

    /// Save a block root for root tree tracking
    ///
    /// # Arguments
    /// * `tree_index` - Position in root tree (day * 8192 + block_index_in_day)
    /// * `block_nr` - Sequential block number (for reference/rollback)
    /// * `block_root` - The root of the 16-level block tree
    pub fn save_block_root(&self, tree_index: u64, block_nr: u64, block_root: B256) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO block_roots (tree_index, block_nr, block_root) VALUES (?1, ?2, ?3)",
            params![tree_index as i64, block_nr as i64, block_root.as_slice()],
        )?;
        debug!(
            "Saved block root for tree_index {} (block {})",
            tree_index, block_nr
        );
        Ok(())
    }

    /// Load all block roots as (tree_index, block_root) pairs (for root tree recovery)
    pub fn load_block_roots(&self) -> Result<Vec<(u64, B256)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT tree_index, block_root FROM block_roots")?;

        let rows = stmt.query_map([], |row| {
            let tree_index: i64 = row.get(0)?;
            let root: Vec<u8> = row.get(1)?;
            Ok((tree_index, root))
        })?;

        let mut roots = Vec::new();
        for row in rows {
            let (tree_index, root_bytes) = row?;
            roots.push((tree_index as u64, B256::from_slice(&root_bytes)));
        }

        info!("Loaded {} block roots from database", roots.len());
        Ok(roots)
    }

    /// Delete block roots from a specific block number onwards (for rollback)
    ///
    /// Note: This deletes by block_nr, not tree_index, since rollbacks are by block number.
    pub fn delete_block_roots_from(&self, from_block: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM block_roots WHERE block_nr >= ?1",
            params![from_block as i64],
        )?;

        if count > 0 {
            info!(
                "Deleted {} block roots from block {} onwards",
                count, from_block
            );
        }

        Ok(count)
    }

    /// Delete a specific block root by tree_index
    pub fn delete_block_root(&self, tree_index: u64) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM block_roots WHERE tree_index = ?1",
            params![tree_index as i64],
        )?;
        Ok(count > 0)
    }

    /// Get the count of block roots in the database
    pub fn block_root_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM block_roots", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    // ========================================================================
    // Blob Data Persistence (for long-term KZG proof generation)
    // ========================================================================

    /// Save blob data for long-term storage
    ///
    /// The beacon chain only retains blobs for ~2 weeks, so we store them here
    /// to enable KZG proof generation for historical blocks.
    ///
    /// # Arguments
    /// * `versioned_hash` - The versioned hash (0x01 || sha256(commitment)[1..])
    /// * `blob_data` - Raw blob data (131072 bytes)
    /// * `l1_block_number` - L1 block number containing this blob
    pub fn save_blob(
        &self,
        versioned_hash: B256,
        blob_data: &[u8],
        l1_block_number: u64,
    ) -> Result<()> {
        if blob_data.len() != 131072 {
            return Err(eyre!(
                "Invalid blob size: expected 131072 bytes, got {}",
                blob_data.len()
            ));
        }

        self.conn.execute(
            "INSERT OR REPLACE INTO blobs (versioned_hash, blob_data, l1_block_number) VALUES (?1, ?2, ?3)",
            params![
                versioned_hash.as_slice(),
                blob_data,
                l1_block_number as i64,
            ],
        )?;

        debug!(
            "Saved blob {} for L1 block {}",
            versioned_hash, l1_block_number
        );
        Ok(())
    }

    /// Save multiple blobs in a batch transaction
    pub fn save_blobs_batch(&self, blobs: &[(B256, Vec<u8>, u64)]) -> Result<()> {
        if blobs.is_empty() {
            return Ok(());
        }

        self.conn.execute("BEGIN TRANSACTION", [])?;

        let result = (|| {
            let mut stmt = self.conn.prepare(
                "INSERT OR REPLACE INTO blobs (versioned_hash, blob_data, l1_block_number) VALUES (?1, ?2, ?3)"
            )?;

            for (versioned_hash, blob_data, l1_block_number) in blobs {
                if blob_data.len() != 131072 {
                    return Err(eyre!(
                        "Invalid blob size: expected 131072 bytes, got {}",
                        blob_data.len()
                    ));
                }

                stmt.execute(params![
                    versioned_hash.as_slice(),
                    blob_data.as_slice(),
                    *l1_block_number as i64,
                ])?;
            }

            Ok::<(), eyre::Error>(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute("COMMIT", [])?;
                debug!("Saved {} blobs to database", blobs.len());
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    /// Load blob data by versioned hash
    ///
    /// # Returns
    /// The raw blob data (131072 bytes) if found, None otherwise
    pub fn load_blob(&self, versioned_hash: B256) -> Result<Option<Vec<u8>>> {
        let result: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob_data FROM blobs WHERE versioned_hash = ?1",
                params![versioned_hash.as_slice()],
                |row| row.get(0),
            )
            .optional()?;

        Ok(result)
    }

    /// Load blob data with L1 block number
    pub fn load_blob_with_l1_block(&self, versioned_hash: B256) -> Result<Option<(Vec<u8>, u64)>> {
        let result = self
            .conn
            .query_row(
                "SELECT blob_data, l1_block_number FROM blobs WHERE versioned_hash = ?1",
                params![versioned_hash.as_slice()],
                |row| {
                    let data: Vec<u8> = row.get(0)?;
                    let l1_block: i64 = row.get(1)?;
                    Ok((data, l1_block))
                },
            )
            .optional()?;

        Ok(result.map(|(data, l1_block)| (data, l1_block as u64)))
    }

    /// Check if a blob exists in the database
    pub fn has_blob(&self, versioned_hash: B256) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM blobs WHERE versioned_hash = ?1",
            params![versioned_hash.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Delete blobs from a specific L1 block onwards (for rollback/cleanup)
    pub fn delete_blobs_from(&self, from_l1_block: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM blobs WHERE l1_block_number >= ?1",
            params![from_l1_block as i64],
        )?;

        if count > 0 {
            info!(
                "Deleted {} blobs from L1 block {} onwards",
                count, from_l1_block
            );
        }

        Ok(count)
    }

    /// Get the count of blobs in the database
    pub fn blob_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get total blob storage size in bytes
    pub fn blob_storage_size(&self) -> Result<u64> {
        let count = self.blob_count()?;
        // Each blob is 131072 bytes
        Ok(count as u64 * 131072)
    }

    // ========================================================================
    // State (Key-Value) Persistence
    // ========================================================================

    /// Save the last processed block
    pub fn save_last_processed_block(&self, block: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO state (key, value) VALUES ('last_processed_block', ?1)",
            params![block.to_be_bytes().as_slice()],
        )?;
        debug!("Saved last processed block: {}", block);
        Ok(())
    }

    /// Load the last processed block
    pub fn load_last_processed_block(&self) -> Result<Option<u64>> {
        let result: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM state WHERE key = 'last_processed_block'",
                [],
                |row| row.get(0),
            )
            .optional()?;

        match result {
            Some(bytes) if bytes.len() == 8 => {
                // Safe: we just verified len() == 8
                let bytes_array: [u8; 8] = bytes.try_into().expect("length verified above");
                Ok(Some(u64::from_be_bytes(bytes_array)))
            }
            Some(bytes) => Err(eyre!(
                "Invalid last_processed_block format: expected 8 bytes, got {}",
                bytes.len()
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_manager_nullifiers() {
        let state = StateManager::in_memory().unwrap();

        let nullifier = B256::repeat_byte(0x11);
        let record = NullifierRecord {
            block_nr: 100,
            tx_index: 5,
            which: 0,
        };

        state.save_nullifier(&nullifier, &record).unwrap();

        let loaded = state.load_nullifiers().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, nullifier);
        assert_eq!(loaded[0].1.block_nr, record.block_nr);
        assert_eq!(loaded[0].1.tx_index, record.tx_index);
        assert_eq!(loaded[0].1.which, record.which);
    }

    #[test]
    fn test_state_manager_delete_nullifiers_from() {
        let state = StateManager::in_memory().unwrap();

        // Save nullifiers in blocks 1, 2, 3
        for block_nr in 1..=3u64 {
            let nullifier = B256::repeat_byte(block_nr as u8);
            let record = NullifierRecord {
                block_nr,
                tx_index: 0,
                which: 0,
            };
            state.save_nullifier(&nullifier, &record).unwrap();
        }

        assert_eq!(state.nullifier_count().unwrap(), 3);

        // Delete from block 2
        state.delete_nullifiers_from(2).unwrap();
        assert_eq!(state.nullifier_count().unwrap(), 1);
    }

    #[test]
    fn test_state_manager_last_processed_block() {
        let state = StateManager::in_memory().unwrap();

        assert!(state.load_last_processed_block().unwrap().is_none());

        state.save_last_processed_block(12345).unwrap();
        assert_eq!(state.load_last_processed_block().unwrap(), Some(12345));

        state.save_last_processed_block(67890).unwrap();
        assert_eq!(state.load_last_processed_block().unwrap(), Some(67890));
    }

    #[test]
    fn test_state_manager_expected_deposits() {
        let state = StateManager::in_memory().unwrap();

        let block_nr: u64 = 100;
        state
            .save_expected_deposit(block_nr, 0, B256::repeat_byte(0x11))
            .unwrap();
        state
            .save_expected_deposit(block_nr, 1, B256::repeat_byte(0x22))
            .unwrap();

        let deposits = state.load_expected_deposits(block_nr).unwrap();
        assert_eq!(deposits.len(), 2);

        state.delete_expected_deposits(block_nr).unwrap();
        let deposits = state.load_expected_deposits(block_nr).unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn test_state_manager_block_data() {
        let state = StateManager::in_memory().unwrap();

        let block_data = BlockData {
            anchor: B256::repeat_byte(0xAA),
            timestamp: U256::from(1234567890u64),
            numTransactions: U256::from(5u64),
            numDeposits: U256::from(3u64),
            blockNr: U256::from(100u64),
            blockIndex: TimestampAndIndex {
                day: 1u128,
                index: 2u128,
            },
            sequencer: Address::repeat_byte(0xBB),
            blobhashes: vec![B256::repeat_byte(0xCC), B256::repeat_byte(0xDD)],
        };

        let l1_block = 50000u64;

        // Save
        state.save_block_data(&block_data, l1_block).unwrap();
        assert_eq!(state.block_count().unwrap(), 1);

        // Load
        let loaded = state.load_block_data(100).unwrap();
        assert!(loaded.is_some());

        let (loaded_data, loaded_l1) = loaded.unwrap();
        assert_eq!(loaded_data.anchor, block_data.anchor);
        assert_eq!(loaded_data.timestamp, block_data.timestamp);
        assert_eq!(loaded_data.numTransactions, block_data.numTransactions);
        assert_eq!(loaded_data.numDeposits, block_data.numDeposits);
        assert_eq!(loaded_data.blockNr, block_data.blockNr);
        assert_eq!(loaded_data.blockIndex.day, 1u128);
        assert_eq!(loaded_data.blockIndex.index, 2u128);
        assert_eq!(loaded_data.sequencer, block_data.sequencer);
        assert_eq!(loaded_data.blobhashes.len(), 2);
        assert_eq!(loaded_data.blobhashes[0], B256::repeat_byte(0xCC));
        assert_eq!(loaded_data.blobhashes[1], B256::repeat_byte(0xDD));
        assert_eq!(loaded_l1, l1_block);

        // Delete
        state.delete_blocks_from(100).unwrap();
        assert_eq!(state.block_count().unwrap(), 0);
    }

    #[test]
    fn test_state_manager_get_latest_block_nr() {
        let state = StateManager::in_memory().unwrap();

        assert!(state.get_latest_block_nr().unwrap().is_none());

        for block_nr in [10u64, 20u64, 15u64] {
            let block_data = BlockData {
                anchor: B256::ZERO,
                timestamp: U256::ZERO,
                numTransactions: U256::ZERO,
                numDeposits: U256::ZERO,
                blockNr: U256::from(block_nr),
                blockIndex: TimestampAndIndex {
                    day: 0u128,
                    index: 0u128,
                },
                sequencer: Address::ZERO,
                blobhashes: vec![],
            };
            state.save_block_data(&block_data, 1).unwrap();
        }

        assert_eq!(state.get_latest_block_nr().unwrap(), Some(20));
    }

    #[test]
    fn test_state_manager_blobs() {
        let state = StateManager::in_memory().unwrap();

        // Create a test blob (131072 bytes)
        let blob_data = vec![0xABu8; 131072];
        let versioned_hash = B256::repeat_byte(0x11);
        let l1_block = 50000u64;

        // Save blob
        state
            .save_blob(versioned_hash, &blob_data, l1_block)
            .unwrap();
        assert_eq!(state.blob_count().unwrap(), 1);
        assert!(state.has_blob(versioned_hash).unwrap());

        // Load blob
        let loaded = state.load_blob(versioned_hash).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().len(), 131072);

        // Load with L1 block
        let loaded_with_l1 = state.load_blob_with_l1_block(versioned_hash).unwrap();
        assert!(loaded_with_l1.is_some());
        let (data, l1) = loaded_with_l1.unwrap();
        assert_eq!(data.len(), 131072);
        assert_eq!(l1, l1_block);

        // Non-existent blob
        let missing = B256::repeat_byte(0xFF);
        assert!(!state.has_blob(missing).unwrap());
        assert!(state.load_blob(missing).unwrap().is_none());
    }

    #[test]
    fn test_state_manager_blob_batch() {
        let state = StateManager::in_memory().unwrap();

        // Create multiple test blobs
        let blobs: Vec<(B256, Vec<u8>, u64)> = (0..3)
            .map(|i| {
                let hash = B256::repeat_byte(i as u8 + 1);
                let data = vec![i as u8; 131072];
                let l1_block = 50000u64 + i as u64;
                (hash, data, l1_block)
            })
            .collect();

        // Batch save
        state.save_blobs_batch(&blobs).unwrap();
        assert_eq!(state.blob_count().unwrap(), 3);

        // Verify each blob
        for (i, (hash, _, l1)) in blobs.iter().enumerate() {
            assert!(state.has_blob(*hash).unwrap());
            let (data, loaded_l1) = state.load_blob_with_l1_block(*hash).unwrap().unwrap();
            assert_eq!(data[0], i as u8);
            assert_eq!(loaded_l1, *l1);
        }
    }

    #[test]
    fn test_state_manager_blob_delete() {
        let state = StateManager::in_memory().unwrap();

        // Save blobs at different L1 blocks
        let blob1 = vec![0xAAu8; 131072];
        let blob2 = vec![0xBBu8; 131072];
        let blob3 = vec![0xCCu8; 131072];

        state
            .save_blob(B256::repeat_byte(0x11), &blob1, 100)
            .unwrap();
        state
            .save_blob(B256::repeat_byte(0x22), &blob2, 200)
            .unwrap();
        state
            .save_blob(B256::repeat_byte(0x33), &blob3, 300)
            .unwrap();
        assert_eq!(state.blob_count().unwrap(), 3);

        // Delete from L1 block 200 onwards
        state.delete_blobs_from(200).unwrap();
        assert_eq!(state.blob_count().unwrap(), 1);

        // Only the first blob should remain
        assert!(state.has_blob(B256::repeat_byte(0x11)).unwrap());
        assert!(!state.has_blob(B256::repeat_byte(0x22)).unwrap());
        assert!(!state.has_blob(B256::repeat_byte(0x33)).unwrap());
    }

    #[test]
    fn test_state_manager_blob_invalid_size() {
        let state = StateManager::in_memory().unwrap();

        // Try to save a blob with wrong size
        let invalid_blob = vec![0xAAu8; 1000]; // Too small
        let result = state.save_blob(B256::repeat_byte(0x11), &invalid_blob, 100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid blob size"));

        // Verify nothing was saved
        assert_eq!(state.blob_count().unwrap(), 0);
    }

    #[test]
    fn test_state_manager_blob_storage_size() {
        let state = StateManager::in_memory().unwrap();

        // Save some blobs
        let blob = vec![0xAAu8; 131072];
        state
            .save_blob(B256::repeat_byte(0x11), &blob, 100)
            .unwrap();
        state
            .save_blob(B256::repeat_byte(0x22), &blob, 200)
            .unwrap();

        // Calculate expected size
        let expected_size = 2 * 131072u64;
        assert_eq!(state.blob_storage_size().unwrap(), expected_size);
    }

    #[test]
    fn test_state_manager_blob_overwrite() {
        let state = StateManager::in_memory().unwrap();

        let hash = B256::repeat_byte(0x11);
        let blob1 = vec![0xAAu8; 131072];
        let blob2 = vec![0xBBu8; 131072];

        // Save initial blob
        state.save_blob(hash, &blob1, 100).unwrap();
        assert_eq!(state.blob_count().unwrap(), 1);

        // Overwrite with new blob data
        state.save_blob(hash, &blob2, 200).unwrap();
        assert_eq!(state.blob_count().unwrap(), 1); // Still just 1 blob

        // Verify the data was updated
        let (data, l1) = state.load_blob_with_l1_block(hash).unwrap().unwrap();
        assert_eq!(data[0], 0xBB); // New data
        assert_eq!(l1, 200); // New L1 block
    }
}
