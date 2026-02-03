//! Client-side proof cache for storing merkle tree roots.
//!
//! The cache stores roots (not paths) and computes paths dynamically:
//! - Day roots: List of all day roots up to the latest day
//! - Current day block roots: For computing block-in-day paths for current day notes
//!
//! Notes store their own immutable proof components:
//! - Block siblings (16 levels): Stored with note, immutable after block commit
//! - Block-in-day siblings (13 levels): Stored with note, immutable after day ends
//!
//! At transfer time, the day path (15 levels) is computed from the cached day roots.

use alloy_primitives::B256;
use eyre::{Result, WrapErr};
use pgp_merkle::hierarchy::{BLOCK_IN_DAY_DEPTH, DAY_TREE_DEPTH};
use pgp_merkle::{poseidon2, BlockRoot, DayRoot};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Serializable sync point
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncPoint {
    /// Anchor at last sync
    pub anchor: B256,
    /// Block number at last sync
    pub block_nr: u64,
    /// Latest day at last sync
    pub latest_day: u16,
}

/// Block roots for the current day (for computing block-in-day paths).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedBlockRoots {
    /// Day index
    pub day: u16,
    /// Block roots (sparse - only non-zero entries)
    pub block_roots: Vec<BlockRoot>,
    /// Day root (computed from block roots)
    pub day_root: B256,
    /// Block number when this was fetched (current day root changes with every block)
    pub fetched_at_block_nr: u64,
    /// Anchor when this was fetched (for verification)
    pub fetched_at_anchor: B256,
}

/// Client-side proof cache - stores roots and computes paths dynamically.
///
/// The new architecture:
/// - Notes store: block siblings (16) + block-in-day siblings (13) once finalized
/// - Cache stores: day roots (for computing day paths) + current day block roots
///
/// At transfer time:
/// 1. For finalized notes: combine stored proof (29 levels) with computed day path (15 levels)
/// 2. For current day notes: compute block-in-day path from block roots, then day path
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProofCache {
    /// Last known chain state
    pub last_sync: SyncPoint,

    /// All day roots up to the latest synced day.
    /// Index in vector = day number.
    /// Uninitialized days have B256::ZERO.
    #[serde(default)]
    pub day_roots: Vec<B256>,

    /// Block roots for current day (for computing block-in-day paths on the fly).
    /// Only needed for notes in the current (not yet finalized) day.
    #[serde(default)]
    pub current_day_block_roots: Option<CachedBlockRoots>,
}

impl ProofCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load cache from a local JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let contents = fs::read_to_string(path)
            .wrap_err_with(|| format!("Failed to read cache file: {}", path.display()))?;

        serde_json::from_str(&contents)
            .wrap_err_with(|| format!("Failed to parse cache file: {}", path.display()))
    }

    /// Save cache to a local JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!("Failed to create cache directory: {}", parent.display())
            })?;
        }

        let contents = serde_json::to_string_pretty(self).wrap_err("Failed to serialize cache")?;

        fs::write(path, contents)
            .wrap_err_with(|| format!("Failed to write cache file: {}", path.display()))
    }

    /// Update the last sync point.
    pub fn set_last_sync(&mut self, anchor: B256, block_nr: u64, latest_day: u16) {
        self.last_sync = SyncPoint {
            anchor,
            block_nr,
            latest_day,
        };
    }

    /// Check if cache is stale (anchor changed).
    pub fn is_stale(&self, current_anchor: B256) -> bool {
        self.last_sync.anchor != current_anchor
    }

    /// Clear all cached data.
    pub fn clear(&mut self) {
        self.day_roots.clear();
        self.current_day_block_roots = None;
    }

    // ========== Day Roots Management ==========

    /// Update day roots from sequencer response.
    ///
    /// This replaces/extends the cached day roots with new data.
    pub fn update_day_roots(&mut self, roots: &[DayRoot]) {
        for root in roots {
            let day = root.day as usize;
            // Extend vector if needed
            if day >= self.day_roots.len() {
                self.day_roots.resize(day + 1, B256::ZERO);
            }
            self.day_roots[day] = root.root;
        }
    }

    /// Get the day root for a specific day.
    pub fn get_day_root(&self, day: u16) -> Option<B256> {
        self.day_roots.get(day as usize).copied()
    }

    /// Compute the day-to-global path (15 levels) for a specific day.
    ///
    /// This computes the merkle path from the day's position in the global
    /// day tree up to the global root.
    pub fn compute_day_path(&self, day: u16) -> Option<[B256; DAY_TREE_DEPTH]> {
        // Need enough day roots to compute the path
        // The tree has 2^15 = 32768 possible days
        const NUM_DAYS: usize = 1 << DAY_TREE_DEPTH;

        // Build the full day tree (sparse - zeros for uninitialized days)
        let mut leaves = vec![B256::ZERO; NUM_DAYS];
        for (i, root) in self.day_roots.iter().enumerate() {
            if i < NUM_DAYS {
                leaves[i] = *root;
            }
        }

        // Compute merkle tree level by level and extract siblings
        let mut siblings = [B256::ZERO; DAY_TREE_DEPTH];
        let mut current_level = leaves;
        let mut idx = day as usize;

        for level in 0..DAY_TREE_DEPTH {
            // Get sibling at this level
            let sibling_idx = idx ^ 1;
            siblings[level] = current_level[sibling_idx];

            // Compute next level
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = current_level[i + 1];
                next_level.push(poseidon2(left, right));
            }
            current_level = next_level;
            idx /= 2;
        }

        Some(siblings)
    }

    /// Compute the global root from cached day roots.
    pub fn compute_global_root(&self) -> B256 {
        const NUM_DAYS: usize = 1 << DAY_TREE_DEPTH;

        let mut leaves = vec![B256::ZERO; NUM_DAYS];
        for (i, root) in self.day_roots.iter().enumerate() {
            if i < NUM_DAYS {
                leaves[i] = *root;
            }
        }

        // Compute up to root
        let mut current_level = leaves;
        for _ in 0..DAY_TREE_DEPTH {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for i in (0..current_level.len()).step_by(2) {
                next_level.push(poseidon2(current_level[i], current_level[i + 1]));
            }
            current_level = next_level;
        }

        current_level[0]
    }

    // ========== Current Day Block Roots Management ==========

    /// Store block roots for the current day.
    ///
    /// IMPORTANT: This also updates `day_roots[current_day]` with the new day root.
    /// This is critical because `compute_day_path` uses the `day_roots` vector to
    /// build the full day tree for computing merkle paths. Without updating the
    /// current day's root here, day paths would be computed against a stale anchor.
    pub fn set_current_day_block_roots(&mut self, roots: CachedBlockRoots) {
        // Update the day root in our day_roots array - this is essential for
        // compute_day_path to work correctly against the current anchor
        let day = roots.day as usize;
        if day >= self.day_roots.len() {
            self.day_roots.resize(day + 1, B256::ZERO);
        }
        self.day_roots[day] = roots.day_root;

        self.current_day_block_roots = Some(roots);
    }

    /// Check if we have valid block roots for the current day.
    ///
    /// Returns true only if we have roots for the correct day AND they were
    /// fetched at the current block number. Each new block changes the day root.
    pub fn has_valid_current_day_roots(&self, day: u16, current_block_nr: u64) -> bool {
        self.current_day_block_roots.as_ref().map_or(false, |r| {
            r.day == day && r.fetched_at_block_nr == current_block_nr
        })
    }

    /// Check if we need to refresh the current day's block roots.
    ///
    /// Returns true if:
    /// - We don't have cached block roots, OR
    /// - The day has changed, OR
    /// - A new block has been added (block_nr increased)
    pub fn needs_current_day_refresh(&self, latest_day: u16, latest_block_nr: u64) -> bool {
        self.current_day_block_roots.as_ref().map_or(true, |r| {
            r.day != latest_day || r.fetched_at_block_nr < latest_block_nr
        })
    }

    /// Get the number of finalized days we have cached.
    ///
    /// Finalized days are days before the current day (their roots won't change).
    /// Returns the count of consecutive finalized days starting from day 0.
    pub fn finalized_days_cached(&self) -> usize {
        // If we have current day block roots, the day_roots array may include
        // the current day's root at the end. We count only finalized days.
        match &self.current_day_block_roots {
            Some(roots) => {
                // Days before the current day are finalized
                self.day_roots.len().min(roots.day as usize)
            }
            None => {
                // Without current day info, we can't know which are finalized
                // Conservatively return what we have minus 1 (last might be current)
                self.day_roots.len().saturating_sub(1)
            }
        }
    }

    /// Compute block-in-day path (13 levels) from cached block roots.
    ///
    /// Returns None if we don't have valid roots for this day.
    pub fn compute_block_in_day_path(
        &self,
        day: u16,
        block_in_day: u16,
    ) -> Option<[B256; BLOCK_IN_DAY_DEPTH]> {
        let roots = self.current_day_block_roots.as_ref()?;
        if roots.day != day {
            return None;
        }

        const NUM_BLOCKS: usize = 1 << BLOCK_IN_DAY_DEPTH; // 8192
        let mut leaves = vec![B256::ZERO; NUM_BLOCKS];

        // Fill in non-zero block roots
        for root in &roots.block_roots {
            let idx = root.block_in_day as usize;
            if idx < NUM_BLOCKS {
                leaves[idx] = root.root;
            }
        }

        // Compute merkle tree and extract siblings
        let mut siblings = [B256::ZERO; BLOCK_IN_DAY_DEPTH];
        let mut current_level = leaves;
        let mut idx = block_in_day as usize;

        for level in 0..BLOCK_IN_DAY_DEPTH {
            let sibling_idx = idx ^ 1;
            siblings[level] = current_level[sibling_idx];

            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for i in (0..current_level.len()).step_by(2) {
                next_level.push(poseidon2(current_level[i], current_level[i + 1]));
            }
            current_level = next_level;
            idx /= 2;
        }

        Some(siblings)
    }

    /// Get the day root from current day block roots.
    pub fn get_current_day_root(&self) -> Option<B256> {
        self.current_day_block_roots.as_ref().map(|r| r.day_root)
    }

    // ========== Utility Methods ==========

    /// Get the number of cached day roots.
    pub fn day_roots_count(&self) -> usize {
        self.day_roots.len()
    }

    /// Check if we need to fetch more day roots.
    ///
    /// Returns true if we don't have roots up to the latest day.
    pub fn needs_day_roots_update(&self, latest_day: u16) -> bool {
        (latest_day as usize) >= self.day_roots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cache_new() {
        let cache = ProofCache::new();
        assert_eq!(cache.day_roots_count(), 0);
        assert!(cache.current_day_block_roots.is_none());
    }

    #[test]
    fn test_cache_save_load() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("test_cache.json");

        let mut cache = ProofCache::new();
        cache.set_last_sync(B256::repeat_byte(0x11), 100, 5);
        cache.update_day_roots(&[
            DayRoot {
                day: 0,
                root: B256::repeat_byte(0x01),
            },
            DayRoot {
                day: 1,
                root: B256::repeat_byte(0x02),
            },
        ]);

        cache.save(&cache_path).unwrap();

        let loaded = ProofCache::load(&cache_path).unwrap();
        assert_eq!(loaded.last_sync.block_nr, 100);
        assert_eq!(loaded.day_roots_count(), 2);
        assert_eq!(loaded.get_day_root(0), Some(B256::repeat_byte(0x01)));
        assert_eq!(loaded.get_day_root(1), Some(B256::repeat_byte(0x02)));
    }

    #[test]
    fn test_update_day_roots() {
        let mut cache = ProofCache::new();

        // Add roots for days 0, 1, 2
        cache.update_day_roots(&[
            DayRoot {
                day: 0,
                root: B256::repeat_byte(0x01),
            },
            DayRoot {
                day: 2,
                root: B256::repeat_byte(0x03),
            },
        ]);

        assert_eq!(cache.day_roots_count(), 3); // 0, 1, 2 (1 is zero)
        assert_eq!(cache.get_day_root(0), Some(B256::repeat_byte(0x01)));
        assert_eq!(cache.get_day_root(1), Some(B256::ZERO)); // Uninitialized
        assert_eq!(cache.get_day_root(2), Some(B256::repeat_byte(0x03)));
        assert_eq!(cache.get_day_root(3), None); // Out of range
    }

    #[test]
    fn test_compute_day_path() {
        let mut cache = ProofCache::new();

        // Set up day roots for days 0 and 1
        cache.update_day_roots(&[
            DayRoot {
                day: 0,
                root: B256::repeat_byte(0x11),
            },
            DayRoot {
                day: 1,
                root: B256::repeat_byte(0x22),
            },
        ]);

        // Compute path for day 0
        let path = cache.compute_day_path(0);
        assert!(path.is_some());

        let path = path.unwrap();
        // First sibling should be day 1's root
        assert_eq!(path[0], B256::repeat_byte(0x22));

        // Compute path for day 1
        let path1 = cache.compute_day_path(1);
        assert!(path1.is_some());
        // First sibling should be day 0's root
        assert_eq!(path1.unwrap()[0], B256::repeat_byte(0x11));
    }

    #[test]
    fn test_compute_global_root_empty() {
        let cache = ProofCache::new();
        let root = cache.compute_global_root();
        // With all zeros, the root should be deterministic
        assert_ne!(root, B256::ZERO); // Poseidon of zeros is not zero
    }

    #[test]
    fn test_current_day_block_roots() {
        let mut cache = ProofCache::new();
        let anchor = B256::repeat_byte(0x55);
        let block_nr = 100u64;

        let roots = CachedBlockRoots {
            day: 10,
            block_roots: vec![
                BlockRoot {
                    day: 10,
                    block_in_day: 0,
                    root: B256::repeat_byte(0x11),
                },
                BlockRoot {
                    day: 10,
                    block_in_day: 1,
                    root: B256::repeat_byte(0x22),
                },
            ],
            day_root: B256::repeat_byte(0x99),
            fetched_at_block_nr: block_nr,
            fetched_at_anchor: anchor,
        };

        cache.set_current_day_block_roots(roots);

        assert!(cache.has_valid_current_day_roots(10, block_nr));
        assert!(!cache.has_valid_current_day_roots(10, block_nr + 1)); // New block added
        assert!(!cache.has_valid_current_day_roots(11, block_nr)); // Wrong day
    }

    #[test]
    fn test_needs_current_day_refresh() {
        let mut cache = ProofCache::new();

        // Empty cache needs refresh
        assert!(cache.needs_current_day_refresh(0, 0));
        assert!(cache.needs_current_day_refresh(5, 100));

        // Add current day roots
        cache.set_current_day_block_roots(CachedBlockRoots {
            day: 5,
            block_roots: vec![],
            day_root: B256::ZERO,
            fetched_at_block_nr: 100,
            fetched_at_anchor: B256::ZERO,
        });

        // Same day and block - no refresh needed
        assert!(!cache.needs_current_day_refresh(5, 100));

        // New block on same day - needs refresh
        assert!(cache.needs_current_day_refresh(5, 101));

        // New day - needs refresh
        assert!(cache.needs_current_day_refresh(6, 100));
    }

    #[test]
    fn test_finalized_days_cached() {
        let mut cache = ProofCache::new();

        // No data - 0 finalized days
        assert_eq!(cache.finalized_days_cached(), 0);

        // Add day roots without current day info
        cache.update_day_roots(&[
            DayRoot {
                day: 0,
                root: B256::repeat_byte(0x01),
            },
            DayRoot {
                day: 1,
                root: B256::repeat_byte(0x02),
            },
            DayRoot {
                day: 2,
                root: B256::repeat_byte(0x03),
            },
        ]);
        // Without current day info, conservatively return len - 1
        assert_eq!(cache.finalized_days_cached(), 2);

        // Set current day to day 3
        cache.set_current_day_block_roots(CachedBlockRoots {
            day: 3,
            block_roots: vec![],
            day_root: B256::repeat_byte(0x04),
            fetched_at_block_nr: 100,
            fetched_at_anchor: B256::ZERO,
        });
        // Now we know days 0-2 are finalized (day 3 is current)
        // day_roots now has 4 entries (0, 1, 2, 3), but only 0-2 are finalized
        assert_eq!(cache.finalized_days_cached(), 3);
    }

    #[test]
    fn test_compute_block_in_day_path() {
        let mut cache = ProofCache::new();

        // Use field-valid values (top bits cleared to fit in BN254 field)
        let root0 = {
            let mut bytes = [0x0Au8; 32];
            bytes[0] = 0x0A; // Ensure within field
            B256::from(bytes)
        };
        let root1 = {
            let mut bytes = [0x0Bu8; 32];
            bytes[0] = 0x0B; // Ensure within field
            B256::from(bytes)
        };

        let roots = CachedBlockRoots {
            day: 5,
            block_roots: vec![
                BlockRoot {
                    day: 5,
                    block_in_day: 0,
                    root: root0,
                },
                BlockRoot {
                    day: 5,
                    block_in_day: 1,
                    root: root1,
                },
            ],
            day_root: B256::repeat_byte(0x0C),
            fetched_at_block_nr: 100,
            fetched_at_anchor: B256::ZERO,
        };

        cache.set_current_day_block_roots(roots);

        // Compute path for block 0
        let path = cache.compute_block_in_day_path(5, 0);
        assert!(path.is_some());
        // First sibling should be block 1's root
        assert_eq!(path.unwrap()[0], root1);

        // Compute path for block 1
        let path1 = cache.compute_block_in_day_path(5, 1);
        assert!(path1.is_some());
        // First sibling should be block 0's root
        assert_eq!(path1.unwrap()[0], root0);

        // Wrong day should return None
        assert!(cache.compute_block_in_day_path(6, 0).is_none());
    }

    #[test]
    fn test_is_stale() {
        let mut cache = ProofCache::new();
        let anchor1 = B256::repeat_byte(0x11);
        let anchor2 = B256::repeat_byte(0x22);

        cache.set_last_sync(anchor1, 100, 5);

        assert!(!cache.is_stale(anchor1));
        assert!(cache.is_stale(anchor2));
    }

    #[test]
    fn test_clear() {
        let mut cache = ProofCache::new();

        cache.update_day_roots(&[DayRoot {
            day: 0,
            root: B256::repeat_byte(0x11),
        }]);
        cache.set_current_day_block_roots(CachedBlockRoots {
            day: 0,
            block_roots: vec![],
            day_root: B256::ZERO,
            fetched_at_block_nr: 0,
            fetched_at_anchor: B256::ZERO,
        });

        assert!(cache.day_roots_count() > 0);
        assert!(cache.current_day_block_roots.is_some());

        cache.clear();

        assert_eq!(cache.day_roots_count(), 0);
        assert!(cache.current_day_block_roots.is_none());
    }

    #[test]
    fn test_needs_day_roots_update() {
        let mut cache = ProofCache::new();

        // Empty cache needs update for any day
        assert!(cache.needs_day_roots_update(0));
        assert!(cache.needs_day_roots_update(5));

        // Add some roots
        cache.update_day_roots(&[
            DayRoot {
                day: 0,
                root: B256::ZERO,
            },
            DayRoot {
                day: 5,
                root: B256::ZERO,
            },
        ]);

        // Now we have up to day 5
        assert!(!cache.needs_day_roots_update(0));
        assert!(!cache.needs_day_roots_update(5));
        assert!(cache.needs_day_roots_update(6)); // Need update for day 6+
    }
}
