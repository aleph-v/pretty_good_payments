#!/usr/bin/env node
/**
 * FFI script to generate comprehensive multi-day, multi-block integration test data
 *
 * This generates:
 * - 2 full days with 5 blocks each (10 deposits + 1 tx per block)
 * - 3rd day with 5 blocks, targeting block index 2 for fraud/no fraud tests
 * - All anchors computed using real Poseidon hashes
 * - ZK proof for the target block's deposit group
 *
 * Output: JSON with complete state history and test data
 */

const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const crypto = require("crypto");

let poseidon = null;
let F = null;

const BLOCK_DEPTH = 16;
const ROOT_DEPTH = 28;
const BLOCKS_PER_DAY = 8192; // 2^13

// Cross-blob configuration constants for TreeUpdateChallenge
// For transactions: memoryAddress = depositsLength + txNr * 15 + 11
// With depositsLength = 4 and txNr = 272: memoryAddress = 4 + 272*15 + 11 = 4095
// Elements span positions 4095-4098, giving region.length=1, extensionRegion.length=3
const CROSSBLOB_CONFIG = {
    depositsPerBlock: 3,        // 1 group * 4 elements = 4 elements
    txPerBlock: 273,            // Need 273 transactions so tx 272 is at position 4095
    targetUpdateIndex: 273,     // The transaction update (after 1 deposit group, so index = 1 + 272 = 273? Actually targeting tx 272)
    numDepositGroups: 1         // ceil(3/3) = 1
};

async function initPoseidon() {
    if (!poseidon) {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    }
}

function poseidonHash2(a, b) {
    const hash = poseidon([a, b]);
    return F.toObject(hash);
}

function computeZeroHashes(depth) {
    const zeroHashes = [BigInt(0)];
    for (let i = 1; i <= depth; i++) {
        zeroHashes.push(poseidonHash2(zeroHashes[i - 1], zeroHashes[i - 1]));
    }
    return zeroHashes;
}

/**
 * Sparse Merkle Tree with clone support
 */
class SparseMerkleTree {
    constructor(depth, zeroHashes, existingNodes = null) {
        this.depth = depth;
        this.zeroHashes = zeroHashes;
        if (existingNodes) {
            // Deep clone existing nodes
            this.nodes = new Map();
            for (let i = 0; i <= depth; i++) {
                this.nodes.set(i, new Map(existingNodes.get(i)));
            }
        } else {
            this.nodes = new Map();
            for (let i = 0; i <= depth; i++) {
                this.nodes.set(i, new Map());
            }
        }
    }

    clone() {
        return new SparseMerkleTree(this.depth, this.zeroHashes, this.nodes);
    }

    getNode(level, index) {
        const levelNodes = this.nodes.get(level);
        if (levelNodes.has(index)) {
            return levelNodes.get(index);
        }
        return this.zeroHashes[level];
    }

    setNode(level, index, value) {
        this.nodes.get(level).set(index, value);
    }

    getRoot() {
        return this.getNode(this.depth, 0);
    }

    getProof(index) {
        const proof = [];
        let idx = index;
        for (let level = 0; level < this.depth; level++) {
            const siblingIdx = idx ^ 1;
            proof.push(this.getNode(level, siblingIdx));
            idx = idx >> 1;
        }
        return proof;
    }

    setLeaf(index, value) {
        let idx = index;
        let currentValue = value;
        this.setNode(0, index, value);

        for (let level = 0; level < this.depth; level++) {
            const parentIdx = idx >> 1;
            const isLeft = (idx & 1) === 0;
            const siblingIdx = idx ^ 1;
            const sibling = this.getNode(level, siblingIdx);

            let parentValue;
            if (isLeft) {
                parentValue = poseidonHash2(currentValue, sibling);
            } else {
                parentValue = poseidonHash2(sibling, currentValue);
            }

            this.setNode(level + 1, parentIdx, parentValue);
            currentValue = parentValue;
            idx = parentIdx;
        }
    }
}

/**
 * Compute zero hashes for the root tree where the base zero is the empty block root
 * This is different from regular zero hashes because unset positions should have
 * the empty block tree root, not 0
 */
function computeRootTreeZeroHashes(depth, emptyBlockRoot) {
    const zeroHashes = [emptyBlockRoot];
    for (let i = 1; i <= depth; i++) {
        zeroHashes.push(poseidonHash2(zeroHashes[i - 1], zeroHashes[i - 1]));
    }
    return zeroHashes;
}

/**
 * Root tree that tracks block roots across the entire system
 * This is a sparse Merkle tree where each leaf position corresponds to a treeIndex
 * Unset positions default to the empty block root (not zero!)
 */
class RootTree {
    constructor(depth, emptyBlockRoot) {
        this.depth = depth;
        this.emptyBlockRoot = emptyBlockRoot;
        // Compute zero hashes where base zero = empty block root
        this.zeroHashes = computeRootTreeZeroHashes(depth, emptyBlockRoot);
        // Use sparse merkle tree for root tracking with proper zero hashes
        this.tree = new SparseMerkleTree(depth, this.zeroHashes);
    }

    setBlockRoot(treeIndex, blockRoot) {
        this.tree.setLeaf(treeIndex, blockRoot);
    }

    getBlockRoot(treeIndex) {
        return this.tree.getNode(0, treeIndex);
    }

    getRoot() {
        return this.tree.getRoot();
    }

    getProof(treeIndex) {
        return this.tree.getProof(treeIndex);
    }

    clone() {
        const cloned = new RootTree(this.depth, this.emptyBlockRoot);
        cloned.tree = this.tree.clone();
        return cloned;
    }
}

/**
 * Generate deterministic deposit values for a block
 */
function generateDeposits(day, blockIdx, count) {
    const deposits = [];
    for (let i = 0; i < count; i++) {
        // Create deterministic but unique deposit values
        const value = BigInt(day * 1000000 + blockIdx * 10000 + i * 100 + 1);
        deposits.push(value);
    }
    return deposits;
}

/**
 * Generate deterministic transaction update values
 */
function generateTxUpdates(day, blockIdx, txIdx) {
    // Each transaction produces 3 updates
    const base = BigInt(day * 10000000 + blockIdx * 100000 + txIdx * 1000 + 500);
    return [base, base + BigInt(1), base + BigInt(2)];
}

/**
 * Compute anchor from root tree's root (after a block root has been set)
 * This is simply the root of the root tree
 */
function computeAnchorFromRootTree(rootTree) {
    return rootTree.getRoot();
}

/**
 * Compute anchor for a specific block root at a given treeIndex
 * Uses the current state of the root tree to get proper sibling values
 * @param rootTree - The current root tree state (will be cloned to avoid mutation)
 * @param blockRoot - The block root to place at treeIndex
 * @param treeIndex - The position in the root tree
 */
function computeAnchorWithState(rootTree, blockRoot, treeIndex) {
    // Clone the tree, set the block root, and get the new root
    const tempTree = rootTree.clone();
    tempTree.setBlockRoot(treeIndex, blockRoot);
    return tempTree.getRoot();
}

/**
 * Process a single block's updates and return the new anchor
 * Each block uses a fresh block tree and computes anchors using the root tree state
 * This ensures anchors properly chain across blocks
 */
function processBlock(blockTree, rootTree, priorAnchor, day, blockIdx, numDeposits, numTx, blockZeroHashes, rootZeroHashes) {
    const treeIndex = day * BLOCKS_PER_DAY + blockIdx;

    // Generate deposits
    const deposits = generateDeposits(day, blockIdx, numDeposits);

    // Generate transaction updates
    const txUpdates = [];
    for (let i = 0; i < numTx; i++) {
        txUpdates.push(generateTxUpdates(day, blockIdx, i));
    }

    // Track all updates and anchors for this block
    const blockUpdates = [];

    // The prior anchor for this block is the current root tree's root (before any updates to this block)
    // This is the previous block's final anchor, which properly chains blocks together
    const blockPriorAnchor = computeAnchorFromRootTree(rootTree);

    const groupAnchors = [blockPriorAnchor];
    let currentAnchor = blockPriorAnchor;
    let inBlockIndex = 0;

    // Process deposit groups (3 deposits per group)
    const numDepositGroups = Math.ceil(numDeposits / 3);
    for (let g = 0; g < numDepositGroups; g++) {
        const groupDeposits = deposits.slice(g * 3, Math.min((g + 1) * 3, numDeposits));
        // Pad with zeros if needed
        while (groupDeposits.length < 3) {
            groupDeposits.push(BigInt(0));
        }

        // Insert deposits into block tree
        for (let i = 0; i < 3; i++) {
            if (groupDeposits[i] !== BigInt(0)) {
                blockTree.setLeaf(inBlockIndex + i, groupDeposits[i]);
            }
        }

        // Compute new anchor by placing updated block root in the root tree
        const newBlockRoot = blockTree.getRoot();
        const newAnchor = computeAnchorWithState(rootTree, newBlockRoot, treeIndex);

        blockUpdates.push({
            type: 'deposit',
            groupIndex: g,
            updates: groupDeposits.map(d => d.toString()),
            priorAnchor: currentAnchor.toString(),
            newAnchor: newAnchor.toString(),
            inBlockIndex: inBlockIndex
        });

        groupAnchors.push(newAnchor);
        currentAnchor = newAnchor;
        inBlockIndex += 3;
    }

    // Process transactions (each tx has 3 updates)
    for (let t = 0; t < numTx; t++) {
        const updates = txUpdates[t];

        // Insert tx updates into block tree
        for (let i = 0; i < 3; i++) {
            blockTree.setLeaf(inBlockIndex + i, updates[i]);
        }

        // Compute new anchor by placing updated block root in the root tree
        const newBlockRoot = blockTree.getRoot();
        const newAnchor = computeAnchorWithState(rootTree, newBlockRoot, treeIndex);

        blockUpdates.push({
            type: 'transaction',
            txIndex: t,
            updates: updates.map(u => u.toString()),
            priorAnchor: currentAnchor.toString(),
            newAnchor: newAnchor.toString(),
            inBlockIndex: inBlockIndex
        });

        groupAnchors.push(newAnchor);
        currentAnchor = newAnchor;
        inBlockIndex += 3;
    }

    // Update root tree with final block root (this persists the state for subsequent blocks)
    rootTree.setBlockRoot(treeIndex, blockTree.getRoot());

    return {
        day,
        blockIdx,
        treeIndex,
        numDeposits,
        numTx,
        deposits: deposits.map(d => d.toString()),
        txUpdates: txUpdates.map(tx => tx.map(u => u.toString())),
        blockUpdates,
        finalAnchor: currentAnchor.toString(),
        blockPriorAnchor: blockPriorAnchor.toString(),
        groupAnchors: groupAnchors.map(a => a.toString())
    };
}

/**
 * Generate ZK proof for a specific update
 * @param priorAnchor - The anchor before this update group
 * @param treeIndex - The tree index (day * 8192 + blockIdx)
 * @param updates - Array of 3 updates for this group
 * @param inBlockIndex - Starting leaf index within the block tree
 * @param blockTree - The block tree state BEFORE this update (with prior groups applied)
 * @param rootTree - The root tree state BEFORE this block (for getting sibling path)
 * @param wasmPath - Path to circuit wasm
 * @param zkeyPath - Path to circuit zkey
 */
async function generateZkProof(priorAnchor, treeIndex, updates, inBlockIndex, blockTree, rootTree, wasmPath, zkeyPath) {
    const blockRootBefore = blockTree.getRoot();

    // For the circuit's nonzeroField check:
    // If inBlockIndex > 0, we need to provide the value at inBlockIndex - 1 (must be non-zero)
    // If inBlockIndex == 0, nonzeroField is not checked (isIndexZero = 1 bypasses the check)
    let nonzeroField = BigInt(0);
    if (inBlockIndex > 0) {
        nonzeroField = blockTree.getNode(0, inBlockIndex - 1);
        if (nonzeroField === BigInt(0)) {
            throw new Error(`nonzeroField at index ${inBlockIndex - 1} is zero but inBlockIndex > 0`);
        }
    }

    // Generate block proofs
    const blockProofs = [];

    // blockProofs[0]: proof for nonzeroField position (inBlockIndex - 1 if inBlockIndex > 0, else inBlockIndex)
    const nonzeroProofIndex = inBlockIndex > 0 ? inBlockIndex - 1 : inBlockIndex;
    blockProofs.push(blockTree.getProof(nonzeroProofIndex));

    // blockProofs[1]: proof for position inBlockIndex (before first insert)
    blockProofs.push(blockTree.getProof(inBlockIndex));

    // Clone tree for incremental proofs
    const tempTree = blockTree.clone();

    // Insert first update
    tempTree.setLeaf(inBlockIndex, BigInt(updates[0]));
    blockProofs.push(tempTree.getProof(inBlockIndex + 1));

    // Insert second update
    tempTree.setLeaf(inBlockIndex + 1, BigInt(updates[1]));
    blockProofs.push(tempTree.getProof(inBlockIndex + 2));

    // Root path from the root tree - this is the sibling path at treeIndex
    // The root tree should have all previous blocks' roots already set
    const rootPath = rootTree.getProof(treeIndex);

    const input = {
        anchorBefore: priorAnchor.toString(),
        blockRootBefore: blockRootBefore.toString(),
        updates: updates.map(u => u.toString()),
        blockIndex: treeIndex.toString(),
        inBlockIndex: inBlockIndex.toString(),
        nonzeroField: nonzeroField.toString(),
        blockProofs: blockProofs.map(proof => proof.map(p => p.toString())),
        rootPath: rootPath.map(p => p.toString())
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        wasmPath,
        zkeyPath
    );

    // Format proof for Solidity
    const solidityProof = {
        _pA: [proof.pi_a[0], proof.pi_a[1]],
        _pB: [
            [proof.pi_b[0][1], proof.pi_b[0][0]],
            [proof.pi_b[1][1], proof.pi_b[1][0]]
        ],
        _pC: [proof.pi_c[0], proof.pi_c[1]]
    };

    return { proof: solidityProof, publicSignals };
}

/**
 * Generate KZG proofs for specified indices using the Python script
 * @param blobData - Array of hex strings (will be padded to 4096)
 * @param indices - Array of indices to generate proofs for
 * @returns KZG proof data including commitment, proofs, claims, and hash
 */
function generateKzgProofs(blobData, indices) {
    // Write blob data to temp JSON file with unique ID to avoid parallel test conflicts
    const uniqueId = crypto.randomBytes(4).toString('hex');
    const blobJsonPath = `/tmp/blob_data_for_kzg_${uniqueId}.json`;

    // Convert blobData to hex strings with 0x prefix, pad with zeros
    const hexBlobData = [];
    for (let i = 0; i < 4096; i++) {
        if (i < blobData.length && blobData[i]) {
            // Convert to hex string with proper padding
            let val = blobData[i];
            if (typeof val === 'string' && !val.startsWith('0x')) {
                val = BigInt(val);
            }
            if (typeof val === 'bigint') {
                val = '0x' + val.toString(16).padStart(64, '0');
            }
            hexBlobData.push(val);
        } else {
            hexBlobData.push('0x' + '0'.repeat(64));
        }
    }

    fs.writeFileSync(blobJsonPath, JSON.stringify({ blobData: hexBlobData }));

    // Call Python script with --json flag and indices
    const scriptDir = path.dirname(__filename);
    const pythonScript = path.join(scriptDir, "generateKzgProof.py");

    const indicesStr = indices.join(' ');
    const cmd = `python3 "${pythonScript}" --json "${blobJsonPath}" ${indicesStr}`;

    try {
        const resultPath = execSync(cmd, { encoding: 'utf8' }).trim();
        const resultData = fs.readFileSync(resultPath);

        // The result is ABI-encoded, we need to decode it
        // For multiple indices: (bytes commitment, uint256[] indices, bytes32[] claims, bytes32 hash, bytes[] proofs)
        // We'll return the raw binary data and let the test decode it
        return {
            binaryPath: resultPath,
            indices: indices
        };
    } catch (err) {
        console.error("KZG proof generation failed:", err.message);
        throw err;
    }
}

async function main() {
    await initPoseidon();

    // Parse command line arguments
    const args = process.argv.slice(2);
    const fraudMode = args.includes('--fraud');
    const targetTx = args.includes('--tx');  // Target a transaction instead of deposit
    const crossblobMode = args.includes('--crossblob');

    if (fraudMode) {
        console.error("FRAUD MODE: Generating blob with incorrect anchor");
    }
    if (targetTx) {
        console.error("TX MODE: Targeting transaction instead of deposit");
    }
    if (crossblobMode) {
        console.error("CROSSBLOB MODE: Generating tree update spanning blob boundary");
    }

    const blockZeroHashes = computeZeroHashes(BLOCK_DEPTH);
    const rootZeroHashes = computeZeroHashes(ROOT_DEPTH);

    // The empty block root is the Merkle root of an empty block tree (all zeros)
    const emptyBlockRoot = blockZeroHashes[BLOCK_DEPTH];

    // Initialize root tree - unset positions default to empty block root
    const rootTree = new RootTree(ROOT_DEPTH, emptyBlockRoot);

    // Genesis anchor is the root of the root tree where all positions have empty block roots
    const genesisAnchor = computeAnchorFromRootTree(rootTree);

    // Configuration - use cross-blob config if flag is set
    const DAYS = 3;
    const BLOCKS_PER_TEST_DAY = 5;
    const DEPOSITS_PER_BLOCK = crossblobMode ? CROSSBLOB_CONFIG.depositsPerBlock : 12;
    const TX_PER_BLOCK = crossblobMode ? CROSSBLOB_CONFIG.txPerBlock : 1;
    const TARGET_DAY = 2; // 0-indexed, so this is day 3
    const TARGET_BLOCK = 2; // 0-indexed, so this is block 3

    // Calculate number of deposit groups
    const NUM_DEPOSIT_GROUPS = Math.ceil(DEPOSITS_PER_BLOCK / 3);

    // Target update index in blockUpdates array
    // For cross-blob: always target a transaction (tx 272) at the blob boundary
    // For deposits: use group 1 (not 0) so isLast = false when numTx > 0
    // For transactions: use transaction 0 (first tx after all deposits)
    let TARGET_UPDATE_INDEX;
    let TARGET_IS_TX;
    if (crossblobMode) {
        // In cross-blob mode, we target transaction 272 (0-indexed), which is at update index (numDepositGroups + 272)
        TARGET_UPDATE_INDEX = NUM_DEPOSIT_GROUPS + 272;
        TARGET_IS_TX = true;
        const depositsLength = NUM_DEPOSIT_GROUPS * 4;
        const txNr = TARGET_UPDATE_INDEX - NUM_DEPOSIT_GROUPS;
        const memoryAddress = depositsLength + txNr * 15 + 11;
        console.error(`  Deposits: ${DEPOSITS_PER_BLOCK} (${NUM_DEPOSIT_GROUPS} groups = ${depositsLength} elements)`);
        console.error(`  Transactions: ${TX_PER_BLOCK}`);
        console.error(`  Target TX: ${txNr} (update index ${TARGET_UPDATE_INDEX})`);
        console.error(`  Memory Address: ${memoryAddress} (4 elements span ${memoryAddress}-${memoryAddress + 3})`);
        console.error(`  Elements in blob 1: ${4096 - memoryAddress}, Elements in blob 2: ${memoryAddress + 4 - 4096}`);
    } else {
        TARGET_UPDATE_INDEX = targetTx ? NUM_DEPOSIT_GROUPS : 1;
        TARGET_IS_TX = targetTx;
    }

    // Track all blocks and root tree states
    const allBlocks = [];
    const rootTreeStates = []; // Store root tree state before each block
    let currentAnchor = genesisAnchor;

    // Process all days and blocks
    for (let day = 0; day < DAYS; day++) {
        for (let blockIdx = 0; blockIdx < BLOCKS_PER_TEST_DAY; blockIdx++) {
            // Save root tree state BEFORE processing this block
            rootTreeStates.push(rootTree.clone());

            // Create fresh block tree for this block
            const blockTree = new SparseMerkleTree(BLOCK_DEPTH, blockZeroHashes);

            const blockData = processBlock(
                blockTree,
                rootTree,
                currentAnchor,
                day,
                blockIdx,
                DEPOSITS_PER_BLOCK,
                TX_PER_BLOCK,
                blockZeroHashes,
                rootZeroHashes
            );

            allBlocks.push(blockData);
            currentAnchor = BigInt(blockData.finalAnchor);
        }
    }

    // Find target block for ZK proof generation
    const targetBlockData = allBlocks.find(b => b.day === TARGET_DAY && b.blockIdx === TARGET_BLOCK);
    const targetUpdate = targetBlockData.blockUpdates[TARGET_UPDATE_INDEX];

    // Get the block BEFORE target for prior anchor context
    const targetBlockIndex = allBlocks.indexOf(targetBlockData);
    const priorBlockData = targetBlockIndex > 0 ? allBlocks[targetBlockIndex - 1] : null;

    // Get the root tree state BEFORE the target block was processed
    const rootTreeBeforeTarget = rootTreeStates[targetBlockIndex];

    // Reconstruct block tree state before target update
    const blockTree = new SparseMerkleTree(BLOCK_DEPTH, blockZeroHashes);

    // Insert all updates before target update
    let leafIndex = 0;
    for (let i = 0; i < TARGET_UPDATE_INDEX; i++) {
        const update = targetBlockData.blockUpdates[i];
        for (let j = 0; j < 3; j++) {
            const val = BigInt(update.updates[j]);
            if (val !== BigInt(0)) {
                blockTree.setLeaf(leafIndex + j, val);
            }
        }
        leafIndex += 3;
    }

    // Generate ZK proof for target update
    const circuitDir = path.join(__dirname, "..", "circuits", "outputs", "predictableUpdate");
    const wasmPath = path.join(circuitDir, "predictableUpdate_js", "predictableUpdate.wasm");
    const zkeyPath = path.join(circuitDir, "predictableUpdate.zkey");

    if (!fs.existsSync(wasmPath)) {
        console.error("ERROR: Circuit wasm not found at: " + wasmPath);
        process.exit(1);
    }

    if (!fs.existsSync(zkeyPath)) {
        console.error("ERROR: Circuit zkey not found at: " + zkeyPath);
        process.exit(1);
    }

    const updates = targetUpdate.updates.map(u => BigInt(u));
    const priorAnchor = BigInt(targetUpdate.priorAnchor);
    const treeIndex = targetBlockData.treeIndex;
    const inBlockIndex = targetUpdate.inBlockIndex;

    const targetTypeStr = TARGET_IS_TX ? `transaction ${TARGET_UPDATE_INDEX - NUM_DEPOSIT_GROUPS}` : `deposit group ${TARGET_UPDATE_INDEX}`;
    console.error(`Generating ZK proof for day ${TARGET_DAY}, block ${TARGET_BLOCK}, ${targetTypeStr}`);
    console.error(`TreeIndex: ${treeIndex}, InBlockIndex: ${inBlockIndex}`);
    console.error(`PriorAnchor: ${priorAnchor}`);
    console.error(`Updates: ${updates.join(', ')}`);

    // Use the root tree state from BEFORE the target block was processed
    // This ensures the ZK proof uses the correct sibling values in the root path
    const { proof, publicSignals } = await generateZkProof(
        priorAnchor,
        treeIndex,
        updates,
        inBlockIndex,
        blockTree,
        rootTreeBeforeTarget,
        wasmPath,
        zkeyPath
    );

    // Build blob data for target block (deposits + tx updates)
    // Blob format:
    //   - Each deposit group: 4 elements (update0, update1, update2, anchor)
    //   - Each transaction: 15 elements (8 ZK proof, 1 tx info, 2 nullifiers, 3 updates, 1 anchor)
    // In fraud mode, we corrupt the anchor for the target group
    const blobData = [];
    let fraudAnchor = null;

    for (let updateIdx = 0; updateIdx < targetBlockData.blockUpdates.length; updateIdx++) {
        const update = targetBlockData.blockUpdates[updateIdx];
        const isTransaction = update.type === 'transaction';

        if (isTransaction) {
            // Transaction format: 15 elements
            // [0-7]: ZK proof (pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1])
            // [8]: Encoded tx info
            // [9-10]: Nullifiers
            // [11-13]: Updates
            // [14]: Anchor

            // Add placeholder ZK proof elements (8 elements)
            for (let i = 0; i < 8; i++) {
                blobData.push('0');
            }
            // Add placeholder tx info (1 element)
            blobData.push('0');
            // Add placeholder nullifiers (2 elements)
            blobData.push('0');
            blobData.push('0');
            // Add updates (3 elements)
            blobData.push(update.updates[0]);
            blobData.push(update.updates[1]);
            blobData.push(update.updates[2]);
            // Add anchor (1 element)
            if (fraudMode && updateIdx === TARGET_UPDATE_INDEX) {
                fraudAnchor = (BigInt(update.newAnchor) + BigInt(1)).toString();
                blobData.push(fraudAnchor);
                console.error(`FRAUD: Corrupted anchor for group ${updateIdx}`);
                console.error(`  Correct anchor: ${update.newAnchor}`);
                console.error(`  Fraud anchor:   ${fraudAnchor}`);
            } else {
                blobData.push(update.newAnchor);
            }
        } else {
            // Deposit format: 4 elements (update0, update1, update2, anchor)
            blobData.push(update.updates[0]);
            blobData.push(update.updates[1]);
            blobData.push(update.updates[2]);
            if (fraudMode && updateIdx === TARGET_UPDATE_INDEX) {
                fraudAnchor = (BigInt(update.newAnchor) + BigInt(1)).toString();
                blobData.push(fraudAnchor);
                console.error(`FRAUD: Corrupted anchor for group ${updateIdx}`);
                console.error(`  Correct anchor: ${update.newAnchor}`);
                console.error(`  Fraud anchor:   ${fraudAnchor}`);
            } else {
                blobData.push(update.newAnchor);
            }
        }
    }

    // Calculate the memory position for the target region
    // Deposit groups: 4 elements each, starting at position 0
    // Transactions: 15 elements each, starting after all deposits
    let regionStart;
    let priorAnchorPosition;

    if (TARGET_IS_TX) {
        // For transactions, TreeUpdateChallenge expects region at txMemoryAddress + 11
        // txMemoryAddress = depositsLength + txNumber * 15
        // depositsLength = numDepositGroups * 4
        const depositsLength = NUM_DEPOSIT_GROUPS * 4;
        const txNumber = TARGET_UPDATE_INDEX - NUM_DEPOSIT_GROUPS;
        // Region should cover positions 11-14 of the transaction (3 updates + anchor)
        regionStart = depositsLength + txNumber * 15 + 11;
        // Prior anchor is at position 14 of the PREVIOUS update
        if (txNumber > 0) {
            // Prior tx's anchor at position 14
            priorAnchorPosition = depositsLength + (txNumber - 1) * 15 + 14;
        } else {
            // Last deposit group's anchor
            priorAnchorPosition = (NUM_DEPOSIT_GROUPS - 1) * 4 + 3;
        }
    } else {
        // For deposits, region starts at updateIndex * 4
        regionStart = TARGET_UPDATE_INDEX * 4;
        // Prior anchor is at previous group's position + 3
        priorAnchorPosition = TARGET_UPDATE_INDEX > 0 ? (TARGET_UPDATE_INDEX - 1) * 4 + 3 : null;
    }

    // Calculate region split for cross-blob
    let regionLength = 4; // Tree update needs 4 elements
    let extensionRegionLength = 0;
    let extensionRegionMemoryAddress = 0;
    let blob1Data = blobData;
    let blob2Data = [];

    if (crossblobMode && regionStart + 4 > 4096) {
        // Update spans blob boundary
        regionLength = 4096 - regionStart;
        extensionRegionLength = 4 - regionLength;
        extensionRegionMemoryAddress = 0; // Extension region starts at beginning of blob 2

        // Split blob data at position 4096
        blob1Data = blobData.slice(0, 4096);
        blob2Data = blobData.slice(4096);

        // Pad blob1Data to exactly 4096 elements if needed
        while (blob1Data.length < 4096) {
            blob1Data.push('0');
        }

        console.error(`Cross-blob split: region.length=${regionLength}, extensionRegion.length=${extensionRegionLength}`);
        console.error(`Blob 1 size: ${blob1Data.length}, Blob 2 size: ${blob2Data.length}`);
    }

    // Prepare KZG indices
    let kzgIndices;
    let extensionKzgIndices = null;
    let kzgData, extensionKzgData = null;

    if (crossblobMode && extensionRegionLength > 0) {
        // Generate KZG proofs for blob 1 (region indices + prior anchor)
        kzgIndices = [];
        for (let i = 0; i < regionLength; i++) {
            kzgIndices.push(regionStart + i);
        }

        // For updates > 0, we also need proof for the prior anchor position
        if (priorAnchorPosition !== null && TARGET_UPDATE_INDEX > 0) {
            kzgIndices = [priorAnchorPosition, ...kzgIndices];
        }

        console.error(`Generating KZG proofs for blob 1 indices: ${kzgIndices.join(', ')}`);
        kzgData = generateKzgProofs(blob1Data, kzgIndices);

        // Generate KZG proofs for blob 2 (extension region indices)
        extensionKzgIndices = [];
        for (let i = 0; i < extensionRegionLength; i++) {
            extensionKzgIndices.push(i);
        }

        // Pad blob 2 data to 4096 elements
        while (blob2Data.length < 4096) {
            blob2Data.push('0');
        }

        console.error(`Generating KZG proofs for blob 2 indices: ${extensionKzgIndices.join(', ')}`);
        extensionKzgData = generateKzgProofs(blob2Data, extensionKzgIndices);
    } else {
        // Single blob case
        kzgIndices = [regionStart, regionStart + 1, regionStart + 2, regionStart + 3];

        // For updates > 0, we also need proof for the prior anchor position
        if (priorAnchorPosition !== null && TARGET_UPDATE_INDEX > 0) {
            // Insert at the beginning so it's at index 0 in the proofs array
            kzgIndices = [priorAnchorPosition, ...kzgIndices];
        }

        console.error(`Generating KZG proofs for indices: ${kzgIndices.join(', ')}`);
        kzgData = generateKzgProofs(blobData, kzgIndices);
    }

    // Output comprehensive test data
    const output = {
        // Genesis and configuration
        genesisAnchor: genesisAnchor.toString(),
        fraudMode: fraudMode,
        fraudAnchor: fraudAnchor,
        crossblobMode: crossblobMode,
        targetIsTx: TARGET_IS_TX,
        config: {
            days: DAYS,
            blocksPerDay: BLOCKS_PER_TEST_DAY,
            depositsPerBlock: DEPOSITS_PER_BLOCK,
            txPerBlock: TX_PER_BLOCK,
            targetDay: TARGET_DAY,
            targetBlock: TARGET_BLOCK,
            targetUpdateIndex: TARGET_UPDATE_INDEX,
            numDepositGroups: NUM_DEPOSIT_GROUPS,
            regionStart: regionStart,
            priorAnchorPosition: priorAnchorPosition
        },

        // Region split info (for cross-blob)
        regionLength: regionLength,
        extensionRegionLength: extensionRegionLength,
        extensionRegionMemoryAddress: extensionRegionMemoryAddress,

        // All blocks summary
        blocks: allBlocks.map(b => ({
            day: b.day,
            blockIdx: b.blockIdx,
            treeIndex: b.treeIndex,
            numDeposits: b.numDeposits,
            numTx: b.numTx,
            finalAnchor: b.finalAnchor
        })),

        // Target block details
        targetBlock: {
            day: targetBlockData.day,
            blockIdx: targetBlockData.blockIdx,
            treeIndex: targetBlockData.treeIndex,
            numDeposits: targetBlockData.numDeposits,
            numTx: targetBlockData.numTx,
            deposits: targetBlockData.deposits,
            txUpdates: targetBlockData.txUpdates,
            blockUpdates: targetBlockData.blockUpdates,
            finalAnchor: targetBlockData.finalAnchor,
            blobData: blobData,
            // For cross-blob, include split blob data
            blob1Data: crossblobMode ? blob1Data : null,
            blob2Data: crossblobMode ? blob2Data : null
        },

        // Prior block (for context)
        priorBlock: priorBlockData ? {
            day: priorBlockData.day,
            blockIdx: priorBlockData.blockIdx,
            treeIndex: priorBlockData.treeIndex,
            finalAnchor: priorBlockData.finalAnchor
        } : null,

        // Target update details
        targetUpdate: {
            type: targetUpdate.type,
            groupIndex: targetUpdate.groupIndex,
            updates: targetUpdate.updates,
            priorAnchor: targetUpdate.priorAnchor,
            newAnchor: targetUpdate.newAnchor,
            inBlockIndex: targetUpdate.inBlockIndex
        },

        // ZK proof
        proof: proof,
        publicSignals: publicSignals,

        // Anchor before target block (the anchor with empty block tree at target's treeIndex)
        // This is the correct "genesis" anchor for this specific block
        anchorBeforeTargetBlock: targetBlockData.blockPriorAnchor,

        // KZG proof data for blob 1 (binary file path for Solidity to decode)
        kzgProofBinaryPath: kzgData.binaryPath,
        kzgIndices: kzgData.indices,

        // KZG proof data for blob 2 (extension region) - only in cross-blob mode
        extensionKzgBinaryPath: extensionKzgData ? extensionKzgData.binaryPath : null,
        extensionKzgIndices: extensionKzgIndices
    };

    // Generate unique output path based on flags and UUID to avoid race conditions when tests run in parallel
    let outputSuffix = '';
    if (crossblobMode) outputSuffix += '_crossblob';
    if (targetTx && !crossblobMode) outputSuffix += '_tx';
    if (fraudMode) outputSuffix += '_fraud';
    const uniqueId = crypto.randomBytes(4).toString('hex');
    const outputPath = `/tmp/multi_block_test_data${outputSuffix}_${uniqueId}.json`;
    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));

    process.stdout.write(outputPath);
    process.exit(0);
}

main().catch(err => {
    console.error("ERROR:", err);
    process.exit(1);
});
