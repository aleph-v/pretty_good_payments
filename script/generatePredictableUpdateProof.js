#!/usr/bin/env node
/**
 * FFI script to generate a predictableUpdate ZK proof
 *
 * Usage: node generatePredictableUpdateProof.js
 *
 * This script generates a valid proof for the predictableUpdate circuit.
 * The circuit verifies 3 sequential tree updates at positions inBlockIndex, inBlockIndex+1, inBlockIndex+2.
 * Each proof must be for the tree state AFTER the previous update.
 *
 * Output format: JSON with proof and publicSignals
 */

const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");

let poseidon = null;
let F = null;

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

/**
 * Pre-compute zero hashes for a tree of given depth
 * zeroHashes[i] = hash of two children that are both zeroHashes[i-1]
 * zeroHashes[0] = 0 (the leaf value)
 */
function computeZeroHashes(depth) {
    const zeroHashes = [BigInt(0)];
    for (let i = 1; i <= depth; i++) {
        zeroHashes.push(poseidonHash2(zeroHashes[i - 1], zeroHashes[i - 1]));
    }
    return zeroHashes;
}

/**
 * Sparse Merkle Tree that supports efficient updates
 */
class SparseMerkleTree {
    constructor(depth, zeroHashes) {
        this.depth = depth;
        this.zeroHashes = zeroHashes;
        // Store non-zero nodes: level -> index -> value
        this.nodes = new Map();
        for (let i = 0; i <= depth; i++) {
            this.nodes.set(i, new Map());
        }
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

    /**
     * Get Merkle proof for a leaf at given index
     */
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

    /**
     * Set a leaf value and update all parent nodes
     */
    setLeaf(index, value) {
        let idx = index;
        let currentValue = value;

        // Set the leaf
        this.setNode(0, index, value);

        // Update all parents
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
 * Compute Merkle root of a sparse tree with one leaf set at index 0
 */
function computeSparseRoot(leaf, index, depth, zeroHashes) {
    let current = leaf;
    let idx = index;
    for (let i = 0; i < depth; i++) {
        const sibling = zeroHashes[i];
        if ((idx & 1) === 0) {
            current = poseidonHash2(current, sibling);
        } else {
            current = poseidonHash2(sibling, current);
        }
        idx = idx >> 1;
    }
    return current;
}

async function main() {
    await initPoseidon();

    // Circuit depths
    const BLOCK_DEPTH = 16; // 2^16 = 65536 elements in a block
    const ROOT_DEPTH = 28;  // Root tree depth

    // Pre-compute zero hashes
    const blockZeroHashes = computeZeroHashes(BLOCK_DEPTH);
    const rootZeroHashes = computeZeroHashes(ROOT_DEPTH);

    // Create a sparse block tree
    const blockTree = new SparseMerkleTree(BLOCK_DEPTH, blockZeroHashes);

    // Block root of an empty block tree
    const blockRootBefore = blockTree.getRoot();

    // Block index we're updating (using 0 for simplicity)
    const blockIndex = BigInt(0);

    // In-block index where we start inserting (0 for first 3 leaves)
    const inBlockIndex = 0;

    // The three updates we're inserting
    const updates = [BigInt(100), BigInt(200), BigInt(300)];

    // Compute anchor before: root of the root tree with blockRootBefore at blockIndex
    const anchorBefore = computeSparseRoot(blockRootBefore, Number(blockIndex), ROOT_DEPTH, rootZeroHashes);

    // For the nonzeroField check:
    // If inBlockIndex == 0, isIndexZero = 1, so the constraint 1 === isRootEqual*isElementNonzero + isIndexZero passes
    // We just need blockProofs[0] to open the correct position
    const nonzeroField = BigInt(0);

    // Generate block proofs incrementally as we update the tree
    const blockProofs = [];

    // blockProofs[0]: proof for position inBlockIndex - 1 (or just index 0 if inBlockIndex is 0)
    // Since inBlockIndex == 0, we can use any valid proof, but the formula uses inBlockIndex - isIndexNonZero
    // When inBlockIndex == 0: isIndexZero = 1, isIndexNonZero = 0, so index = 0 - 0 = 0
    blockProofs.push(blockTree.getProof(inBlockIndex));

    // blockProofs[1]: proof for position inBlockIndex in the initial empty tree
    // Used to verify leaf at inBlockIndex is 0, then compute root after inserting updates[0]
    blockProofs.push(blockTree.getProof(inBlockIndex));

    // Insert updates[0] at inBlockIndex
    blockTree.setLeaf(inBlockIndex, updates[0]);

    // blockProofs[2]: proof for position inBlockIndex + 1 AFTER updates[0] is inserted
    // Used to verify leaf at inBlockIndex+1 is 0, then compute root after inserting updates[1]
    blockProofs.push(blockTree.getProof(inBlockIndex + 1));

    // Insert updates[1] at inBlockIndex + 1
    blockTree.setLeaf(inBlockIndex + 1, updates[1]);

    // blockProofs[3]: proof for position inBlockIndex + 2 AFTER updates[0] and updates[1] are inserted
    // Used to verify leaf at inBlockIndex+2 is 0, then compute root after inserting updates[2]
    blockProofs.push(blockTree.getProof(inBlockIndex + 2));

    // Root path proof - for blockIndex in the root tree (still empty)
    const rootPath = [];
    for (let i = 0; i < ROOT_DEPTH; i++) {
        rootPath.push(rootZeroHashes[i]);
    }

    // Construct the witness input
    const input = {
        anchorBefore: anchorBefore.toString(),
        blockRootBefore: blockRootBefore.toString(),
        updates: updates.map(u => u.toString()),
        blockIndex: blockIndex.toString(),
        inBlockIndex: inBlockIndex.toString(),
        nonzeroField: nonzeroField.toString(),
        blockProofs: blockProofs.map(proof => proof.map(p => p.toString())),
        rootPath: rootPath.map(p => p.toString())
    };

    // Paths to circuit files
    const circuitDir = path.join(__dirname, "..", "circuits", "outputs", "predictableUpdate");
    const wasmPath = path.join(circuitDir, "predictableUpdate_js", "predictableUpdate.wasm");
    const zkeyPath = path.join(circuitDir, "predictableUpdate.zkey");

    // Check if files exist
    if (!fs.existsSync(wasmPath)) {
        console.error("ERROR: Circuit wasm not found at: " + wasmPath);
        process.exit(1);
    }

    if (!fs.existsSync(zkeyPath)) {
        console.error("ERROR: Circuit zkey not found at: " + zkeyPath);
        process.exit(1);
    }

    try {
        // Generate the proof
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasmPath,
            zkeyPath
        );

        // Format proof for Solidity (note: pi_b coordinates need to be swapped for Solidity)
        const solidityProof = {
            _pA: [proof.pi_a[0], proof.pi_a[1]],
            _pB: [
                [proof.pi_b[0][1], proof.pi_b[0][0]],
                [proof.pi_b[1][1], proof.pi_b[1][0]]
            ],
            _pC: [proof.pi_c[0], proof.pi_c[1]]
        };

        // Output JSON
        const output = {
            proof: solidityProof,
            publicSignals: publicSignals
        };

        process.stdout.write(JSON.stringify(output));

        // Force exit - snarkjs/circomlibjs keep event loops alive
        process.exit(0);
    } catch (err) {
        console.error("ERROR: Proof generation failed:", err.message);
        if (err.stack) {
            console.error(err.stack);
        }
        process.exit(1);
    }
}

main().catch(err => {
    console.error("ERROR:", err);
    process.exit(1);
});
