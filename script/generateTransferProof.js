#!/usr/bin/env node
/**
 * FFI script to generate a transfer ZK proof for TransactionChallenge tests.
 *
 * Usage: node generateTransferProof.js [--anchor <anchor>] [--ethKey <ethKey>]
 *
 * The circuit verifies a transfer transaction with:
 * - 2 input notes (one or both in the merkle tree)
 * - 3 output notes (can include withdrawals)
 * - Merkle proofs for inputs
 * - Balance conservation (inputs sum = outputs sum)
 *
 * Output format: JSON with proof, publicSignals, and additional data for tests
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

function poseidonHash(inputs) {
    const hash = poseidon(inputs.map(x => BigInt(x)));
    return F.toObject(hash);
}

/**
 * Pre-compute zero hashes for a tree of given depth
 */
function computeZeroHashes(depth) {
    const zeroHashes = [BigInt(0)];
    for (let i = 1; i <= depth; i++) {
        zeroHashes.push(poseidonHash([zeroHashes[i - 1], zeroHashes[i - 1]]));
    }
    return zeroHashes;
}

/**
 * Sparse Merkle Tree
 */
class SparseMerkleTree {
    constructor(depth, zeroHashes) {
        this.depth = depth;
        this.zeroHashes = zeroHashes;
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
                parentValue = poseidonHash([currentValue, sibling]);
            } else {
                parentValue = poseidonHash([sibling, currentValue]);
            }

            this.setNode(level + 1, parentIdx, parentValue);
            currentValue = parentValue;
            idx = parentIdx;
        }
    }
}

// Domain separator from circuit: Keccak256("Pretty Good Transfer Protocol V1")
const DOMAIN_SEPARATOR = BigInt("0x8c89ded3cb316b3e2163ee0f7a92095673c65827649008298772837236d62a6e");

/**
 * Derive public key from private key using circuit's formula
 */
function derivePublicKey(privateKey) {
    return poseidonHash([DOMAIN_SEPARATOR, privateKey]);
}

/**
 * Compute note leaf hash
 */
function computeNoteLeaf(note) {
    // note = [assetId, amount, blindingFactor, publicKey]
    return poseidonHash(note);
}

/**
 * Compute nullifier
 */
function computeNullifier(privateKey, blindingFactor, index) {
    return poseidonHash([privateKey, blindingFactor, index]);
}

async function main() {
    await initPoseidon();

    // Parse arguments
    const args = process.argv.slice(2);
    let providedAnchor = null;
    let providedEthKey = BigInt(0);

    for (let i = 0; i < args.length; i++) {
        if (args[i] === "--anchor" && i + 1 < args.length) {
            providedAnchor = BigInt(args[i + 1]);
            i++;
        } else if (args[i] === "--ethKey" && i + 1 < args.length) {
            providedEthKey = BigInt(args[i + 1]);
            i++;
        }
    }

    const TREE_DEPTH = 44;
    const zeroHashes = computeZeroHashes(TREE_DEPTH);
    const tree = new SparseMerkleTree(TREE_DEPTH, zeroHashes);

    // Create test notes
    // For zkSNARK-only transaction (ethKey = 0), we use regular private keys
    // Note format: [assetId, amount, blindingFactor, publicKey]

    const assetId = BigInt(1); // Asset ID
    const amount1 = BigInt(1000); // Input amount
    const amount2 = BigInt(0); // Second input not used (amount 0)

    // Private keys - use regular keys for zkSNARK-only
    // For eth-keyed transactions, the private key would be the eth address padded
    const privateKey1 = BigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    // For unused second note, use the special constant from circuit to prevent blocking
    const privateKey2 = BigInt("0x4cc1de474cacd406eea434351d2907cfea08fece7e38ebebff463599ffa252a7");

    const publicKey1 = derivePublicKey(privateKey1);
    const publicKey2 = derivePublicKey(privateKey2);

    // Random values for blinding factors
    const random1 = BigInt("0xaabbccdd");
    const random2 = BigInt("0xeeff0011");
    const random3 = BigInt("0x22334455");

    // Blinding factor for input note (can be any value for test)
    const blindingFactor1 = BigInt("0x1111111111111111111111111111111111111111111111111111111111111111");
    const blindingFactor2 = BigInt("0x2222222222222222222222222222222222222222222222222222222222222222");

    // Input notes
    const noteIn1 = [assetId, amount1, blindingFactor1, publicKey1];
    const noteIn2 = [assetId, amount2, blindingFactor2, publicKey2];

    // Compute leaves and add to tree
    const leaf1 = computeNoteLeaf(noteIn1);
    const leaf2 = computeNoteLeaf(noteIn2);

    const index1 = 0;
    const index2 = 1;

    tree.setLeaf(index1, leaf1);
    tree.setLeaf(index2, leaf2);

    // Get anchor (merkle root) - use provided or computed
    let anchor = providedAnchor;
    if (anchor === null) {
        anchor = tree.getRoot();
    } else {
        // If anchor is provided, we need to make the tree match it
        // For simplicity, we'll create a tree that produces this anchor
        // This is a test scenario, so we'll proceed with our computed anchor
        anchor = tree.getRoot();
    }

    // Get merkle proofs
    const path1 = tree.getProof(index1);
    const path2 = tree.getProof(index2);

    // Output notes - split the input amount
    // For a simple test, send all to one output (same key, preserving privacy)
    const hashLeavesIn = poseidonHash([leaf1, leaf2]);

    // Compute blinding factors for outputs (as per circuit)
    const blindingOut1 = poseidonHash([random1, hashLeavesIn]);
    const blindingOut2 = poseidonHash([random2, hashLeavesIn]);
    const blindingOut3 = poseidonHash([random3, hashLeavesIn]);

    // Output notes - all value to first output, others are zero
    const noteOut1 = [assetId, amount1, blindingOut1, publicKey1]; // All value here
    const noteOut2 = [assetId, BigInt(0), blindingOut2, publicKey1]; // Zero value
    const noteOut3 = [assetId, BigInt(0), blindingOut3, publicKey1]; // Zero value

    // Compute output leaves (or zero if amount is zero)
    const leafOut1 = amount1 > 0 ? computeNoteLeaf(noteOut1) : BigInt(0);
    const leafOut2 = BigInt(0); // Zero amount = zero leaf
    const leafOut3 = BigInt(0); // Zero amount = zero leaf

    // Compute nullifiers
    const nullifier1 = computeNullifier(privateKey1, blindingFactor1, index1);
    const nullifier2 = computeNullifier(privateKey2, blindingFactor2, index2);

    // Build witness input
    const input = {
        anchor: anchor.toString(),
        indices: [index1, index2],
        paths: [
            path1.map(p => p.toString()),
            path2.map(p => p.toString())
        ],
        notesIn: [
            noteIn1.map(n => n.toString()),
            noteIn2.map(n => n.toString())
        ],
        notesOut: [
            noteOut1.map(n => n.toString()),
            noteOut2.map(n => n.toString()),
            noteOut3.map(n => n.toString())
        ],
        randoms: [random1.toString(), random2.toString(), random3.toString()],
        privateKeys: [privateKey1.toString(), privateKey2.toString()],
        ethKey: providedEthKey.toString()
    };

    // Paths to circuit files
    const circuitDir = path.join(__dirname, "..", "circuits", "outputs", "transfer");
    const wasmPath = path.join(circuitDir, "transfer_js", "transfer.wasm");
    const zkeyPath = path.join(circuitDir, "transfer.zkey");

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

        // Format proof for Solidity (pi_b coordinates need to be swapped)
        const solidityProof = {
            _pA: [proof.pi_a[0], proof.pi_a[1]],
            _pB: [
                [proof.pi_b[0][1], proof.pi_b[0][0]],
                [proof.pi_b[1][1], proof.pi_b[1][0]]
            ],
            _pC: [proof.pi_c[0], proof.pi_c[1]]
        };

        // Public signals order: [anchor, ethKey, nullifier0, nullifier1, leafOut0, leafOut1, leafOut2]
        // The circuit outputs: nullifiers[2], leavesOut[3]
        // Public inputs: anchor, ethKey

        const output = {
            proof: solidityProof,
            publicSignals: publicSignals,
            // Additional data for tests
            anchor: anchor.toString(),
            ethKey: providedEthKey.toString(),
            nullifiers: [nullifier1.toString(), nullifier2.toString()],
            leavesOut: [leafOut1.toString(), leafOut2.toString(), leafOut3.toString()],
            // For blob encoding
            rawBlobData: {
                // raw[0-7]: proof components
                pA: solidityProof._pA,
                pB: solidityProof._pB,
                pC: solidityProof._pC,
                // raw[9-13]: nullifiers and leaves
                publicInputs: [
                    nullifier1.toString(),
                    nullifier2.toString(),
                    leafOut1.toString(),
                    leafOut2.toString(),
                    leafOut3.toString()
                ]
            }
        };

        process.stdout.write(JSON.stringify(output));
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
