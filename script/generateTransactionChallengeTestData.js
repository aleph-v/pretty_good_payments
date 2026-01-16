#!/usr/bin/env node
/**
 * FFI script to generate comprehensive test data for TransactionChallenge integration tests.
 *
 * Usage: node generateTransactionChallengeTestData.js [flags]
 *
 * Flags:
 *   --fraud          Generate a fraudulent ZK proof (incorrect anchor)
 *   --unregistered   Generate a valid ZK proof but for an unregistered eth key transaction
 *   --crossblob      Generate transaction spanning blob boundary
 *   --multi-tx       Generate block with multiple transactions (5 tx, target tx 3)
 *   --deposit-anchor Transaction references a deposit anchor instead of transaction anchor
 *   --same-block     Transaction references an anchor from same block (earlier update)
 *
 * This script generates:
 * 1. Multi-day, multi-block chain with proper anchor progression
 * 2. A target block containing a transaction with:
 *    - Real transfer ZK proof (Groth16)
 *    - Proper blob encoding (14 elements for the transaction)
 *    - Real KZG proofs for blob validation
 * 3. All data needed to construct and validate the challenge
 */

const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { execSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function generateUUID() {
    return crypto.randomBytes(16).toString("hex");
}

// Cross-blob configuration constants
// These values position transaction 272 at memory address 4088, spanning the 4096 blob boundary
const CROSSBLOB_CONFIG = {
    depositsPerBlock: 6,        // 2 groups * 4 elements = 8 elements
    txPerBlock: 273,            // Need 273 transactions so tx 272 is at position 4088
    targetTxNr: 272,            // This tx spans the blob boundary
    numDepositGroups: 2         // ceil(6/3) = 2
};

// Multi-transaction configuration constants
// Block with 5 transactions, target is transaction 3 (0-indexed)
const MULTI_TX_CONFIG = {
    depositsPerBlock: 12,       // 4 groups * 4 elements = 16 elements
    txPerBlock: 5,              // 5 transactions per block
    targetTxNr: 3,              // Challenge the 4th transaction (0-indexed)
    numDepositGroups: 4         // ceil(12/3) = 4
};

// Deposit anchor reference configuration
// Transaction references a deposit group's anchor instead of a transaction anchor
const DEPOSIT_ANCHOR_CONFIG = {
    depositsPerBlock: 12,       // 4 groups * 4 elements = 16 elements
    txPerBlock: 1,              // 1 transaction per block
    targetTxNr: 0,              // Challenge the transaction
    numDepositGroups: 4,        // ceil(12/3) = 4
    anchorDepositGroup: 2       // Reference deposit group 2's anchor (0-indexed)
};

// Same-block anchor reference configuration
// Transaction references an anchor from an earlier update in the SAME block
const SAME_BLOCK_CONFIG = {
    depositsPerBlock: 12,       // 4 groups * 4 elements = 16 elements
    txPerBlock: 5,              // 5 transactions - need multiple to reference earlier one
    targetTxNr: 4,              // Challenge the 5th transaction (0-indexed)
    numDepositGroups: 4,        // ceil(12/3) = 4
    anchorTxNrInSameBlock: 1    // Reference transaction 1's anchor in the same block
};

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

function computeZeroHashes(depth) {
    const zeroHashes = [BigInt(0)];
    for (let i = 1; i <= depth; i++) {
        zeroHashes.push(poseidonHash([zeroHashes[i - 1], zeroHashes[i - 1]]));
    }
    return zeroHashes;
}

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

// Constants
const BLOCK_DEPTH = 12;
const ROOT_DEPTH = 28;
const TREE_DEPTH = 40; // For transfer circuit merkle tree
const DOMAIN_SEPARATOR = BigInt("0x8c89ded3cb316b3e2163ee0f7a92095673c65827649008298772837236d62a6e");

function derivePublicKey(privateKey) {
    return poseidonHash([DOMAIN_SEPARATOR, privateKey]);
}

function computeNoteLeaf(note) {
    return poseidonHash(note);
}

function computeNullifier(privateKey, blindingFactor, index) {
    return poseidonHash([privateKey, blindingFactor, index]);
}

function computeSparseRoot(leaf, index, depth, zeroHashes) {
    let current = leaf;
    let idx = index;
    for (let i = 0; i < depth; i++) {
        const sibling = zeroHashes[i];
        if ((idx & 1) === 0) {
            current = poseidonHash([current, sibling]);
        } else {
            current = poseidonHash([sibling, current]);
        }
        idx = idx >> 1;
    }
    return current;
}

/**
 * Encode transaction info matching the contract's encoding
 * Bit layout:
 *   - Bit 254: isDeposit
 *   - Bits 253-222: blockNr (32 bits)
 *   - Bits 221-190: updateNr (32 bits)
 *   - Bits 159-0: ethAddress (160 bits, at LOW bits)
 */
function encodeTxInfo(blockNr, updateNr, isDeposit, ethAddress) {
    let ret = isDeposit ? (BigInt(1) << BigInt(254)) : BigInt(0);
    ret = ret | ((BigInt(blockNr) << BigInt(222)) + (BigInt(updateNr) << BigInt(190)));
    ret = ret | BigInt(ethAddress);
    return ret;
}

/**
 * Generate transfer ZK proof
 */
async function generateTransferProof(anchor, ethKey, fraudMode = false) {
    const treeZeroHashes = computeZeroHashes(TREE_DEPTH);
    const tree = new SparseMerkleTree(TREE_DEPTH, treeZeroHashes);

    const assetId = BigInt(1);
    const amount1 = BigInt(1000);
    const amount2 = BigInt(0);

    const privateKey1 = BigInt("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    const privateKey2 = BigInt("0x4cc1de474cacd406eea434351d2907cfea08fece7e38ebebff463599ffa252a7");

    const publicKey1 = derivePublicKey(privateKey1);
    const publicKey2 = derivePublicKey(privateKey2);

    const random1 = BigInt("0xaabbccdd");
    const random2 = BigInt("0xeeff0011");
    const random3 = BigInt("0x22334455");

    const blindingFactor1 = BigInt("0x1111111111111111111111111111111111111111111111111111111111111111");
    const blindingFactor2 = BigInt("0x2222222222222222222222222222222222222222222222222222222222222222");

    const noteIn1 = [assetId, amount1, blindingFactor1, publicKey1];
    const noteIn2 = [assetId, amount2, blindingFactor2, publicKey2];

    const leaf1 = computeNoteLeaf(noteIn1);
    const leaf2 = computeNoteLeaf(noteIn2);

    const index1 = 0;
    const index2 = 1;

    tree.setLeaf(index1, leaf1);
    tree.setLeaf(index2, leaf2);

    // For the ZK proof, we use the tree's actual anchor
    // In fraud mode, the blob will contain a different anchor
    const zkAnchor = tree.getRoot();

    const path1 = tree.getProof(index1);
    const path2 = tree.getProof(index2);

    const hashLeavesIn = poseidonHash([leaf1, leaf2]);
    const blindingOut1 = poseidonHash([random1, hashLeavesIn]);
    const blindingOut2 = poseidonHash([random2, hashLeavesIn]);
    const blindingOut3 = poseidonHash([random3, hashLeavesIn]);

    const noteOut1 = [assetId, amount1, blindingOut1, publicKey1];
    const noteOut2 = [assetId, BigInt(0), blindingOut2, publicKey1];
    const noteOut3 = [assetId, BigInt(0), blindingOut3, publicKey1];

    const leafOut1 = amount1 > 0 ? computeNoteLeaf(noteOut1) : BigInt(0);
    const leafOut2 = BigInt(0);
    const leafOut3 = BigInt(0);

    const nullifier1 = computeNullifier(privateKey1, blindingFactor1, index1);
    const nullifier2 = computeNullifier(privateKey2, blindingFactor2, index2);

    const input = {
        anchor: zkAnchor.toString(),
        indices: [index1, index2],
        paths: [path1.map(p => p.toString()), path2.map(p => p.toString())],
        notesIn: [noteIn1.map(n => n.toString()), noteIn2.map(n => n.toString())],
        notesOut: [noteOut1.map(n => n.toString()), noteOut2.map(n => n.toString()), noteOut3.map(n => n.toString())],
        randoms: [random1.toString(), random2.toString(), random3.toString()],
        privateKeys: [privateKey1.toString(), privateKey2.toString()],
        ethKey: ethKey.toString()
    };

    const circuitDir = path.join(__dirname, "..", "circuits", "outputs", "transfer");
    const wasmPath = path.join(circuitDir, "transfer_js", "transfer.wasm");
    const zkeyPath = path.join(circuitDir, "transfer.zkey");

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

    // Format for Solidity
    const solidityProof = {
        _pA: [proof.pi_a[0], proof.pi_a[1]],
        _pB: [
            [proof.pi_b[0][1], proof.pi_b[0][0]],
            [proof.pi_b[1][1], proof.pi_b[1][0]]
        ],
        _pC: [proof.pi_c[0], proof.pi_c[1]]
    };

    return {
        proof: solidityProof,
        publicSignals,
        anchor: zkAnchor,
        nullifiers: [nullifier1, nullifier2],
        leavesOut: [leafOut1, leafOut2, leafOut3]
    };
}

async function main() {
    await initPoseidon();

    // Parse arguments
    const args = process.argv.slice(2);
    const fraudMode = args.includes("--fraud");
    const unregisteredMode = args.includes("--unregistered");
    const crossblobMode = args.includes("--crossblob");
    const multiTxMode = args.includes("--multi-tx");
    const depositAnchorMode = args.includes("--deposit-anchor");
    const sameBlockMode = args.includes("--same-block");

    // Configuration - choose based on mode flags
    let config;
    if (crossblobMode) {
        config = {
            days: 3,
            blocksPerDay: 5,
            depositsPerBlock: CROSSBLOB_CONFIG.depositsPerBlock,
            txPerBlock: CROSSBLOB_CONFIG.txPerBlock,
            targetDay: 2,
            targetBlock: 2,
            targetTxNr: CROSSBLOB_CONFIG.targetTxNr,
            numDepositGroups: CROSSBLOB_CONFIG.numDepositGroups
        };
    } else if (multiTxMode) {
        config = {
            days: 3,
            blocksPerDay: 5,
            depositsPerBlock: MULTI_TX_CONFIG.depositsPerBlock,
            txPerBlock: MULTI_TX_CONFIG.txPerBlock,
            targetDay: 2,
            targetBlock: 2,
            targetTxNr: MULTI_TX_CONFIG.targetTxNr,
            numDepositGroups: MULTI_TX_CONFIG.numDepositGroups
        };
    } else if (depositAnchorMode) {
        config = {
            days: 3,
            blocksPerDay: 5,
            depositsPerBlock: DEPOSIT_ANCHOR_CONFIG.depositsPerBlock,
            txPerBlock: DEPOSIT_ANCHOR_CONFIG.txPerBlock,
            targetDay: 2,
            targetBlock: 2,
            targetTxNr: DEPOSIT_ANCHOR_CONFIG.targetTxNr,
            numDepositGroups: DEPOSIT_ANCHOR_CONFIG.numDepositGroups,
            anchorDepositGroup: DEPOSIT_ANCHOR_CONFIG.anchorDepositGroup
        };
    } else if (sameBlockMode) {
        config = {
            days: 3,
            blocksPerDay: 5,
            depositsPerBlock: SAME_BLOCK_CONFIG.depositsPerBlock,
            txPerBlock: SAME_BLOCK_CONFIG.txPerBlock,
            targetDay: 2,
            targetBlock: 2,
            targetTxNr: SAME_BLOCK_CONFIG.targetTxNr,
            numDepositGroups: SAME_BLOCK_CONFIG.numDepositGroups,
            anchorTxNrInSameBlock: SAME_BLOCK_CONFIG.anchorTxNrInSameBlock
        };
    } else {
        // Default configuration
        config = {
            days: 3,
            blocksPerDay: 5,
            depositsPerBlock: 12,
            txPerBlock: 1,
            targetDay: 2,
            targetBlock: 2,
            targetTxNr: 0,
            numDepositGroups: 4
        };
    }

    if (crossblobMode) {
        console.error("CROSSBLOB MODE: Generating transaction spanning blob boundary");
        console.error(`  Deposits: ${config.depositsPerBlock} (${config.numDepositGroups} groups = ${config.numDepositGroups * 4} elements)`);
        console.error(`  Transactions: ${config.txPerBlock}`);
        console.error(`  Target TX: ${config.targetTxNr}`);
        const txMemAddr = config.numDepositGroups * 4 + config.targetTxNr * 15;
        console.error(`  TX Memory Address: ${txMemAddr} (needs 14 elements, spans to ${txMemAddr + 13})`);
        console.error(`  Elements in blob 1: ${4096 - txMemAddr}, Elements in blob 2: ${txMemAddr + 14 - 4096}`);
    }

    if (multiTxMode) {
        console.error("MULTI-TX MODE: Generating block with multiple transactions");
        console.error(`  Deposits: ${config.depositsPerBlock} (${config.numDepositGroups} groups)`);
        console.error(`  Transactions: ${config.txPerBlock}`);
        console.error(`  Target TX: ${config.targetTxNr} (challenging tx index ${config.targetTxNr})`);
    }

    if (depositAnchorMode) {
        console.error("DEPOSIT-ANCHOR MODE: Transaction references a deposit anchor");
        console.error(`  Deposits: ${config.depositsPerBlock} (${config.numDepositGroups} groups)`);
        console.error(`  Reference deposit group: ${config.anchorDepositGroup}`);
    }

    if (sameBlockMode) {
        console.error("SAME-BLOCK MODE: Transaction references anchor from same block");
        console.error(`  Transactions: ${config.txPerBlock}`);
        console.error(`  Target TX: ${config.targetTxNr}`);
        console.error(`  References TX: ${config.anchorTxNrInSameBlock} in same block`);
    }

    // Pre-compute zero hashes
    const blockZeroHashes = computeZeroHashes(BLOCK_DEPTH);
    const rootZeroHashes = computeZeroHashes(ROOT_DEPTH);

    // Compute genesis anchor (empty tree)
    const emptyBlockRoot = blockZeroHashes[BLOCK_DEPTH];
    const genesisAnchor = computeSparseRoot(emptyBlockRoot, 0, ROOT_DEPTH, rootZeroHashes);

    // Build blocks
    const blocks = [];
    let currentAnchor = genesisAnchor;

    // For eth-keyed transactions, we need an eth address
    // For zkSNARK-only, ethKey = 0
    const ethKey = unregisteredMode ? BigInt("0xDEADBEEFCAFEBABE") : BigInt(0);

    // Generate the transfer proof first so we know the anchor it uses
    const transferResult = await generateTransferProof(currentAnchor, ethKey, fraudMode);
    const zkAnchor = transferResult.anchor;

    // The transfer proof's anchor is based on its internal merkle tree
    // For the challenge to work, the transaction must reference a valid anchor from a prior block/update
    // We'll set up the anchor chain so that the referenced anchor matches

    // Simulate block progression
    for (let day = 0; day < config.days; day++) {
        for (let blockIdx = 0; blockIdx < config.blocksPerDay; blockIdx++) {
            const treeIndex = day * 8192 + blockIdx; // 2^13 = 8192 blocks per day

            // Simple anchor evolution for test
            const blockAnchor = poseidonHash([currentAnchor, BigInt(treeIndex + 1)]);

            blocks.push({
                day,
                blockIdx,
                treeIndex,
                numDeposits: config.depositsPerBlock,
                numTx: config.txPerBlock,
                finalAnchor: blockAnchor.toString()
            });

            currentAnchor = blockAnchor;
        }
    }

    // Target block info
    const targetBlockArrayIndex = config.targetDay * config.blocksPerDay + config.targetBlock;
    const targetBlock = blocks[targetBlockArrayIndex];
    const priorBlock = blocks[targetBlockArrayIndex - 1];

    // Determine anchor reference based on mode
    let anchorBlockNr, anchorUpdateNr, isDepositAnchor;

    if (sameBlockMode) {
        // Reference an earlier transaction in the SAME block
        // Solidity formula: deposits + anchorUpdateNr * 15 - 1
        // To reference tx N's OUTPUT, use anchorUpdateNr = N + 1
        anchorBlockNr = targetBlockArrayIndex; // Same block!
        anchorUpdateNr = config.anchorTxNrInSameBlock + 1; // Tx N's output uses updateNr = N + 1
        isDepositAnchor = false;
        console.error(`SAME-BLOCK: Tx ${config.targetTxNr} references tx ${config.anchorTxNrInSameBlock}'s output (anchorUpdateNr=${anchorUpdateNr}) in same block ${anchorBlockNr}`);
    } else if (depositAnchorMode) {
        // Reference a deposit anchor in the prior block
        // Solidity formula: anchorUpdateNr * 4 - 1
        // For deposit group N (0-indexed), use anchorUpdateNr = N + 1
        anchorBlockNr = targetBlockArrayIndex - 1;
        anchorUpdateNr = config.anchorDepositGroup + 1; // Group N uses updateNr = N + 1
        isDepositAnchor = true;
        console.error(`DEPOSIT-ANCHOR: Tx references deposit group ${config.anchorDepositGroup} (anchorUpdateNr=${anchorUpdateNr}) in block ${anchorBlockNr}`);
    } else if (crossblobMode) {
        // For cross-blob, reference tx 0's prior anchor (the last deposit anchor)
        // Position = deposits + 0 * 15 - 1 = 8 - 1 = 7 (but for 6 deposits, deposits = 8)
        // Actually for crossblob with 6 deposits: numDepositGroups = 2, deposits = 8
        // Position = 8 + 0 - 1 = 7 (last deposit anchor at position 7)
        anchorBlockNr = targetBlockArrayIndex - 1;
        anchorUpdateNr = 0; // Reference the anchor BEFORE tx 0 (last deposit anchor)
        isDepositAnchor = false;
        console.error(`CROSSBLOB: Referencing tx 0's prior anchor (anchorUpdateNr=${anchorUpdateNr})`);
    } else {
        // Default: reference the anchor before the first transaction (which is the last deposit anchor)
        // anchorUpdateNr = N means "reference the anchor BEFORE tx N"
        // Valid range: 0 <= anchorUpdateNr < numTransactions
        // For a block with 1 tx, only anchorUpdateNr = 0 is valid
        anchorBlockNr = targetBlockArrayIndex - 1;
        anchorUpdateNr = 0; // Reference the anchor before tx 0
        isDepositAnchor = false;
    }

    // For the ZK proof to verify, we need to ensure the anchor matches
    // In a real scenario, the ZK proof's anchor would be the merkle root of the note tree
    // For testing, we'll use the zkAnchor from the transfer proof
    const txAnchor = zkAnchor;

    // Build the blob data for the target block
    // Format: 4 elements per deposit group, then 15 elements per transaction
    // Deposit group: [update0, update1, update2, newAnchor]
    // Transaction: [pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1], txInfo, null0, null1, leaf0, leaf1, leaf2, (padding)]
    // Note: Contract expects 14 elements but we pad to 15 for alignment

    const blobData = [];

    // Add deposit group data
    let depositAnchor = BigInt(priorBlock.finalAnchor);
    for (let g = 0; g < config.numDepositGroups; g++) {
        const updates = [];
        for (let u = 0; u < 3; u++) {
            const depositId = BigInt(`${config.targetDay}${config.targetBlock}${g}${u}01`);
            updates.push(depositId.toString());
            blobData.push(depositId.toString());
        }
        // New anchor after this deposit group
        depositAnchor = poseidonHash([depositAnchor, ...updates.map(BigInt)]);
        blobData.push(depositAnchor.toString());
    }

    // Anchor after all deposits (before transactions)
    const anchorAfterDeposits = depositAnchor;

    // Extract ZK proof data
    const { proof, nullifiers, leavesOut } = transferResult;

    // Encode transaction info
    const txInfo = encodeTxInfo(anchorBlockNr, anchorUpdateNr, isDepositAnchor, ethKey);

    // Build transaction region (14 elements)
    const txRegion = [
        proof._pA[0],
        proof._pA[1],
        proof._pB[0][0],
        proof._pB[0][1],
        proof._pB[1][0],
        proof._pB[1][1],
        proof._pC[0],
        proof._pC[1],
        txInfo.toString(),
        nullifiers[0].toString(),
        nullifiers[1].toString(),
        leavesOut[0].toString(),
        leavesOut[1].toString(),
        leavesOut[2].toString()
    ];

    // In fraud mode, the blob will contain a different anchor than what the ZK proof uses
    const blobAnchor = fraudMode ? poseidonHash([zkAnchor, BigInt(1)]) : zkAnchor;
    const anchorToPlaceInBlob = fraudMode ? blobAnchor : txAnchor;

    // For modes with multiple transactions, add transactions before and after target
    if (crossblobMode || multiTxMode || sameBlockMode) {
        // Add transactions before the target transaction
        for (let t = 0; t < config.targetTxNr; t++) {
            // Add 14 elements of dummy data
            for (let i = 0; i < 14; i++) {
                blobData.push(BigInt(t * 100 + i).toString()); // Dummy values
            }

            // The 15th element is the new anchor after this transaction
            // For same-block mode, if this is the referenced transaction, place the anchor here
            if (sameBlockMode && t === config.anchorTxNrInSameBlock) {
                blobData.push(anchorToPlaceInBlob.toString());
                console.error(`SAME-BLOCK: Placed anchor at tx ${t}, position ${blobData.length - 1}`);
            } else {
                blobData.push(poseidonHash([anchorAfterDeposits, BigInt(t + 1)]).toString()); // Dummy anchor
            }
        }
    }

    // Add the target transaction data (14 elements)
    for (const elem of txRegion) {
        blobData.push(elem);
    }

    // Add anchor after target transaction (15th element)
    const targetTxAnchor = poseidonHash([anchorAfterDeposits, BigInt(config.targetTxNr + 1)]);
    blobData.push(targetTxAnchor.toString());

    // For modes with multiple transactions, add transactions after target
    if (crossblobMode || multiTxMode || sameBlockMode) {
        // Add dummy transactions after target tx to fill out the block
        for (let t = config.targetTxNr + 1; t < config.txPerBlock; t++) {
            for (let i = 0; i < 14; i++) {
                blobData.push(BigInt(t * 100 + i).toString());
            }
            blobData.push(poseidonHash([anchorAfterDeposits, BigInt(t + 1)]).toString()); // Dummy anchor
        }
    }

    // Calculate memory positions
    const depositsMemoryLength = config.numDepositGroups * 4;
    const txMemoryAddress = depositsMemoryLength + config.targetTxNr * 15;

    // For cross-blob mode, calculate region split
    let regionLength = 14;
    let extensionRegionLength = 0;
    let extensionRegionMemoryAddress = 0;
    let blob1Data = blobData;
    let blob2Data = [];

    if (crossblobMode && txMemoryAddress + 14 > 4096) {
        // Transaction spans blob boundary
        regionLength = 4096 - txMemoryAddress;
        extensionRegionLength = 14 - regionLength;
        extensionRegionMemoryAddress = 0; // Extension region starts at beginning of blob 2

        // Split blob data at position 4096
        blob1Data = blobData.slice(0, 4096);
        blob2Data = blobData.slice(4096);

        // Pad blob1Data to exactly 4096 elements if needed
        while (blob1Data.length < 4096) {
            blob1Data.push("0");
        }

        console.error(`Cross-blob split: region.length=${regionLength}, extensionRegion.length=${extensionRegionLength}`);
        console.error(`Blob 1 size: ${blob1Data.length}, Blob 2 size: ${blob2Data.length}`);
    }

    // Prepare KZG proof generation for TARGET block
    // For cross-blob, we need proofs from BOTH blobs
    let kzgBinaryPath, kzgIndices;
    let extensionKzgBinaryPath = null, extensionKzgIndices = null;

    if (crossblobMode && extensionRegionLength > 0) {
        // Generate KZG proofs for blob 1 (indices txMemoryAddress to 4095)
        kzgIndices = [];
        for (let i = 0; i < regionLength; i++) {
            kzgIndices.push(txMemoryAddress + i);
        }

        // Write blob 1 data to JSON file
        const blob1JsonPath = `/tmp/tx_challenge_blob1_${generateUUID().slice(0, 8)}.json`;
        const blob1JsonData = {
            blobData: blob1Data.map(d => "0x" + BigInt(d).toString(16).padStart(64, "0"))
        };
        fs.writeFileSync(blob1JsonPath, JSON.stringify(blob1JsonData));

        // Generate KZG proofs for blob 1
        const kzgCmd1 = `python3 ${path.join(__dirname, "generateKzgProof.py")} --json ${blob1JsonPath} ${kzgIndices.join(" ")}`;
        try {
            kzgBinaryPath = execSync(kzgCmd1, { encoding: "utf8", cwd: __dirname }).trim();
        } catch (err) {
            console.error("ERROR: KZG proof generation for blob 1 failed:", err.message);
            process.exit(1);
        }

        // Generate KZG proofs for blob 2 (indices 0 to extensionRegionLength-1)
        extensionKzgIndices = [];
        for (let i = 0; i < extensionRegionLength; i++) {
            extensionKzgIndices.push(i);
        }

        // Pad blob 2 data to 4096 elements
        while (blob2Data.length < 4096) {
            blob2Data.push("0");
        }

        // Write blob 2 data to JSON file
        const blob2JsonPath = `/tmp/tx_challenge_blob2_${generateUUID().slice(0, 8)}.json`;
        const blob2JsonData = {
            blobData: blob2Data.map(d => "0x" + BigInt(d).toString(16).padStart(64, "0"))
        };
        fs.writeFileSync(blob2JsonPath, JSON.stringify(blob2JsonData));

        // Generate KZG proofs for blob 2
        const kzgCmd2 = `python3 ${path.join(__dirname, "generateKzgProof.py")} --json ${blob2JsonPath} ${extensionKzgIndices.join(" ")}`;
        try {
            extensionKzgBinaryPath = execSync(kzgCmd2, { encoding: "utf8", cwd: __dirname }).trim();
        } catch (err) {
            console.error("ERROR: KZG proof generation for blob 2 failed:", err.message);
            process.exit(1);
        }

        console.error(`Generated KZG proofs for blob 1 (indices ${kzgIndices.join(", ")})`);
        console.error(`Generated KZG proofs for blob 2 (indices ${extensionKzgIndices.join(", ")})`);
    } else {
        // Single blob case
        kzgIndices = [];
        for (let i = 0; i < 14; i++) {
            kzgIndices.push(txMemoryAddress + i);
        }

        // Write blob data to JSON file for KZG proof generation
        const blobJsonPath = `/tmp/tx_challenge_blob_${generateUUID().slice(0, 8)}.json`;
        const blobJsonData = {
            blobData: blobData.map(d => "0x" + BigInt(d).toString(16).padStart(64, "0"))
        };
        fs.writeFileSync(blobJsonPath, JSON.stringify(blobJsonData));

        // Generate KZG proofs for target block
        const kzgCmd = `python3 ${path.join(__dirname, "generateKzgProof.py")} --json ${blobJsonPath} ${kzgIndices.join(" ")}`;
        try {
            kzgBinaryPath = execSync(kzgCmd, { encoding: "utf8", cwd: __dirname }).trim();
        } catch (err) {
            console.error("ERROR: KZG proof generation failed:", err.message);
            process.exit(1);
        }
    }

    // =========================================================
    // Generate KZG proofs for PRIOR ANCHOR block
    // The transaction references an anchor from a prior block
    // We need to generate blob data and KZG proofs for that anchor position
    // =========================================================

    // Build blob data for the prior anchor block
    // The prior anchor block has the same structure: 4 deposit groups + 1 transaction
    // The anchor that our transaction references should be at position:
    // - For isDeposit=true, updateNr=0: anchor is from previous block (no KZG needed)
    // - For isDeposit=false, updateNr=0: anchor is at depositsMemoryLength - 1 = 15 (last deposit group root)
    // - For isDeposit=false, updateNr=n: anchor is at depositsMemoryLength + n*15 - 1

    const priorBlobData = [];

    // For the prior anchor block, we need to place the ZK proof's anchor (txAnchor) at the correct position
    // Position depends on anchorUpdateNr and isDepositAnchor
    // Solidity formulas (from BlobData.priorRootMemoryLocation):
    //   Deposit anchors: position = anchorUpdateNr * 4 - 1
    //   Transaction anchors: position = depositsMemoryLength + anchorUpdateNr * 15 - 1
    // Note: For deposits, anchorUpdateNr is 1-indexed (group 0's anchor uses anchorUpdateNr=1)
    // For transactions, anchorUpdateNr=N gives the prior anchor for tx N (i.e., tx N-1's output)
    const priorAnchorMemoryPosition = isDepositAnchor
        ? (anchorUpdateNr * 4 - 1)  // deposit anchor: group 0 uses updateNr=1 -> pos 3
        : (depositsMemoryLength + anchorUpdateNr * 15 - 1);  // transaction anchor: updateNr=1 -> deposits + 14

    console.error(`Prior anchor memory position: ${priorAnchorMemoryPosition} (isDeposit=${isDepositAnchor}, updateNr=${anchorUpdateNr})`);

    // For same-block mode, the "prior anchor block" is actually the TARGET block
    // because we're referencing an earlier update within the same block
    const priorAnchorBlockIndex = sameBlockMode ? targetBlockArrayIndex : anchorBlockNr;

    // Build prior anchor block blob data
    // For same-block mode, the "prior anchor" is in the TARGET block's blob
    // For other modes, it's in a separate prior block's blob
    // Structure: deposit groups (numDepositGroups * 4 elements) + transactions (txPerBlock * 15 elements)
    const priorBlockBlobSize = depositsMemoryLength + config.txPerBlock * 15;

    // Get the anchor BEFORE the prior anchor block
    let priorBlockStartAnchor;
    if (sameBlockMode) {
        // For same-block mode, priorBlockStartAnchor is the anchor before the TARGET block
        priorBlockStartAnchor = BigInt(priorBlock.finalAnchor);
    } else if (anchorBlockNr > 0) {
        priorBlockStartAnchor = BigInt(blocks[anchorBlockNr - 1].finalAnchor);
    } else {
        priorBlockStartAnchor = genesisAnchor;
    }

    // Build deposit groups for prior anchor block
    // In fraud mode, we place blobAnchor (wrong anchor) instead of txAnchor
    // This simulates a sequencer that put the wrong anchor in the blob
    const anchorToPlaceInPriorBlob = fraudMode ? blobAnchor : txAnchor;
    let priorDepositAnchor = priorBlockStartAnchor;
    for (let g = 0; g < config.numDepositGroups; g++) {
        const updates = [];
        for (let u = 0; u < 3; u++) {
            // Generate unique deposit IDs for prior block
            const depositId = BigInt(`${anchorBlockNr}${g}${u}01`);
            updates.push(depositId.toString());
            priorBlobData.push(depositId.toString());
        }

        // Check if this deposit group's anchor is being referenced
        // anchorUpdateNr is 1-indexed: group N (0-indexed) uses anchorUpdateNr = N + 1
        // Special case: when anchorUpdateNr = 0 and !isDepositAnchor, the anchor is at the
        // last deposit position (the anchor BEFORE tx 0 = anchor AFTER all deposits)
        const isLastDepositGroup = g === config.numDepositGroups - 1;
        const placeAnchorHere = (isDepositAnchor && anchorUpdateNr === g + 1) ||
                                 (!isDepositAnchor && anchorUpdateNr === 0 && isLastDepositGroup);
        if (placeAnchorHere) {
            // Place the anchor here - in fraud mode this is blobAnchor (wrong), otherwise txAnchor (correct)
            priorBlobData.push(anchorToPlaceInPriorBlob.toString());
            priorDepositAnchor = anchorToPlaceInPriorBlob;
            console.error(`Placed anchor at deposit group ${g}, prior blob position ${priorBlobData.length - 1}`);
        } else {
            // Regular anchor evolution
            priorDepositAnchor = poseidonHash([priorDepositAnchor, ...updates.map(BigInt)]);
            priorBlobData.push(priorDepositAnchor.toString());
        }
    }

    // Add transaction data for prior block (15 elements per tx)
    // For transaction anchor references, place the anchor at the correct transaction position
    for (let t = 0; t < config.txPerBlock; t++) {
        // Fill with dummy transaction data
        for (let i = 0; i < 14; i++) {
            priorBlobData.push("0"); // dummy proof data
        }

        // The 15th element is the new root after this transaction
        // anchorUpdateNr is "1-indexed": tx N's output anchor uses anchorUpdateNr = N + 1
        // So we place the anchor after tx (anchorUpdateNr - 1)
        if (!isDepositAnchor && t + 1 === anchorUpdateNr) {
            // Place the anchor here - in fraud mode this is blobAnchor (wrong), otherwise txAnchor (correct)
            priorBlobData.push(anchorToPlaceInPriorBlob.toString());
            console.error(`Placed anchor at transaction ${t}'s output, prior blob position ${priorBlobData.length - 1}`);
        } else {
            // Dummy anchor for this transaction
            priorBlobData.push(poseidonHash([priorDepositAnchor, BigInt(t + 1)]).toString());
        }
    }

    // Ensure prior blob data is exactly 4096 elements (truncate or pad as needed)
    if (priorBlobData.length > 4096) {
        // Truncate to 4096 elements - but make sure we keep the anchor position!
        if (priorAnchorMemoryPosition >= 4096) {
            console.error(`ERROR: Prior anchor position ${priorAnchorMemoryPosition} is beyond blob boundary!`);
            process.exit(1);
        }
        priorBlobData.length = 4096;
    }
    while (priorBlobData.length < 4096) {
        priorBlobData.push("0");
    }

    // Generate KZG proof for the prior anchor position
    let priorKzgBinaryPath;
    let priorBlobForKzg;

    if (sameBlockMode) {
        // For same-block mode, the prior anchor is in the TARGET block's blob
        // Use the same blob data we already built (blob1Data or blobData)
        priorBlobForKzg = crossblobMode ? blob1Data : blobData;

        // Pad to 4096 if needed
        while (priorBlobForKzg.length < 4096) {
            priorBlobForKzg.push("0");
        }

        console.error(`SAME-BLOCK: Prior anchor KZG from target blob, position ${priorAnchorMemoryPosition}`);
        console.error(`SAME-BLOCK: Anchor value at position: ${priorBlobForKzg[priorAnchorMemoryPosition]}`);
    } else {
        // For non-same-block modes, use the separately built prior blob data
        priorBlobForKzg = priorBlobData;
    }

    // Write prior anchor blob data to JSON
    const priorBlobJsonPath = `/tmp/tx_challenge_prior_blob_${generateUUID().slice(0, 8)}.json`;
    const priorBlobJsonData = {
        blobData: priorBlobForKzg.map(d => "0x" + BigInt(d).toString(16).padStart(64, "0"))
    };
    fs.writeFileSync(priorBlobJsonPath, JSON.stringify(priorBlobJsonData));

    // Generate KZG proof for the prior anchor position
    const priorKzgCmd = `python3 ${path.join(__dirname, "generateKzgProof.py")} --json ${priorBlobJsonPath} ${priorAnchorMemoryPosition}`;
    try {
        priorKzgBinaryPath = execSync(priorKzgCmd, { encoding: "utf8", cwd: __dirname }).trim();
    } catch (err) {
        console.error("ERROR: Prior anchor KZG proof generation failed:", err.message);
        process.exit(1);
    }

    // Build output
    const output = {
        genesisAnchor: genesisAnchor.toString(),
        fraudMode,
        unregisteredMode,
        crossblobMode,
        multiTxMode,
        depositAnchorMode,
        sameBlockMode,
        config,
        blocks,
        targetBlock: {
            ...targetBlock,
            txRegion,
            blobData,
            // For cross-blob, include split blob data
            blob1Data: crossblobMode ? blob1Data : null,
            blob2Data: crossblobMode ? blob2Data : null
        },
        priorBlock,
        // Transaction challenge specific data
        targetTxNr: config.targetTxNr,
        anchorBlockNr,
        anchorUpdateNr,
        isDepositAnchor,
        txAnchor: txAnchor.toString(),
        blobAnchor: blobAnchor.toString(),
        ethKey: ethKey.toString(),
        // ZK proof data
        proof: transferResult.proof,
        publicSignals: transferResult.publicSignals,
        nullifiers: nullifiers.map(n => n.toString()),
        leavesOut: leavesOut.map(l => l.toString()),
        // Memory positions
        txMemoryAddress,
        depositsMemoryLength,
        // Region split info (for cross-blob)
        regionLength,
        extensionRegionLength,
        extensionRegionMemoryAddress,
        // KZG data for target block (blob 1)
        kzgProofBinaryPath: kzgBinaryPath,
        kzgIndices,
        // KZG data for extension region (blob 2) - only in cross-blob mode
        extensionKzgBinaryPath: extensionKzgBinaryPath,
        extensionKzgIndices: extensionKzgIndices,
        // KZG data for prior anchor block
        priorAnchorKzgBinaryPath: priorKzgBinaryPath,
        priorAnchorMemoryPosition,
        priorBlobData,
        // Anchor chain
        anchorBeforeTargetBlock: priorBlock.finalAnchor
    };

    // Write output to temp file
    let suffix = "";
    if (crossblobMode) suffix += "_crossblob";
    if (multiTxMode) suffix += "_multitx";
    if (depositAnchorMode) suffix += "_depositanchor";
    if (sameBlockMode) suffix += "_sameblock";
    if (fraudMode) suffix += "_fraud";
    if (unregisteredMode) suffix += "_unregistered";
    const outputPath = `/tmp/tx_challenge_test_data${suffix}_${generateUUID().slice(0, 8)}.json`;
    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));

    // Output just the path
    process.stdout.write(outputPath);
    process.exit(0);
}

main().catch(err => {
    console.error("ERROR:", err);
    process.exit(1);
});
