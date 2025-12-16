// Audited PSE Merkle Lib
include "binary-merkle-root.circom";
include "poseidon.circom";
include "bitify.circom";
include "comparators.circom";

// Doing the poseidon tree update onchain would cost around over 200 poseidon hashes and therefore cost 4 million gas
// therefore we do a small zk compression of the proof.
// NOTE - need to check that the 

template PredictableUpdate () { 

    signal input anchorBefore;
    signal input blockRootBefore;
    signal input updates[3];
    signal input blockIndex;
    signal input inBlockIndex;
    signal input nonzeroField;
    // The block can hold up to 1026 transactions so we need 4096 fields.
    // We do up to 2^13 blocks per "day" and have 2^15 days in total as has been foretold.
    signal input blockProofs[4][12];
    signal input rootPath[28];
    signal output anchorAfter;

    // First, we need to enforce that the index - 1 in the block is nonzero
    // or that index == 0
    var isIndexZero = IsZero()(inBlockIndex);
    var isIndexNonZero = IsZero()(isIndexZero);
    var isElementNonzero = IsZero()(IsZero()(nonzeroField));
    // Computes the root at index - 1 for "nonzeroElement", or if index zero opens zero
    var computedRoot = BinaryMerkleRoot(12)(nonzeroField, 12, inBlockIndex - isIndexNonZero, blockProofs[0]);
    var isRootEqual = IsEqual()([computedRoot, blockRootBefore]);
    // Enforces root equal and the field at index-1 is not zero
    // If the index is equal to zero, then isElementNonzero will be 0 (as no nonzero elemnts are in the tree)
    // and isIndexZero will be 1. Otherwise isIndexZero is 0 and both isRootEqual and isElementNonzero must be 1 to pass.
    1 === isRootEqual*isElementNonzero + isIndexZero;

    // Now we open first the index, which must have a zero field
    computedRoot = BinaryMerkleRoot(12)(0, 12, inBlockIndex, blockProofs[1]);
    isRootEqual = IsEqual()([computedRoot, blockRootBefore]);
    // We must have that we open the index it has a zero leaf
    1 === isRootEqual;
    computedRoot = BinaryMerkleRoot(12)(updates[0], 12, inBlockIndex, blockProofs[1]);

    // Now we do the next update by increasing the index, enforcing its zero, and changing it
    var intermediateRoot = BinaryMerkleRoot(12)(0, 12, inBlockIndex + 1, blockProofs[2]);
    isRootEqual = IsEqual()([computedRoot, intermediateRoot]);
    1 === isRootEqual;
    computedRoot = BinaryMerkleRoot(12)(updates[1], 12, inBlockIndex, blockProofs[2]);

    // Now we do the next update by increasing the index, enforcing its zero, and changing it
    intermediateRoot = BinaryMerkleRoot(12)(0, 12, inBlockIndex + 2, blockProofs[3]);
    isRootEqual = IsEqual()([computedRoot, intermediateRoot]);
    1 === isRootEqual;
    var blockRootAfter = BinaryMerkleRoot(12)(updates[2], 12, inBlockIndex, blockProofs[3]);

    // Finally we must prove that the block root itself we do this by proving the blockRoot 
    var computedAnchor = BinaryMerkleRoot(28)(blockRootBefore, 28, blockIndex, rootPath);
    isRootEqual = IsEqual()([computedAnchor, anchorBefore]);
    1 === isRootEqual;
    anchorAfter <== BinaryMerkleRoot(28)(blockRootAfter, 28, blockIndex, rootPath);
}

component main {public [anchorBefore, blockIndex, updates]} = PredictableUpdate();