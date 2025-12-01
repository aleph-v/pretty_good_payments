pragma circom 2.1.5;

// Audited PSE Merkle Lib
include "binary-merkle-root.circom";
include "poseidon.circom";
include "bitify.circom";
include "comparators.circom";

// Note format:
// [asset id - 252 bit][amount - 180 bits][bliding factor - 252 bits][public key - 252 bits]
// Here we use preimages as keys: eg we enforce that public key = posiedon(private key)
// Blinding factor is dervived from hash(rand, hash(leaf0, leaf1))

// We provide two input paths, the second is optional. 
// We provide three output notes so you can send partial value and create a fee note.

template Transfer () {  

   // Declaration of signals.  
   signal input anchor;  
   signal input indices[2];
   signal input paths[2][40];
   signal input notesIn[2][4];
   signal input notesOut[3][4];
   signal input randoms[3];
   signal input privateKeys[2];

   signal output nullifiers[2];  
   signal output leavesOut[3]; 

   // Compute leaf hashes (note even if we do not use both leaves we require a hash preimage)
   // TODO - Use width 2 poseidon?
   var computedLeaf0 = Poseidon(4)(notesIn[0]);
   var computedLeaf1 = Poseidon(4)(notesIn[1]);

   // Compute the roots implied by the proofs and then get indicator vars for root equality.
   var root1 = BinaryMerkleRoot(40)(computedLeaf0, 40, indices[0], paths[0]);
   var root2 = BinaryMerkleRoot(40)(computedLeaf1, 40, indices[1], paths[1]);
   var root1_eq = IsEqual()([root1, anchor]);
   root1_eq === 1;
   var root2_eq = IsEqual()([root2, anchor]); 
   // we allow this to be not equal

   // Check proof of knoweldge of private keys
   // Domain Seperator = Keccak256(Pretty Good Transfer Protocol V1)
   var derivedPublicKey0 = Poseidon(2)([0x8c89ded3cb316b3e2163ee0f7a92095673c65827649008298772837236d62a6e, privateKeys[0]]);
   derivedPublicKey0 === notesIn[0][3];   
   var derivedPublicKey1 = Poseidon(2)([0x8c89ded3cb316b3e2163ee0f7a92095673c65827649008298772837236d62a6e, privateKeys[1]]);
   derivedPublicKey1 === notesIn[1][3];   

   // Compute the nullifiers which will be publicised
   nullifiers[0] <== Poseidon(2)([privateKeys[0], indices[0]]);
   // WARNING - You can make notes unspendable if you reuse a private key index key pair. You can also spoof nullifier outputs.
   //           ALWAYS use strongly random private keys, including for non included notes.
   nullifiers[1] <== Poseidon(2)([privateKeys[1], indices[1]]);

   // Enforce asset id equality in each note
   var assetID = notesIn[0][0];
   assetID === notesIn[1][0];
   assetID === notesOut[0][0];
   assetID === notesOut[1][0];
   assetID === notesOut[2][0];

   // Enforce that the input and output sums are the same
   notesIn[0][1] + root2_eq * notesIn[1][1] === notesOut[0][1] + notesOut[1][1] + notesOut[2][1];
   // Enforce that these are less than the max (to prevent overflowing)
   // Note - thes enforcement check inside of this ensures the representation is 180 bits
   var anon0[180] = Num2Bits(180)(notesOut[0][1]);
   var anon1[180] = Num2Bits(180)(notesOut[1][1]);
   var anon2[180] = Num2Bits(180)(notesOut[2][1]);
   
   // Enforce that the blinding factors are computed from the hashes of the input data.
   // This enables disclosable source data, can be used to do recusive proofs of innocence.
   // If the second leaf is not in the tree then this uses a zero value for the second entry.
   var hashLeavesIn = Poseidon(2)([computedLeaf0, computedLeaf1*root2_eq]);
   var blinding0 = Poseidon(2)([randoms[0], hashLeavesIn]);
   blinding0 === notesOut[0][2];
   var blinding1 = Poseidon(2)([randoms[1], hashLeavesIn]);
   blinding1 === notesOut[1][2];
   var blinding2 = Poseidon(2)([randoms[2], hashLeavesIn]);
   blinding2 === notesOut[2][2];

   // Enforce that the output leaves are the hashes of the validated data or
   // that they are zero if the net value change is zero
   // NOTE - We do this just to avoid growing the tree more than needed despite the fact it leaks some privacy.
   leavesOut[0] <== LeafOrZero()(notesOut[0]);
   leavesOut[1] <== LeafOrZero()(notesOut[1]);
   leavesOut[2] <== LeafOrZero()(notesOut[2]);
}

// Returns hash(leaf) if the value of the leaf is not zero or zero if the value is zero
template LeafOrZero() {
   signal input note[4];
   signal output leaf;

   // TODO - This code makes me feel pain
   var leafNotUsed = IsZero()(note[1]);
   var leafUsed = IsZero()(leafNotUsed);
   var computedLeafOut = Poseidon(4)(note);
   leaf <== computedLeafOut * leafUsed;
}


component main {public [anchor]} = Transfer();