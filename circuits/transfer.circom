pragma circom 2.1.5;

include "binary-merkle-root.circom";
include "poseidon.circom";
include "bitify.circom";
include "comparators.circom";

// Note format:
// [asset id - 252 bit][amount - 180 bits][blinding factor - 252 bits][public key - 252 bits]
// Here we use preimages as keys: eg we enforce that public key = poseidon(private key)
// Blinding factor is derived from hash(rand, hash(leaf0, leaf1))
// Nullifiers are derived as hash(privateKey, blindingFactor, index)
// Blinding factors are hash(random, hash(noteIn0, noteIn1)), this allows provable disclosure of sources 

// We provide two input paths, the second is optional. 
// We provide three output notes so you can send partial value and create a fee note.


// Withdraws:
// Withdraws are initiated by sending notes to a public key equal to zero, and then setting the blinding factor to
// an ethereum address. Ethereum owned accounts are forced to withdraw to the address which owns them, other withdraws
// may select any address (in fact may select any field and the value will be truncated on L1).
// Withdraws are not processed automatically, they must be claimed on the L1.

template Transfer () {  

   // Declaration of signals.  
   signal input anchor;  
   signal input indices[2];
   signal input paths[2][40];
   signal input notesIn[2][4];
   signal input notesOut[3][4];
   signal input randoms[3];
   signal input privateKeys[2];
   signal input ethKey;

   signal output nullifiers[2];  
   signal output leavesOut[3]; 

   // Compute leaf hashes (note even if we do not use both leaves we require a hash pre-image)
   var computedLeaf0 = Poseidon(4)(notesIn[0]);
   var computedLeaf1 = Poseidon(4)(notesIn[1]);

   // Compute the roots implied by the proofs and then get indicator vars for root equality.
   var root1 = BinaryMerkleRoot(40)(computedLeaf0, 40, indices[0], paths[0]);
   var root2 = BinaryMerkleRoot(40)(computedLeaf1, 40, indices[1], paths[1]);
   var root1_eq = IsEqual()([root1, anchor]);
   root1_eq === 1;
   var root2_eq = IsEqual()([root2, anchor]);
   var root2_notEq = IsZero()(root2_eq);
   // we allow this to be not equal

   // If we are not using the second entry we force its key to be a random constant to prevent use of nullifiers to block eth
   // transfers.
   // WARNING - If you do not use a random for the blinding factor in the fake note you will leak data about your note
   //           inputs.
   // TODO - Maybe pick another random constant?
   ForceEqualIfEnabled()(root2_notEq, [privateKeys[1], 0x4cc1de474cacd406eea434351d2907cfea08fece7e38ebebff463599ffa252a7]);

   // Check proof of knowledge of private keys
   // Domain Separator = Keccak256(Pretty Good Transfer Protocol V1)
   var derivedPublicKey0 = Poseidon(2)([0x8c89ded3cb316b3e2163ee0f7a92095673c65827649008298772837236d62a6e, privateKeys[0]]);
   derivedPublicKey0 === notesIn[0][3];
   var derivedPublicKey1 = Poseidon(2)([0x8c89ded3cb316b3e2163ee0f7a92095673c65827649008298772837236d62a6e, privateKeys[1]]);
   derivedPublicKey1 === notesIn[1][3];

   // Compute the nullifiers which will be publicized, note that we need to add the semi random (hash derived) blinding factor
   // because eth keys are not random
   nullifiers[0] <== Poseidon(3)([privateKeys[0], notesIn[0][2], indices[0]]);
   nullifiers[1] <== Poseidon(3)([privateKeys[1], notesIn[1][2], indices[1]]);

   // Now we check if the accounts are eth keyed and if they are we force the public input to be the eth address
   // which will force the verifier contract to ask the eth address for approval for transfer
   var isEthKey = IsEthKeyed()(privateKeys[0]);
   var secondNoteIsEthKey = IsEthKeyed()(privateKeys[1]);
   // If the first note is an eth key force both keys to be equal, however we turn off this check if the
   // second key is not included in the tree as it is a constant. (in this case root2_eq is 0)
   ForceEqualIfEnabled()(isEthKey, [privateKeys[0]*root2_eq, privateKeys[1]*root2_eq]);
   // Checks if all of the output note public keys are equal to zero, if so we don't have to publicize the ethKey
   // Note that this line also enforces that the eth key is zero in this case
   // TODO - We want that this is NOT a total withdraw to enforce it
   var isTotalWithdraw = MultiEqual(4)([0, notesOut[0][3], notesOut[1][3], notesOut[2][3]]);
   var isNotTotalWithdraw = IsZero()(isTotalWithdraw);
   // We want to enable keyless note consolidation for ethereum owned accounts so we create this indicator var
   // which will be 0 if not all of the enabled notes are equal and 1 if they are (enabled notes can exclude the second note in)
   var isSameKeyTransaction4 = MultiEqual(4)([notesIn[0][3], notesOut[0][3], notesOut[1][3], notesOut[2][3]]);
   var isSameKeyTransaction5 = MultiEqual(5)([notesIn[0][3], notesIn[1][3], notesOut[0][3], notesOut[1][3], notesOut[2][3]]);
   // Two cases pass: All keys are equal except the second input note, and the second note is not used or all leaves are equal
   // In the first case both is isSameKeyTransaction4 and root2_notEq are 1 and isSameKeyTransaction5 is 0 (except in the deep edge case
   // where someone is trying to use the preset priv key which we do not allow). In the second isSameKeyTransaction4 is 1 and root2_notEq = 0
   // and isSameKeyTransaction5 = 1. If any of the keys except the second mismatch both isSameKeyTransactions will be 0, if all match except
   // the second isSameKeyTransaction5 will be 0 and if this key is included root2_notEq = 0.
   var isSameKeyTransaction = isSameKeyTransaction4*root2_notEq + isSameKeyTransaction5;
   var isNotSameKeyTransaction = IsEqual()([isSameKeyTransaction, 1]);

   ForceEqualIfEnabled()(isEthKey*isNotSameKeyTransaction, [privateKeys[0]*isNotTotalWithdraw, ethKey]);
   // If the first key is not an eth address the second must not be
   var notEthKeyed = IsZero()(isEthKey);
   ForceEqualIfEnabled()(notEthKeyed, [secondNoteIsEthKey, 0]);

   // Enforce asset id equality in each note
   var noteAssetsEqual = MultiEqual(5)([notesIn[0][0], notesIn[1][0], notesOut[0][0], notesOut[1][0], notesOut[2][0]]);
   noteAssetsEqual === 1;

   // Enforce that the input and output sums are the same
   notesIn[0][1] + root2_eq * notesIn[1][1] === notesOut[0][1] + notesOut[1][1] + notesOut[2][1];
   // Enforce that these are less than the max (to prevent overflowing)
   // Note - the enforcement check inside of this ensures the representation is 180 bits
   var anon0[180] = Num2Bits(180)(notesOut[0][1]);
   var anon1[180] = Num2Bits(180)(notesOut[1][1]);
   var anon2[180] = Num2Bits(180)(notesOut[2][1]);
   
   // Enforce that the blinding factors are computed from the hashes of the input data.
   // This enables disclosure of source data, can be used to do recursive proofs of innocence/privacy pools.
   // If the second leaf is not in the tree then this uses a zero value for the second entry.
   // However if we are doing a withdraw (done by sending a note to an output public key zero) then we override
   // this system and send to the withdraw address
   var hashLeavesIn = Poseidon(2)([computedLeaf0, computedLeaf1*root2_eq]);
   BlindingFactorEnforcement()(notesOut[0], randoms[0], hashLeavesIn, isEthKey, privateKeys[0]);
   BlindingFactorEnforcement()(notesOut[1], randoms[1], hashLeavesIn, isEthKey, privateKeys[0]);
   BlindingFactorEnforcement()(notesOut[2], randoms[2], hashLeavesIn, isEthKey, privateKeys[0]);

   // Enforce that the output leaves are the hashes of the validated data or that they are zero if the net value change is zero
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

template IsEthKeyed() {
   signal input key;
   signal output isEthKeyed;

   var binary[254] = Num2Bits(254)(key);
   var bitsum = 0;
   for(var i = 0; i < 94; i++) {
      bitsum += binary[160 + i];
   }
   isEthKeyed <== IsZero()(bitsum);
}

// Enforce that the blinding factors are computed from the hashes of the input data.
// This enables disclosure of source data, can be used to do recursive proofs of innocence/privacy pools.
// If the second leaf is not in the tree then this uses a zero value for the second entry.
// However if we are doing a withdraw (done by sending a note to an output public key zero) then we override
// this system and send to the withdraw address

template BlindingFactorEnforcement() {
   signal input note[4];
   signal input random;
   signal input leavesInHash;
   signal input isEthKeyed;
   signal input ethKey;

   var blinding = Poseidon(2)([random, leavesInHash]);
   var isWithdraw = IsZero()(note[3]);
   var isNotWithdraw = IsZero()(isWithdraw);
   ForceEqualIfEnabled()(isNotWithdraw, [blinding, note[2]]);
   ForceEqualIfEnabled()(isEthKeyed*isWithdraw, [ethKey, note[2]]);
}

template MultiEqual(n) {
   signal input equalFields[n];
   signal output allEqual;

   var sum = 0;
   for(var i = 1; i < n; i++) {
      var nth = IsEqual()([equalFields[0], equalFields[i]]);
      sum += nth;
   }
   allEqual <== IsEqual()([sum, n-1]);
}

component main {public [anchor, ethKey]} = Transfer();