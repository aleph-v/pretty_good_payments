//! Test vectors from Solidity/circomlibjs for verifying Rust implementation compatibility.
//!
//! These test vectors were generated using the circomlibjs library to ensure
//! our Poseidon implementation matches the one used in the circuits.

#[cfg(test)]
mod tests {
    use crate::poseidon::{compute_leaf_hash, compute_nullifier, poseidon2, poseidon3, poseidon4};
    use crate::tree::{compute_zero_hashes, IncrementalMerkleTree};
    use alloy_primitives::{Address, B256, U256};

    /// Helper to convert hex string to B256
    fn hex_to_b256(hex: &str) -> B256 {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex).expect("Invalid hex");
        B256::from_slice(&bytes)
    }

    // ========================================================================
    // POSEIDON-2 TEST VECTORS (from circomlibjs)
    // ========================================================================

    #[test]
    fn test_poseidon2_zeros_matches_circomlib() {
        // poseidon2(0, 0) = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864
        let result = poseidon2(B256::ZERO, B256::ZERO);
        let expected =
            hex_to_b256("0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864");
        assert_eq!(
            result, expected,
            "poseidon2(0, 0) mismatch with circomlibjs"
        );
    }

    #[test]
    fn test_poseidon2_simple_inputs_matches_circomlib() {
        // poseidon2(1, 2) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        let a = B256::from(U256::from(1));
        let b = B256::from(U256::from(2));
        let result = poseidon2(a, b);
        let expected =
            hex_to_b256("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
        assert_eq!(
            result, expected,
            "poseidon2(1, 2) mismatch with circomlibjs"
        );
    }

    #[test]
    fn test_poseidon2_order_matters() {
        // poseidon2(2, 1) = 0x1576c555b70c9b778666e91d600fdc6d73f30aeed2f6adc5360d6a052259775a
        let a = B256::from(U256::from(2));
        let b = B256::from(U256::from(1));
        let result = poseidon2(a, b);
        let expected =
            hex_to_b256("0x1576c555b70c9b778666e91d600fdc6d73f30aeed2f6adc5360d6a052259775a");
        assert_eq!(
            result, expected,
            "poseidon2(2, 1) mismatch with circomlibjs"
        );

        // Verify order matters
        let result_12 = poseidon2(B256::from(U256::from(1)), B256::from(U256::from(2)));
        assert_ne!(result, result_12, "poseidon2 should be order-dependent");
    }

    // ========================================================================
    // POSEIDON-3 TEST VECTORS (from circomlibjs)
    // ========================================================================

    #[test]
    fn test_poseidon3_simple_inputs_matches_circomlib() {
        // poseidon3(1, 2, 3) = 0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732
        let a = B256::from(U256::from(1));
        let b = B256::from(U256::from(2));
        let c = B256::from(U256::from(3));
        let result = poseidon3(a, b, c);
        let expected =
            hex_to_b256("0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732");
        assert_eq!(
            result, expected,
            "poseidon3(1, 2, 3) mismatch with circomlibjs"
        );
    }

    // ========================================================================
    // POSEIDON-4 TEST VECTORS (from circomlibjs)
    // ========================================================================

    #[test]
    fn test_poseidon4_simple_inputs_matches_circomlib() {
        // poseidon4(1, 100, 123, 456) = 0x1a391a79101efe9535c36366cdc5df7569db136ab576ad6ee4d3b0979efa1980
        let a = B256::from(U256::from(1));
        let b = B256::from(U256::from(100));
        let c = B256::from(U256::from(123));
        let d = B256::from(U256::from(456));
        let result = poseidon4(a, b, c, d);
        let expected =
            hex_to_b256("0x1a391a79101efe9535c36366cdc5df7569db136ab576ad6ee4d3b0979efa1980");
        assert_eq!(
            result, expected,
            "poseidon4(1, 100, 123, 456) mismatch with circomlibjs"
        );
    }

    // ========================================================================
    // ZERO HASHES TEST VECTORS (computed from poseidon2)
    // ========================================================================

    #[test]
    fn test_zero_hashes_match_circomlib() {
        // These are the expected zero hashes computed iteratively:
        // zero_hashes[0] = 0
        // zero_hashes[i] = poseidon2(zero_hashes[i-1], zero_hashes[i-1])
        let expected_zero_hashes = [
            "0x0000000000000000000000000000000000000000000000000000000000000000", // level 0
            "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", // level 1
            "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1", // level 2
            "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238", // level 3
            "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a", // level 4
        ];

        let zero_hashes = compute_zero_hashes(4);

        for (i, expected_hex) in expected_zero_hashes.iter().enumerate() {
            let expected = hex_to_b256(expected_hex);
            assert_eq!(
                zero_hashes[i], expected,
                "zero_hashes[{i}] mismatch with circomlibjs"
            );
        }
    }

    #[test]
    fn test_empty_tree_root_matches_expected() {
        // An empty tree of depth 4 should have root = zero_hashes[4]
        let tree = IncrementalMerkleTree::new(4);
        let expected_root =
            hex_to_b256("0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a");
        assert_eq!(tree.root(), expected_root, "Empty tree root mismatch");
    }

    // ========================================================================
    // MERKLE TREE INSERTION AND PROOF TESTS
    // ========================================================================

    #[test]
    fn test_merkle_tree_single_insertion_root() {
        // Insert leaf with value 1 at index 0 in a depth-4 tree
        // The root should be computed as:
        // level 0: leaf=1 at 0, sibling=0 (zero_hash[0])
        // level 1: parent = poseidon2(1, 0) at 0, sibling = zero_hash[1]
        // level 2: parent = poseidon2(prev, zero_hash[1]) at 0, sibling = zero_hash[2]
        // level 3: parent = poseidon2(prev, zero_hash[2]) at 0, sibling = zero_hash[3]
        // level 4 (root): poseidon2(prev, zero_hash[3])

        let mut tree = IncrementalMerkleTree::new(4);
        let leaf = B256::from(U256::from(1));
        tree.insert(leaf).unwrap();

        // Compute expected root step by step
        let zh = compute_zero_hashes(4);
        let l1 = poseidon2(leaf, zh[0]); // poseidon2(1, 0)
        let l2 = poseidon2(l1, zh[1]); // poseidon2(l1, zero_hash[1])
        let l3 = poseidon2(l2, zh[2]); // poseidon2(l2, zero_hash[2])
        let expected_root = poseidon2(l3, zh[3]); // poseidon2(l3, zero_hash[3])

        assert_eq!(tree.root(), expected_root, "Single insertion root mismatch");
    }

    #[test]
    fn test_merkle_tree_multiple_insertions_match_circomlib() {
        // Test vectors computed using circomlibjs poseidon
        // Tree depth: 4 (16 leaves max)
        // Inserting leaves: 100, 200, 300, 400, 500, 600, 700, 800

        let mut tree = IncrementalMerkleTree::new(4);

        // (leaf_value, expected_root_after_insertion) - from circomlibjs
        let test_cases: [(u64, &str); 8] = [
            (
                100,
                "0x2fda6ad0e7f8fb38908e0838a590a8f188492133009bcc2e65880354be696a79",
            ),
            (
                200,
                "0x2cbf11045c42a2fd38beeba92cebf808ba56756b2075c83ac609f9854e11319e",
            ),
            (
                300,
                "0x15ef981644400655f912b82897d7fe9d79b12032bfef408d33be1522251d0319",
            ),
            (
                400,
                "0x1414816579f3f4e37417f26d9d494ae943e044b540b54c6f5aa9f24a92163482",
            ),
            (
                500,
                "0x04f809d04c7c70b00c8aafc136898577bd09e6f5d648b0ad8681b2c78c51ed2b",
            ),
            (
                600,
                "0x2350a76d2ecf427e8e7dd0ab389fbb8e75a1908a10786262d29361e708b80847",
            ),
            (
                700,
                "0x1b190efe1770946e5e0aa81fee80d8267bf11b9a727335aa7498638f1b691e82",
            ),
            (
                800,
                "0x173bd2a3df4aa425f88088c8159af9a89e32091cbb6bd4b1e17cc2b47e97f04f",
            ),
        ];

        for (i, (leaf_val, expected_root_hex)) in test_cases.iter().enumerate() {
            let leaf = B256::from(U256::from(*leaf_val));
            tree.insert(leaf).unwrap();

            let expected_root = hex_to_b256(expected_root_hex);
            assert_eq!(
                tree.root(),
                expected_root,
                "Root mismatch after inserting leaf {i} (value={leaf_val})"
            );
        }

        // Verify tree size
        assert_eq!(tree.size(), 8);

        // Verify all proofs work
        for (i, (leaf_val, _)) in test_cases.iter().enumerate() {
            let leaf = B256::from(U256::from(*leaf_val));
            let proof = tree.get_proof(i).unwrap();
            assert!(
                tree.verify_proof(leaf, &proof),
                "Proof verification failed for leaf at index {i} (value={leaf_val})"
            );
        }
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let mut tree = IncrementalMerkleTree::new(4);

        // Insert a few leaves
        let leaves = [
            B256::from(U256::from(100)),
            B256::from(U256::from(200)),
            B256::from(U256::from(300)),
        ];

        for leaf in &leaves {
            tree.insert(*leaf).unwrap();
        }

        // Verify proofs for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.get_proof(i).unwrap();
            assert!(
                tree.verify_proof(*leaf, &proof),
                "Proof verification failed for leaf {i}"
            );

            // Verify proof computes correct root
            let computed_root = proof.compute_root(*leaf);
            assert_eq!(
                computed_root,
                tree.root(),
                "Proof computed root mismatch for leaf {i}"
            );
        }
    }

    // ========================================================================
    // LEAF HASH TEST (matching Solidity leafHash computation)
    // ========================================================================

    #[test]
    fn test_leaf_hash_with_simple_values() {
        // Test leaf hash computation matching PredictableMerkleLib.leafHash
        // leafHash = Poseidon4(uint256(uint160(asset)), amount, blinding, publicKey)

        // Simple test case with small values
        let asset = Address::ZERO; // 0x0000...0000
        let amount = U256::from(100);
        let blinding = B256::from(U256::from(123));
        let public_key = B256::from(U256::from(456));

        let result = compute_leaf_hash(asset, amount, blinding, public_key);

        // Expected: poseidon4(0, 100, 123, 456)
        // = 0x0090ffb6e10f141acb9fa189ed9b9b6d4246d6e149bdf20e344002168b0d7d21
        let expected =
            hex_to_b256("0x0090ffb6e10f141acb9fa189ed9b9b6d4246d6e149bdf20e344002168b0d7d21");
        assert_eq!(result, expected, "Leaf hash mismatch with expected");
    }

    #[test]
    fn test_leaf_hash_nonzero_asset() {
        // Test with a non-zero asset address
        // Asset addresses are right-aligned (low 160 bits) in the field
        let asset = Address::repeat_byte(0x01); // 0x0101...0101
        let amount = U256::from(1000);
        let blinding = B256::from(U256::from(1));
        let public_key = B256::from(U256::from(2));

        let result = compute_leaf_hash(asset, amount, blinding, public_key);

        // Result should be non-zero and deterministic
        assert_ne!(result, B256::ZERO);

        // Same inputs should give same result
        let result2 = compute_leaf_hash(asset, amount, blinding, public_key);
        assert_eq!(result, result2);
    }

    // ========================================================================
    // NULLIFIER COMPUTATION TEST
    // ========================================================================

    #[test]
    fn test_nullifier_with_simple_values() {
        // nullifier = Poseidon3(privateKey, blinding, index)
        let private_key = B256::from(U256::from(1));
        let blinding = B256::from(U256::from(2));
        let index = 3u64;

        let result = compute_nullifier(private_key, blinding, index);

        // Expected: poseidon3(1, 2, 3)
        // = 0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732
        let expected =
            hex_to_b256("0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732");
        assert_eq!(result, expected, "Nullifier mismatch with expected");
    }

    #[test]
    fn test_nullifier_different_indices_produce_different_results() {
        let private_key = B256::from(U256::from(1));
        let blinding = B256::from(U256::from(2));

        let null_3 = compute_nullifier(private_key, blinding, 3);
        let null_4 = compute_nullifier(private_key, blinding, 4);
        let null_100 = compute_nullifier(private_key, blinding, 100);

        assert_ne!(null_3, null_4);
        assert_ne!(null_3, null_100);
        assert_ne!(null_4, null_100);
    }

    // ========================================================================
    // BLOB MEMORY LAYOUT TESTS (matching BlobData.sol)
    // ========================================================================

    // These are tested in common/src/blob.rs but we verify key formulas here

    #[test]
    fn test_deposits_memory_length_formula() {
        // Formula: ceil(numDeposits / 3) * 4
        fn deposits_memory_length(num_deposits: usize) -> usize {
            num_deposits.div_ceil(3) * 4
        }

        assert_eq!(deposits_memory_length(0), 0);
        assert_eq!(deposits_memory_length(1), 4);
        assert_eq!(deposits_memory_length(2), 4);
        assert_eq!(deposits_memory_length(3), 4);
        assert_eq!(deposits_memory_length(4), 8);
        assert_eq!(deposits_memory_length(5), 8);
        assert_eq!(deposits_memory_length(6), 8);
        assert_eq!(deposits_memory_length(7), 12);
        assert_eq!(deposits_memory_length(30), 40);
        assert_eq!(deposits_memory_length(99), 132);
        assert_eq!(deposits_memory_length(100), 136);
    }

    #[test]
    fn test_deposit_leaf_address_formula() {
        // Formula: number + floor(number / 3)
        fn deposit_leaf_address(number: usize) -> usize {
            number + (number / 3)
        }

        assert_eq!(deposit_leaf_address(0), 0);
        assert_eq!(deposit_leaf_address(1), 1);
        assert_eq!(deposit_leaf_address(2), 2);
        assert_eq!(deposit_leaf_address(3), 4); // skips root at 3
        assert_eq!(deposit_leaf_address(4), 5);
        assert_eq!(deposit_leaf_address(5), 6);
        assert_eq!(deposit_leaf_address(6), 8); // skips root at 7
    }

    #[test]
    fn test_tx_leaf_address_formula() {
        // Formula: depositsLength + (number * TX_SIZE) + 11 + which
        // TX_SIZE = 15 (8 proof + 1 anchor + 2 nullifiers + 3 leaves + 1 root)
        const TX_SIZE: usize = 15;

        fn tx_leaf_address(deposits_length: usize, tx_number: usize, which: usize) -> usize {
            deposits_length + (tx_number * TX_SIZE) + 11 + which
        }

        // With 3 deposits (depositsLength = 4)
        let dl = 4;
        assert_eq!(tx_leaf_address(dl, 0, 0), 15);
        assert_eq!(tx_leaf_address(dl, 0, 1), 16);
        assert_eq!(tx_leaf_address(dl, 0, 2), 17);
        assert_eq!(tx_leaf_address(dl, 1, 0), 30);
        assert_eq!(tx_leaf_address(dl, 1, 1), 31);
        assert_eq!(tx_leaf_address(dl, 1, 2), 32);
    }

    #[test]
    fn test_nullifier_address_formula() {
        // Formula: depositsLength + (txNumber * TX_SIZE) + 9 + which
        const TX_SIZE: usize = 15;

        fn nullifier_address(deposits_length: usize, tx_number: usize, which: usize) -> usize {
            deposits_length + (tx_number * TX_SIZE) + 9 + which
        }

        // With 3 deposits (depositsLength = 4)
        let dl = 4;
        assert_eq!(nullifier_address(dl, 0, 0), 13);
        assert_eq!(nullifier_address(dl, 0, 1), 14);
        assert_eq!(nullifier_address(dl, 1, 0), 28);
        assert_eq!(nullifier_address(dl, 1, 1), 29);
    }
}
