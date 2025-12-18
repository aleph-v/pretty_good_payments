// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {LibBit} from "solady/utils/LibBit.sol";
import {console} from "forge-std/console.sol"; 

// We implement a protocol which does kzg opening against blob commitments.
// In the simplest version it just proves that the commitment evaluated at the bit revevered root of unity
// for an index is equal to the the claimed data.
// We might be able to highly optimise by doing a multi point opening.


// Blobs are structured as follows: 
// [deposits range][transactions range]
// each desposit is [leaf1, leaf2, leaf3, new_root] and each leaf must match the deposit leaf in the array for this block
// each transaction is [[zk proof], anchor id, nullifier0, nullifier1, leaf0, leaf1, leaf2, new_root]
// The transaction is expected to be 15, 32 byte commitment leaves. 8 leaves for the zk proof, then 7 with 6 for inputs and 1 for new root.

// Has to be a contract because libs can't do immutables
contract BlobData {

    uint256 constant BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513;
    uint256 immutable ROOT = exp(7, (BLS_MODULUS - 1) / 4096);

    // Next we want some functions related to the actual blob layout

    function txStartIndex(uint256 txNumber, uint256 numDeposits) internal pure returns(uint256) {
        uint256 deposits = numDeposits*4;
        uint256 prior = (txNumber - 1)*15;
        // TODO - Might be 0 indexed?
        return (deposits + prior);
    }

    function leafIndex(uint256 number, uint256 numDeposits, bool isDeposit, uint256 which) internal pure returns(uint256) {
        assert(which < 3);
        if (isDeposit) {
            assert(number < numDeposits);
            uint256 prior = (number -1) * 4;
            return (prior + which);
        } else {
            uint256 deposits = numDeposits*4;
            uint256 prior = (number -1) * 15;
            // 4 entries per deposit, 15 per prior tx, 11 (8 zk, 1 root, 2 nullifiers)
            return (deposits + prior + 11 + which);
        }
    }

    function nullifierIndex(uint256 txNumber, uint256 numDeposits, uint256 which) internal pure returns(uint256) {
        uint256 deposits = numDeposits*4;
        uint256 prior = (txNumber -1) * 15;
        assert(which < 2);
        // 4 entries per deposit, 15 per prior tx, 11 (8 zk, 1 root, 2 nullifiers)
        return (deposits + prior + 9 + which);
    }

    function rootIndex(uint256 number, bool isDeposit, uint256 numDeposits) internal pure returns(uint256) {
        if (isDeposit) {
            assert(number < numDeposits);
            return (number*4 -1);
        } else {
            uint256 deposits = numDeposits*4;
            return(deposits + number*15 - 1);
        }
    }

    /// @dev Checks that the kzg proof validates that the polynomial interpolates data at the roots of unity indexed by the bitreversed
    ///      roots of unity
    function validateDataOpening(
        bytes32 rootHash,
        bytes calldata commitment,
        uint256[] memory dataIndicies,
        bytes32[] memory data,
        bytes[] calldata kzgProofs
    ) internal view {
        // TODO we could optimize the memory use here by overwriting the last one in assembly
        for (uint256 i = 0; i < dataIndicies.length; i++) {
            validateSingle(rootHash, commitment, dataIndicies[i], data[i], kzgProofs[i]);
        }
    }

    function validateSingle(
        bytes32 rootHash,
        bytes calldata commitment,
        uint256 index,
        bytes32 data,
        bytes calldata proof
    ) internal view {
        // To do a single validation we use the point open precompile and prove that the polynomial at 
        // the bit reversed root of unity for that index is equal to the data field
        uint256 evalRoot = bitReversedRoot(index);

        assembly {
            let ptr := mload(0x40)
            // Load the inputs for the point evaluation precompile into memory. The inputs to the point evaluation
            // precompile are packed, and not supposed to be ABI-encoded.
            mstore(ptr, rootHash)
            mstore(add(ptr, 0x20), evalRoot)
            mstore(add(ptr, 0x40), data)
            calldatacopy(add(ptr, 0x60), commitment.offset, 0x30)
            calldatacopy(add(ptr, 0x90), proof.offset, 0x30)

            // Verify the KZG proof by calling the point evaluation precompile. If the proof is invalid, the precompile
            // will revert.
            let success :=
                staticcall(
                    gas(), // forward all gas
                    0x0A, // point evaluation precompile address
                    ptr, // input ptr
                    0xC0, // input size = 192 bytes
                    0x00, // output ptr
                    0x40 // output size
                )
            if iszero(success) {
                // Store the "InvalidProof()" error selector.
                mstore(0x00, 0x09bde339)
                // revert with "InvalidProof()"
                revert(0x1C, 0x04)
            }
        }
    }

    // Computes the bit reverse of i as if it is a 12 bit number (ie less than 4096)
    function bitReversedRoot(uint256 i) internal view returns(uint256) {
        uint256 reversed = LibBit.reverseBits(i);
        console.log(reversed);
        reversed = (reversed >> 244);
        console.log(reversed);
        // TODO - Check that this is the right offset
        console.logBytes32(bytes32(ROOT));
        console.log(exp(ROOT, reversed));
        return (exp(ROOT, reversed));
    }

    // Should give good preformance for our exp < 4096 compared to modexp 
    function exp(uint256 b, uint256 e) internal pure returns(uint256) {
        if (e == 0) {
            return(1);
        }
        uint256 ret = 1;
        while (e != 0) {
            if (e % 2 == 1) {
                ret = mulmod(ret, b, BLS_MODULUS);
            }
            e = e >> 1;
            b = mulmod(b, b, BLS_MODULUS);
        }
        return (ret);
    }
}
