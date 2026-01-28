// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {PredictableMerkleLib, Leaf, Bytes32Poseidon, Proof} from "../src/library/PredictableMerkleLib.sol";
import {IUpdateVerifier} from "../src/interfaces/IUpdateVerifier.sol";
import {UpdateVerifier} from "../circuits/verifiers/predictableUpdateVerifier.sol";

/// @notice Test contract for PredictableMerkleLib
/// @dev Tests the hash function using FFI with circomlibjs Poseidon
///      Tests verifyPredictableUpdate with real Groth16 verifier
contract PredictableMerkleLibTest is Test {
    using PredictableMerkleLib for IUpdateVerifier;
    using Bytes32Poseidon for bytes32[2];
    using Bytes32Poseidon for bytes32[4];

    // Real Groth16 verifier
    UpdateVerifier realVerifier;

    // Cached proof data (generated once in setUp to avoid repeated slow FFI calls)
    Proof cachedProof;
    bytes32[6] cachedPublicInputs;
    bool proofGenerated;

    function setUp() public {
        realVerifier = new UpdateVerifier();

        // Generate proof once via FFI and cache it
        _generateAndCacheProof();
    }

    /// @notice Generate proof via FFI and cache for reuse across tests
    function _generateAndCacheProof() internal {
        string[] memory cmd = new string[](2);
        cmd[0] = "node";
        cmd[1] = "script/generatePredictableUpdateProof.js";

        bytes memory result = vm.ffi(cmd);
        string memory jsonStr = string(result);

        // Parse proof components
        uint256 pA0 = vm.parseJsonUint(jsonStr, ".proof._pA[0]");
        uint256 pA1 = vm.parseJsonUint(jsonStr, ".proof._pA[1]");
        uint256 pB00 = vm.parseJsonUint(jsonStr, ".proof._pB[0][0]");
        uint256 pB01 = vm.parseJsonUint(jsonStr, ".proof._pB[0][1]");
        uint256 pB10 = vm.parseJsonUint(jsonStr, ".proof._pB[1][0]");
        uint256 pB11 = vm.parseJsonUint(jsonStr, ".proof._pB[1][1]");
        uint256 pC0 = vm.parseJsonUint(jsonStr, ".proof._pC[0]");
        uint256 pC1 = vm.parseJsonUint(jsonStr, ".proof._pC[1]");

        // Parse public signals
        // Snarkjs order: [anchorAfter (output), anchorBefore, update0, update1, update2, blockIndex]
        uint256 anchorAfter = vm.parseJsonUint(jsonStr, ".publicSignals[0]");
        uint256 anchorBefore = vm.parseJsonUint(jsonStr, ".publicSignals[1]");
        uint256 update0 = vm.parseJsonUint(jsonStr, ".publicSignals[2]");
        uint256 update1 = vm.parseJsonUint(jsonStr, ".publicSignals[3]");
        uint256 update2 = vm.parseJsonUint(jsonStr, ".publicSignals[4]");
        uint256 blockIndex = vm.parseJsonUint(jsonStr, ".publicSignals[5]");

        // Cache the proof
        cachedProof = Proof({_pA: [pA0, pA1], _pB: [[pB00, pB01], [pB10, pB11]], _pC: [pC0, pC1]});

        // Cache public inputs in snarkjs order: [anchorAfter, anchorBefore, update0, update1, update2, blockIndex]
        cachedPublicInputs = [
            bytes32(anchorAfter),
            bytes32(anchorBefore),
            bytes32(update0),
            bytes32(update1),
            bytes32(update2),
            bytes32(blockIndex)
        ];

        proofGenerated = true;
    }

    // ============================================================================
    // Helper Functions
    // ============================================================================

    /// @notice Converts bytes32 to hex string (without 0x prefix)
    function _bytes32ToHexString(bytes32 value) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            result[i * 2] = hexChars[uint8(value[i]) >> 4];
            result[i * 2 + 1] = hexChars[uint8(value[i]) & 0x0f];
        }
        return string(result);
    }

    /// @notice Converts uint256 to hex string (without 0x prefix), padded to 64 chars
    function _uint256ToHexString(uint256 value) internal pure returns (string memory) {
        return _bytes32ToHexString(bytes32(value));
    }

    /// @notice Computes 4-input Poseidon hash via FFI using circomlibjs
    function _ffiPoseidonHash(uint256[4] memory inputs) internal returns (bytes32) {
        string[] memory cmd = new string[](6);
        cmd[0] = "node";
        cmd[1] = "script/poseidonHash.js";
        cmd[2] = _uint256ToHexString(inputs[0]);
        cmd[3] = _uint256ToHexString(inputs[1]);
        cmd[4] = _uint256ToHexString(inputs[2]);
        cmd[5] = _uint256ToHexString(inputs[3]);

        bytes memory result = vm.ffi(cmd);
        return abi.decode(result, (bytes32));
    }

    /// @notice Computes 2-input Poseidon hash via FFI using circomlibjs
    function _ffiPoseidonHash2(uint256[2] memory inputs) internal returns (bytes32) {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = "script/poseidonHash.js";
        cmd[2] = _uint256ToHexString(inputs[0]);
        cmd[3] = _uint256ToHexString(inputs[1]);

        bytes memory result = vm.ffi(cmd);
        return abi.decode(result, (bytes32));
    }

    // ============================================================================
    // Leaf Hash Tests
    // ============================================================================

    /// @notice Test hash function with simple inputs
    function test_Hash_SimpleInputs() public pure {
        Leaf memory leaf =
            Leaf({asset: address(0x1), amount: 100, blinding: bytes32(uint256(123)), publicKey: bytes32(uint256(456))});

        bytes32 solidityHash = PredictableMerkleLib.hash(leaf);

        // Verify hash is non-zero
        assertTrue(solidityHash != bytes32(0), "Hash should be non-zero");

        // Verify deterministic - same input gives same output
        bytes32 solidityHash2 = PredictableMerkleLib.hash(leaf);
        assertEq(solidityHash, solidityHash2, "Hash should be deterministic");
    }

    /// @notice Test hash function matches circomlib Poseidon via FFI
    function test_Hash_MatchesCircomlib() public {
        address asset = address(0x1234567890123456789012345678901234567890);
        uint256 amount = 1000000;
        bytes32 blinding = keccak256("test_blinding");
        bytes32 publicKey = keccak256("test_public_key");

        Leaf memory leaf = Leaf({asset: asset, amount: amount, blinding: blinding, publicKey: publicKey});

        // Compute hash in Solidity
        bytes32 solidityHash = PredictableMerkleLib.hash(leaf);

        // Compute hash via FFI using circomlibjs
        // The hash function uses uint256(uint160(asset)) which RIGHT-aligns the address (low 160 bits)
        uint256[4] memory inputs;
        inputs[0] = uint256(uint160(asset));
        inputs[1] = amount;
        inputs[2] = uint256(blinding);
        inputs[3] = uint256(publicKey);

        bytes32 ffiHash = _ffiPoseidonHash(inputs);

        assertEq(solidityHash, ffiHash, "Solidity Poseidon hash should match circomlib");
    }

    /// @notice Test hash function with zero inputs
    function test_Hash_ZeroInputs() public {
        Leaf memory leaf = Leaf({asset: address(0), amount: 0, blinding: bytes32(0), publicKey: bytes32(0)});

        bytes32 hash = PredictableMerkleLib.hash(leaf);
        assertTrue(hash != bytes32(0), "Hash of zeros should be non-zero");

        // Verify via FFI
        uint256[4] memory inputs = [uint256(0), uint256(0), uint256(0), uint256(0)];
        bytes32 ffiHash = _ffiPoseidonHash(inputs);

        assertEq(hash, ffiHash, "Zero input hash should match circomlib");
    }

    // ============================================================================
    // 2-Width Hash Tests (Bytes32Poseidon for tree internal nodes)
    // ============================================================================

    /// @notice Test 2-width hash function matches circomlib Poseidon via FFI
    function test_Hash2_MatchesCircomlib() public {
        bytes32 left = keccak256("left_child");
        bytes32 right = keccak256("right_child");

        bytes32[2] memory data = [left, right];

        // Compute hash in Solidity
        bytes32 solidityHash = data.hash();

        // Compute hash via FFI using circomlibjs
        uint256[2] memory inputs = [uint256(left), uint256(right)];
        bytes32 ffiHash = _ffiPoseidonHash2(inputs);

        assertEq(solidityHash, ffiHash, "Solidity 2-width Poseidon hash should match circomlib");
    }

    /// @notice Test 2-width hash with zero inputs
    function test_Hash2_ZeroInputs() public {
        bytes32[2] memory data = [bytes32(0), bytes32(0)];

        bytes32 hash = data.hash();
        assertTrue(hash != bytes32(0), "Hash of zeros should be non-zero");

        // Verify via FFI
        uint256[2] memory inputs = [uint256(0), uint256(0)];
        bytes32 ffiHash = _ffiPoseidonHash2(inputs);

        assertEq(hash, ffiHash, "Zero input 2-width hash should match circomlib");
    }

    /// @notice Test 2-width hash is deterministic
    function test_Hash2_Deterministic() public pure {
        bytes32[2] memory data = [bytes32(uint256(123)), bytes32(uint256(456))];

        bytes32 hash1 = data.hash();
        bytes32 hash2 = data.hash();

        assertEq(hash1, hash2, "2-width hash should be deterministic");
    }

    // ============================================================================
    // verifyPredictableUpdate Tests with Real Verifier
    // ============================================================================

    /// @notice Test verifyPredictableUpdate with actual ZK proof
    function test_VerifyPredictableUpdate_RealProof() public view {
        require(proofGenerated, "Proof not generated");

        bool isValid = IUpdateVerifier(address(realVerifier)).verifyPredictableUpdate(cachedPublicInputs, cachedProof);
        assertTrue(isValid, "Real ZK proof should verify");
    }

    /// @notice Test that an invalid proof fails verification
    function test_VerifyPredictableUpdate_InvalidProof() public view {
        require(proofGenerated, "Proof not generated");

        // Create an INVALID proof
        Proof memory invalidProof = Proof({
            _pA: [uint256(1), uint256(2)],
            _pB: [[uint256(1), uint256(2)], [uint256(1), uint256(2)]],
            _pC: [uint256(1), uint256(2)]
        });

        bool isValid = IUpdateVerifier(address(realVerifier)).verifyPredictableUpdate(cachedPublicInputs, invalidProof);
        assertFalse(isValid, "Invalid proof should not verify");
    }

    /// @notice Test that proof with wrong public inputs fails
    function test_VerifyPredictableUpdate_WrongPublicInputs() public view {
        require(proofGenerated, "Proof not generated");

        // Use WRONG public inputs
        bytes32[6] memory wrongPublicInputs = [
            bytes32(uint256(999)),
            bytes32(uint256(0)),
            bytes32(uint256(100)),
            bytes32(uint256(200)),
            bytes32(uint256(300)),
            bytes32(uint256(888))
        ];

        bool isValid = IUpdateVerifier(address(realVerifier)).verifyPredictableUpdate(wrongPublicInputs, cachedProof);
        assertFalse(isValid, "Proof with wrong public inputs should not verify");
    }
}
