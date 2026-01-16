// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {TreeUpdateChallenge} from "../src/TreeUpdateChallenge.sol";
import {Spine} from "../src/Spine.sol";
import {PredictableMerkleLib, Proof} from "../src/library/PredictableMerkleLib.sol";
import {BlobData} from "../src/library/BlobData.sol";
import {Groth16Verifier} from "../circuits/verifiers/predictableUpdateVerifier.sol";
import {IYieldRouter} from "../src/interfaces/IYieldRouter.sol";
import {IUpdateVerifier} from "../src/interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "../src/interfaces/ITransferVerifier.sol";
import {ITransactionRegistry} from "../src/TransactionRegistry.sol";
import {MockYieldRouter} from "./mocks/MockYieldRouter.sol";
import {MockTransactionRegistry} from "./mocks/MockTransactionRegistry.sol";
import {FakeZK} from "./mocks/FakeZK.sol";
import {FakeBlobs} from "./mocks/FakeBlobs.sol";

/// @title TreeUpdateChallenge Integration Test
/// @notice Comprehensive integration tests with real ZK proofs and multi-day/block scenarios
/// @dev Tests:
///      1. 2 full days with 5 blocks each (12 deposits + 1 tx per block)
///      2. 3rd day with fraud/no fraud tests on block 3
///      3. Real Poseidon-based anchor computation
/// @dev IMPORTANT: Run tests with --jobs 1 to avoid FFI race conditions:
///      forge test --match-contract TreeUpdateChallengeIntegrationTest --jobs 1
///      4. Non-zero day/index values
///      5. Blocks before and after the challenged block
contract TreeUpdateChallengeIntegrationTest is Test {
    using PredictableMerkleLib for IUpdateVerifier;

    // Real Groth16 verifier for predictableUpdate circuit
    Groth16Verifier realZkVerifier;

    // Mock verifier for transfer proofs (not tested here)
    FakeZK fakeTransferVerifier;

    MockYieldRouter yieldRouter;
    MockTransactionRegistry txRegistry;

    address sequencer = address(0x1111);
    address challenger = address(0x2222);

    uint256 constant BLOCKS_PER_DAY = 8192; // 2^13

    // Multi-block test data from FFI
    struct MultiBlockTestData {
        bytes32 genesisAnchor;
        // Target block info
        uint256 targetDay;
        uint256 targetBlockIdx;
        uint256 targetTreeIndex;
        uint256 targetNumDeposits;
        uint256 targetNumTx;
        bytes32 targetFinalAnchor;
        // Target update info
        uint256 targetUpdateIndex; // Index in blockUpdates array
        uint256 numDepositGroups; // Number of deposit groups
        bool targetIsTx; // True if targeting a transaction, false for deposits
        uint256 regionStart; // Memory address where the challenge region starts
        bytes32[3] targetUpdates;
        bytes32 targetPriorAnchor;
        bytes32 targetNewAnchor;
        uint256 targetInBlockIndex;
        // Prior block info
        bytes32 anchorBeforeTargetBlock;
        // ZK proof
        Proof zkProof;
        bytes32[6] publicSignals;
        // Blob data for target block
        bytes32[] blobData;
        // All block anchors for building state
        bytes32[] blockAnchors;
        uint256[] blockTreeIndexes;
        // KZG proof data for blob 1
        bytes kzgCommitment;
        bytes32 kzgBlobHash;
        bytes32[] kzgClaims;
        bytes[] kzgProofs;
        uint256[] kzgIndices;
        // KZG proof data for blob 2 (extension region) - cross-blob only
        bytes extensionKzgCommitment;
        bytes32 extensionKzgBlobHash;
        bytes32[] extensionKzgClaims;
        bytes[] extensionKzgProofs;
        uint256[] extensionKzgIndices;
        // Region split info (for cross-blob)
        uint256 regionLength;
        uint256 extensionRegionLength;
        uint256 extensionRegionMemoryAddress;
        // Fraud mode
        bool fraudMode;
        bytes32 fraudAnchor;
        // Cross-blob mode
        bool crossblobMode;
    }

    // Test data for different scenarios
    MultiBlockTestData fraudTestData;
    bool fraudTestDataGenerated;

    MultiBlockTestData txTestData; // Transaction (no fraud)
    bool txTestDataGenerated;

    MultiBlockTestData txFraudTestData; // Transaction (fraud)
    bool txFraudTestDataGenerated;

    MultiBlockTestData crossblobTestData; // Cross-blob transaction
    bool crossblobTestDataGenerated;

    MultiBlockTestData crossblobFraudTestData; // Cross-blob transaction (fraud)
    bool crossblobFraudTestDataGenerated;

    // Structure to decode KZG proof binary
    struct KzgProofData {
        bytes commitment;
        uint256[] indices;
        bytes32[] claims;
        bytes32 hash;
        bytes[] proofs;
    }

    MultiBlockTestData testData;
    bool testDataGenerated;

    function setUp() public {
        realZkVerifier = new Groth16Verifier();
        fakeTransferVerifier = new FakeZK();
        yieldRouter = new MockYieldRouter();
        txRegistry = new MockTransactionRegistry();

        vm.deal(sequencer, 100 ether);
        vm.deal(challenger, 10 ether);

        // Generate multi-block test data via FFI
        _generateMultiBlockTestData();
    }

    /// @notice Parse JSON string into a MultiBlockTestData struct
    /// @param jsonStr The JSON string to parse
    /// @param data The storage struct to populate
    function _parseTestDataFromJson(string memory jsonStr, MultiBlockTestData storage data) internal {
        // Parse genesis anchor and mode flags
        data.genesisAnchor = bytes32(vm.parseJsonUint(jsonStr, ".genesisAnchor"));
        data.fraudMode = vm.parseJsonBool(jsonStr, ".fraudMode");
        data.targetIsTx = vm.parseJsonBool(jsonStr, ".targetIsTx");

        // Parse fraud anchor if in fraud mode
        if (data.fraudMode) {
            data.fraudAnchor = bytes32(vm.parseJsonUint(jsonStr, ".fraudAnchor"));
        }

        // Parse config
        data.targetUpdateIndex = vm.parseJsonUint(jsonStr, ".config.targetUpdateIndex");
        data.numDepositGroups = vm.parseJsonUint(jsonStr, ".config.numDepositGroups");
        data.regionStart = vm.parseJsonUint(jsonStr, ".config.regionStart");

        // Parse target block info
        data.targetDay = vm.parseJsonUint(jsonStr, ".targetBlock.day");
        data.targetBlockIdx = vm.parseJsonUint(jsonStr, ".targetBlock.blockIdx");
        data.targetTreeIndex = vm.parseJsonUint(jsonStr, ".targetBlock.treeIndex");
        data.targetNumDeposits = vm.parseJsonUint(jsonStr, ".targetBlock.numDeposits");
        data.targetNumTx = vm.parseJsonUint(jsonStr, ".targetBlock.numTx");
        data.targetFinalAnchor = bytes32(vm.parseJsonUint(jsonStr, ".targetBlock.finalAnchor"));

        // Parse target update info
        data.targetUpdates[0] = bytes32(vm.parseJsonUint(jsonStr, ".targetUpdate.updates[0]"));
        data.targetUpdates[1] = bytes32(vm.parseJsonUint(jsonStr, ".targetUpdate.updates[1]"));
        data.targetUpdates[2] = bytes32(vm.parseJsonUint(jsonStr, ".targetUpdate.updates[2]"));
        data.targetPriorAnchor = bytes32(vm.parseJsonUint(jsonStr, ".targetUpdate.priorAnchor"));
        data.targetNewAnchor = bytes32(vm.parseJsonUint(jsonStr, ".targetUpdate.newAnchor"));
        data.targetInBlockIndex = vm.parseJsonUint(jsonStr, ".targetUpdate.inBlockIndex");

        // Parse anchor before target block
        data.anchorBeforeTargetBlock = bytes32(vm.parseJsonUint(jsonStr, ".anchorBeforeTargetBlock"));

        // Parse ZK proof
        uint256 pA0 = vm.parseJsonUint(jsonStr, ".proof._pA[0]");
        uint256 pA1 = vm.parseJsonUint(jsonStr, ".proof._pA[1]");
        uint256 pB00 = vm.parseJsonUint(jsonStr, ".proof._pB[0][0]");
        uint256 pB01 = vm.parseJsonUint(jsonStr, ".proof._pB[0][1]");
        uint256 pB10 = vm.parseJsonUint(jsonStr, ".proof._pB[1][0]");
        uint256 pB11 = vm.parseJsonUint(jsonStr, ".proof._pB[1][1]");
        uint256 pC0 = vm.parseJsonUint(jsonStr, ".proof._pC[0]");
        uint256 pC1 = vm.parseJsonUint(jsonStr, ".proof._pC[1]");

        data.zkProof = Proof({_pA: [pA0, pA1], _pB: [[pB00, pB01], [pB10, pB11]], _pC: [pC0, pC1]});

        // Parse public signals
        data.publicSignals[0] = bytes32(vm.parseJsonUint(jsonStr, ".publicSignals[0]"));
        data.publicSignals[1] = bytes32(vm.parseJsonUint(jsonStr, ".publicSignals[1]"));
        data.publicSignals[2] = bytes32(vm.parseJsonUint(jsonStr, ".publicSignals[2]"));
        data.publicSignals[3] = bytes32(vm.parseJsonUint(jsonStr, ".publicSignals[3]"));
        data.publicSignals[4] = bytes32(vm.parseJsonUint(jsonStr, ".publicSignals[4]"));
        data.publicSignals[5] = bytes32(vm.parseJsonUint(jsonStr, ".publicSignals[5]"));

        // Parse blob data for target block (20 elements: 4 deposit groups + 1 tx = 5 groups * 4)
        uint256 blobDataLength = 20;
        data.blobData = new bytes32[](blobDataLength);
        for (uint256 i = 0; i < blobDataLength; i++) {
            string memory key = string(abi.encodePacked(".targetBlock.blobData[", vm.toString(i), "]"));
            data.blobData[i] = bytes32(vm.parseJsonUint(jsonStr, key));
        }

        // Parse all block anchors and tree indexes (15 blocks total)
        uint256 numBlocks = 15;
        data.blockAnchors = new bytes32[](numBlocks);
        data.blockTreeIndexes = new uint256[](numBlocks);
        for (uint256 i = 0; i < numBlocks; i++) {
            string memory anchorKey = string(abi.encodePacked(".blocks[", vm.toString(i), "].finalAnchor"));
            string memory indexKey = string(abi.encodePacked(".blocks[", vm.toString(i), "].treeIndex"));
            data.blockAnchors[i] = bytes32(vm.parseJsonUint(jsonStr, anchorKey));
            data.blockTreeIndexes[i] = vm.parseJsonUint(jsonStr, indexKey);
        }

        // Parse region split info (for cross-blob)
        data.regionLength = vm.parseJsonUint(jsonStr, ".regionLength");
        data.extensionRegionLength = vm.parseJsonUint(jsonStr, ".extensionRegionLength");
        data.extensionRegionMemoryAddress = vm.parseJsonUint(jsonStr, ".extensionRegionMemoryAddress");
        data.crossblobMode = vm.parseJsonBool(jsonStr, ".crossblobMode");

        // Parse KZG proof data from binary file (blob 1)
        string memory kzgBinaryPath = vm.parseJsonString(jsonStr, ".kzgProofBinaryPath");
        bytes memory kzgBinary = vm.readFileBinary(kzgBinaryPath);
        KzgProofData memory kzgData = abi.decode(kzgBinary, (KzgProofData));

        data.kzgCommitment = kzgData.commitment;
        data.kzgBlobHash = kzgData.hash;
        data.kzgClaims = kzgData.claims;
        data.kzgProofs = kzgData.proofs;
        data.kzgIndices = kzgData.indices;

        // Parse extension KZG proof data (blob 2) - only in cross-blob mode
        if (data.crossblobMode && data.extensionRegionLength > 0) {
            string memory extKzgBinaryPath = vm.parseJsonString(jsonStr, ".extensionKzgBinaryPath");
            bytes memory extKzgBinary = vm.readFileBinary(extKzgBinaryPath);
            KzgProofData memory extKzgData = abi.decode(extKzgBinary, (KzgProofData));

            data.extensionKzgCommitment = extKzgData.commitment;
            data.extensionKzgBlobHash = extKzgData.hash;
            data.extensionKzgClaims = extKzgData.claims;
            data.extensionKzgProofs = extKzgData.proofs;
            data.extensionKzgIndices = extKzgData.indices;
        }
    }

    /// @notice Generate comprehensive multi-block test data via FFI
    function _generateMultiBlockTestData() internal {
        string[] memory cmd = new string[](2);
        cmd[0] = "node";
        cmd[1] = "script/generateMultiBlockTestData.js";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, testData);
        testDataGenerated = true;
    }

    /// @notice Generate fraud test data via FFI with --fraud flag
    function _generateFraudTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateMultiBlockTestData.js";
        cmd[2] = "--fraud";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, fraudTestData);
        fraudTestDataGenerated = true;
    }

    /// @notice Generate transaction test data via FFI with --tx flag
    function _generateTxTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateMultiBlockTestData.js";
        cmd[2] = "--tx";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, txTestData);
        txTestDataGenerated = true;
    }

    /// @notice Generate transaction fraud test data via FFI with --tx and --fraud flags
    function _generateTxFraudTestData() internal {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = "script/generateMultiBlockTestData.js";
        cmd[2] = "--tx";
        cmd[3] = "--fraud";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, txFraudTestData);
        txFraudTestDataGenerated = true;
    }

    /// @notice Generate cross-blob test data via FFI with --crossblob flag
    function _generateCrossblobTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateMultiBlockTestData.js";
        cmd[2] = "--crossblob";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, crossblobTestData);
        crossblobTestDataGenerated = true;
    }

    /// @notice Generate cross-blob fraud test data via FFI with --crossblob and --fraud flags
    function _generateCrossblobFraudTestData() internal {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = "script/generateMultiBlockTestData.js";
        cmd[2] = "--crossblob";
        cmd[3] = "--fraud";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, crossblobFraudTestData);
        crossblobFraudTestDataGenerated = true;
    }

    // ============================================================================
    // Configuration and state verification tests
    // ============================================================================

    /// @notice Verify that the test configuration has non-zero day/index
    function test_Config_NonZeroDayAndIndex() public view {
        require(testDataGenerated, "Test data not generated");

        assertTrue(testData.targetDay > 0, "Target day should be > 0");
        assertTrue(testData.targetBlockIdx > 0, "Target block index should be > 0");
        assertTrue(testData.targetTreeIndex > 0, "Tree index should be > 0");

        // Verify tree index formula: day * 2^13 + blockIdx
        uint256 expectedTreeIndex = testData.targetDay * BLOCKS_PER_DAY + testData.targetBlockIdx;
        assertEq(testData.targetTreeIndex, expectedTreeIndex, "Tree index formula");
    }

    /// @notice Verify we have blocks before and after target
    function test_Config_BlocksBeforeAndAfter() public view {
        require(testDataGenerated, "Test data not generated");

        // Target is day 2, block 2 (0-indexed), so index in array is 2*5 + 2 = 12
        uint256 targetIndex = testData.targetDay * 5 + testData.targetBlockIdx;

        assertTrue(targetIndex > 0, "Should have blocks before target");
        assertTrue(targetIndex < testData.blockAnchors.length - 1, "Should have blocks after target");
    }

    /// @notice Verify genesis anchor is non-zero (computed from zero tree)
    function test_GenesisAnchor_IsNonZero() public view {
        require(testDataGenerated, "Test data not generated");
        assertTrue(testData.genesisAnchor != bytes32(0), "Genesis anchor should be non-zero");
    }

    /// @notice Verify target block has expected deposit/tx counts
    function test_TargetBlock_Configuration() public view {
        require(testDataGenerated, "Test data not generated");

        assertEq(testData.targetNumDeposits, 12, "Should have 12 deposits");
        assertEq(testData.targetNumTx, 1, "Should have 1 transaction");

        // 12 deposits = 4 groups, plus 1 tx = 5 total update groups
        // Each group has 4 blob elements (3 updates + anchor)
        assertEq(testData.blobData.length, 20, "Blob should have 20 elements");
    }

    // ============================================================================
    // Real ZK proof verification tests
    // ============================================================================

    /// @notice Verify that the real ZK proof verifies with the public signals
    function test_RealZkProof_Verifies() public view {
        require(testDataGenerated, "Test data not generated");

        bool isValid =
            IUpdateVerifier(address(realZkVerifier)).verifyPredictableUpdate(testData.publicSignals, testData.zkProof);
        assertTrue(isValid, "Real ZK proof should verify");
    }

    /// @notice Verify public signals structure matches contract expectations
    function test_PublicSignals_MatchesContractOrder() public view {
        require(testDataGenerated, "Test data not generated");

        // Contract constructs: [trueAnchor, priorAnchor, update0, update1, update2, treeIndex]
        // snarkjs outputs: [anchorAfter, anchorBefore, update0, update1, update2, blockIndex]

        assertEq(testData.publicSignals[0], testData.targetNewAnchor, "publicSignals[0] = newAnchor");
        assertEq(testData.publicSignals[1], testData.targetPriorAnchor, "publicSignals[1] = priorAnchor");
        assertEq(testData.publicSignals[2], testData.targetUpdates[0], "publicSignals[2] = update0");
        assertEq(testData.publicSignals[3], testData.targetUpdates[1], "publicSignals[3] = update1");
        assertEq(testData.publicSignals[4], testData.targetUpdates[2], "publicSignals[4] = update2");
        assertEq(testData.publicSignals[5], bytes32(testData.targetTreeIndex), "publicSignals[5] = treeIndex");
    }

    /// @notice Test that modifying the anchor causes proof verification to fail
    function test_RealZkProof_FailsWithWrongAnchor() public view {
        require(testDataGenerated, "Test data not generated");

        bytes32[6] memory wrongSignals = testData.publicSignals;
        wrongSignals[0] = bytes32(uint256(testData.publicSignals[0]) + 1);

        bool isValid = IUpdateVerifier(address(realZkVerifier)).verifyPredictableUpdate(wrongSignals, testData.zkProof);
        assertFalse(isValid, "Proof should fail with wrong anchor");
    }

    /// @notice Test that modifying treeIndex causes proof verification to fail
    function test_RealZkProof_FailsWithWrongTreeIndex() public view {
        require(testDataGenerated, "Test data not generated");

        bytes32[6] memory wrongSignals = testData.publicSignals;
        wrongSignals[5] = bytes32(uint256(testData.publicSignals[5]) + 1);

        bool isValid = IUpdateVerifier(address(realZkVerifier)).verifyPredictableUpdate(wrongSignals, testData.zkProof);
        assertFalse(isValid, "Proof should fail with wrong treeIndex");
    }

    // ============================================================================
    // Anchor chain verification tests
    // ============================================================================

    /// @notice Verify anchor chain across multiple blocks
    function test_AnchorChain_EvolvesCorrectly() public view {
        require(testDataGenerated, "Test data not generated");

        // Each block should have a different anchor (state evolved)
        for (uint256 i = 1; i < testData.blockAnchors.length; i++) {
            assertTrue(
                testData.blockAnchors[i] != testData.blockAnchors[i - 1],
                "Adjacent blocks should have different anchors"
            );
        }

        // First block's prior should relate to genesis
        assertTrue(testData.blockAnchors[0] != testData.genesisAnchor, "First block anchor should differ from genesis");
    }

    /// @notice Verify tree indexes follow day*2^13 + blockIdx pattern
    function test_TreeIndexes_FollowPattern() public view {
        require(testDataGenerated, "Test data not generated");

        for (uint256 i = 0; i < testData.blockTreeIndexes.length; i++) {
            uint256 day = i / 5; // 5 blocks per day in test
            uint256 blockIdx = i % 5;
            uint256 expectedTreeIndex = day * BLOCKS_PER_DAY + blockIdx;

            assertEq(testData.blockTreeIndexes[i], expectedTreeIndex, "Tree index should match formula");
        }
    }

    // ============================================================================
    // Helper Functions for Full Integration Tests
    // ============================================================================

    /// @notice Create harness with real ZK verifier and fund sequencer
    function _createRealHarness() internal returns (TreeUpdateChallengeRealHarness harness) {
        harness = new TreeUpdateChallengeRealHarness(
            testData.genesisAnchor,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(realZkVerifier)), // Real Groth16 verifier
            ITransferVerifier(address(fakeTransferVerifier)),
            ITransactionRegistry(address(txRegistry))
        );
        harness.fundSequencer{value: 20 ether}(sequencer);
    }

    /// @notice Build up state by adding all blocks before target
    /// @param harness The harness to add blocks to
    /// @param startTime Base timestamp for time warping
    /// @return targetBlockArrayIndex The index of the target block in the array
    function _buildBlockChain(TreeUpdateChallengeRealHarness harness, uint256 startTime)
        internal
        returns (uint256 targetBlockArrayIndex)
    {
        uint256 SECONDS_PER_DAY = 86400;
        targetBlockArrayIndex = testData.targetDay * 5 + testData.targetBlockIdx;

        for (uint256 i = 0; i < targetBlockArrayIndex; i++) {
            uint256 day = i / 5;
            uint256 blockIdx = i % 5;

            // Warp time to the correct day
            vm.warp(startTime + day * SECONDS_PER_DAY + blockIdx * 100);

            // Use fake blob hash for prior blocks (we won't challenge them)
            bytes32 fakeBlobHash = keccak256(abi.encodePacked("fake_blob_", i));
            bytes32[] memory blobHashes = new bytes32[](1);
            blobHashes[0] = fakeBlobHash;
            vm.blobhashes(blobHashes);

            Spine.BlockData memory blockData = Spine.BlockData({
                anchor: testData.blockAnchors[i],
                timestamp: 0,
                numTransactions: 1,
                numDeposits: 12,
                blockNr: 0,
                blockIndex: Spine.TimestampAndIndex(uint16(day), uint16(blockIdx)),
                sequencer: sequencer,
                blobhashes: blobHashes
            });

            uint256[] memory blockIndices = new uint256[](1);
            blockIndices[0] = 0;

            vm.prank(sequencer);
            harness.addBlockTest(blockData, blockIndices);
        }
    }

    /// @notice Add target block with REAL KZG blob hash
    /// @param harness The harness to add the target block to
    /// @param startTime Base timestamp for time warping
    /// @param blobHash The blob hash to use (real KZG or fraud)
    /// @param finalAnchor The anchor to use in the block header
    /// @return targetBlockData The added block data
    function _addTargetBlock(
        TreeUpdateChallengeRealHarness harness,
        uint256 startTime,
        bytes32 blobHash,
        bytes32 finalAnchor
    ) internal returns (Spine.BlockData memory targetBlockData) {
        uint256 SECONDS_PER_DAY = 86400;

        // Warp to target day/block
        vm.warp(startTime + testData.targetDay * SECONDS_PER_DAY + testData.targetBlockIdx * 100);

        // Use provided blob hash
        bytes32[] memory realBlobHashes = new bytes32[](1);
        realBlobHashes[0] = blobHash;
        vm.blobhashes(realBlobHashes);

        targetBlockData = Spine.BlockData({
            anchor: finalAnchor,
            timestamp: 0,
            numTransactions: testData.targetNumTx,
            numDeposits: testData.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(uint16(testData.targetDay), uint16(testData.targetBlockIdx)),
            sequencer: sequencer,
            blobhashes: realBlobHashes
        });

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);
    }

    /// @notice Build challenge region from KZG proofs
    /// @param kzgClaims The KZG claims to use
    /// @param kzgProofs The KZG proofs to use
    /// @param commitment The KZG commitment
    /// @param blobHash The blob hash
    /// @param regionStartAddr The memory address where the region starts
    /// @param hasPriorAnchorProof Whether there's a prior anchor proof at index 0
    /// @return region The challenge region
    /// @return emptyRegion Empty region for unused parameter
    /// @return priorAnchorProof The proof for prior anchor position
    function _buildChallengeRegion(
        bytes32[] memory kzgClaims,
        bytes[] memory kzgProofs,
        bytes memory commitment,
        bytes32 blobHash,
        uint256 regionStartAddr,
        bool hasPriorAnchorProof
    )
        internal
        pure
        returns (BlobData.Region memory region, BlobData.Region memory emptyRegion, bytes memory priorAnchorProof)
    {
        uint256 regionProofOffset = hasPriorAnchorProof ? 1 : 0;

        bytes32[] memory regionData = new bytes32[](4);
        bytes[] memory regionProofs = new bytes[](4);
        for (uint256 i = 0; i < 4; i++) {
            regionData[i] = kzgClaims[regionProofOffset + i];
            regionProofs[i] = kzgProofs[regionProofOffset + i];
        }

        region = BlobData.Region({
            length: 4,
            memoryAddress: regionStartAddr,
            data: regionData,
            proofs: regionProofs,
            commitment: commitment,
            hash: blobHash
        });

        emptyRegion = BlobData.Region({
            length: 0,
            memoryAddress: 0,
            data: new bytes32[](0),
            proofs: new bytes[](0),
            commitment: "",
            hash: bytes32(0)
        });

        priorAnchorProof = hasPriorAnchorProof ? kzgProofs[0] : bytes("");
    }

    // ============================================================================
    // Full Integration Test with REAL ZK and KZG proofs
    // ============================================================================

    /// @notice Comprehensive integration test with:
    ///         - Real Groth16 ZK proofs
    ///         - Real KZG blob proofs for the target block
    ///         - All blocks built up over 3 days with vm.warp
    ///         - Proper anchor chain from genesis through target
    function test_FullIntegration_RealZkAndKzg_NoFraud() public {
        require(testDataGenerated, "Test data not generated");

        // Create harness and build block chain
        TreeUpdateChallengeRealHarness harness = _createRealHarness();
        uint256 startTime = block.timestamp;
        uint256 targetBlockArrayIndex = _buildBlockChain(harness, startTime);

        // Add target block with real KZG blob hash and correct anchor
        Spine.BlockData memory targetBlockData =
            _addTargetBlock(harness, startTime, testData.kzgBlobHash, testData.targetFinalAnchor);

        // Verify block was added at correct position
        assertEq(targetBlockData.blockNr, targetBlockArrayIndex, "Block number should match");

        // Build challenge region with real KZG proofs
        (BlobData.Region memory region, BlobData.Region memory emptyRegion, bytes memory priorAnchorProof) = _buildChallengeRegion(
            testData.kzgClaims,
            testData.kzgProofs,
            testData.kzgCommitment,
            testData.kzgBlobHash,
            testData.regionStart,
            testData.targetUpdateIndex > 0
        );

        // The prior and new anchors come from test data
        bytes32 priorAnchor = testData.targetPriorAnchor;
        bytes32 trueAnchor = testData.targetNewAnchor;

        // Challenge with real proofs - should revert with "No Fraud"
        // because trueAnchor matches what's in the blob
        vm.prank(challenger);
        Spine.BlockData memory rollbackTarget;
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            targetBlockData,
            testData.targetUpdateIndex,
            testData.targetIsTx, // isTx from test data
            region,
            emptyRegion,
            priorAnchor,
            testData.kzgCommitment,
            priorAnchorProof,
            trueAnchor,
            testData.zkProof,
            rollbackTarget
        );
    }

    /// @notice Test that KZG proofs were correctly generated and match blob data
    function test_KzgProofData_IsValid() public view {
        require(testDataGenerated, "Test data not generated");

        // Verify we have KZG data
        assertTrue(testData.kzgCommitment.length > 0, "KZG commitment should exist");
        // For update > 0, we have 5 proofs (1 prior + 4 region), for update 0, we have 4 proofs
        uint256 expectedProofs = testData.targetUpdateIndex > 0 ? 5 : 4;
        assertEq(testData.kzgProofs.length, expectedProofs, "Should have expected KZG proofs");
        assertEq(testData.kzgClaims.length, expectedProofs, "Should have expected KZG claims");
        assertTrue(testData.kzgBlobHash != bytes32(0), "KZG blob hash should exist");

        // Verify KZG claims match blob data at the expected indices
        // For update > 0: claims[0] is prior anchor, claims[1-4] are region
        // For update 0: claims[0-3] are region
        uint256 offset = testData.targetUpdateIndex > 0 ? 1 : 0;
        uint256 regionStart = testData.targetUpdateIndex * 4;
        for (uint256 i = 0; i < 4; i++) {
            assertEq(
                testData.kzgClaims[offset + i], testData.blobData[regionStart + i], "KZG claim should match blob data"
            );
        }
    }

    // ============================================================================
    // Fraud Integration Test with REAL ZK and KZG proofs
    // ============================================================================

    /// @notice Integration test demonstrating fraud detection with:
    ///         - Real Groth16 ZK proofs proving the CORRECT anchor
    ///         - Real KZG blob proofs proving a FRAUDULENT anchor in the blob
    ///         - Challenger proves fraud and sequencer gets slashed
    function test_FullIntegration_RealZkAndKzg_Fraud() public {
        // Generate fraud test data (blob has incorrect anchor)
        _generateFraudTestData();
        require(fraudTestDataGenerated, "Fraud test data not generated");
        require(fraudTestData.fraudMode, "Should be in fraud mode");

        // Create harness with real genesis anchor and real ZK verifier
        TreeUpdateChallengeRealHarness harness = new TreeUpdateChallengeRealHarness(
            fraudTestData.genesisAnchor,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(realZkVerifier)), // Real Groth16 verifier
            ITransferVerifier(address(fakeTransferVerifier)),
            ITransactionRegistry(address(txRegistry))
        );

        harness.fundSequencer{value: 20 ether}(sequencer);

        // Constants for time progression
        uint256 SECONDS_PER_DAY = 86400;
        uint256 startTime = block.timestamp;

        // Build up state: Add all blocks before target
        // Store each block after adding so we have correct data for rollback target
        uint256 targetBlockArrayIndex = fraudTestData.targetDay * 5 + fraudTestData.targetBlockIdx;
        Spine.BlockData[] memory storedBlocks = new Spine.BlockData[](targetBlockArrayIndex);

        for (uint256 i = 0; i < targetBlockArrayIndex; i++) {
            uint256 day = i / 5;
            uint256 blockIdx = i % 5;

            vm.warp(startTime + day * SECONDS_PER_DAY + blockIdx * 100);

            bytes32 fakeBlobHash = keccak256(abi.encodePacked("fake_blob_", i));
            bytes32[] memory blobHashes = new bytes32[](1);
            blobHashes[0] = fakeBlobHash;
            vm.blobhashes(blobHashes);

            Spine.BlockData memory blockData = Spine.BlockData({
                anchor: fraudTestData.blockAnchors[i],
                timestamp: 0,
                numTransactions: 1,
                numDeposits: 12,
                blockNr: 0,
                blockIndex: Spine.TimestampAndIndex(uint16(day), uint16(blockIdx)),
                sequencer: sequencer,
                blobhashes: blobHashes
            });

            uint256[] memory blockIndices = new uint256[](1);
            blockIndices[0] = 0;

            vm.prank(sequencer);
            storedBlocks[i] = harness.addBlockTest(blockData, blockIndices);
        }

        // Add target block with FRAUDULENT KZG blob hash
        vm.warp(startTime + fraudTestData.targetDay * SECONDS_PER_DAY + fraudTestData.targetBlockIdx * 100);

        bytes32[] memory fraudBlobHashes = new bytes32[](1);
        fraudBlobHashes[0] = fraudTestData.kzgBlobHash;
        vm.blobhashes(fraudBlobHashes);

        Spine.BlockData memory targetBlockData = Spine.BlockData({
            anchor: fraudTestData.targetFinalAnchor,
            timestamp: 0,
            numTransactions: fraudTestData.targetNumTx,
            numDeposits: fraudTestData.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(uint16(fraudTestData.targetDay), uint16(fraudTestData.targetBlockIdx)),
            sequencer: sequencer,
            blobhashes: fraudBlobHashes
        });

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);

        // Build challenge region with FRAUD KZG proofs
        (BlobData.Region memory region, BlobData.Region memory emptyRegion, bytes memory priorAnchorProof) = _buildChallengeRegion(
            fraudTestData.kzgClaims,
            fraudTestData.kzgProofs,
            fraudTestData.kzgCommitment,
            fraudTestData.kzgBlobHash,
            fraudTestData.regionStart,
            fraudTestData.targetUpdateIndex > 0
        );

        // The prior anchor is the same as normal (computed correctly by FFI)
        bytes32 priorAnchor = fraudTestData.targetPriorAnchor;

        // The TRUE anchor (what ZK proof proves is correct)
        bytes32 trueAnchor = fraudTestData.targetNewAnchor;

        // The FRAUD anchor (what's actually in the blob - differs from trueAnchor!)
        bytes32 fraudAnchor = fraudTestData.fraudAnchor;

        // Verify the fraud: blob anchor differs from true anchor
        assertTrue(fraudAnchor != trueAnchor, "Fraud anchor should differ from true anchor");

        // Verify blob data at position 3 of region contains the fraudulent anchor
        uint256 fraudAnchorBlobPos = fraudTestData.targetUpdateIndex * 4 + 3;
        assertEq(fraudTestData.blobData[fraudAnchorBlobPos], fraudAnchor, "Blob should contain fraud anchor");

        // Capture sequencer state before challenge
        (bool isActiveBefore,,,,, uint64 stakeBefore,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before");
        assertTrue(stakeBefore > 0, "Sequencer should have stake before");

        // Use the stored block data for rollback target (the block BEFORE the fraudulent block)
        Spine.BlockData memory rollbackTarget = storedBlocks[targetBlockArrayIndex - 1];

        // Challenge with real proofs - should SUCCEED and slash sequencer
        // because trueAnchor (ZK verified) != fraudAnchor (in blob)
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            targetBlockData,
            fraudTestData.targetUpdateIndex,
            fraudTestData.targetIsTx,
            region,
            emptyRegion,
            priorAnchor,
            fraudTestData.kzgCommitment,
            priorAnchorProof,
            trueAnchor,
            fraudTestData.zkProof,
            rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActiveAfter,,,,, uint64 stakeAfter, address payable challengerAfter) =
            harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed (inactive)");
        assertEq(challengerAfter, challenger, "Challenger should be recorded");
        assertTrue(stakeAfter > 0, "Stake should still be held for later claim");
    }

    // ============================================================================
    // Transaction Integration Tests with REAL ZK and KZG proofs
    // ============================================================================

    /// @notice Transaction integration test - No Fraud case
    ///         Tests a transaction update (not deposit) with real proofs
    function test_FullIntegration_Transaction_RealZkAndKzg_NoFraud() public {
        // Generate transaction test data
        _generateTxTestData();
        require(txTestDataGenerated, "Tx test data not generated");
        require(txTestData.targetIsTx, "Should target a transaction");

        // Create harness with real ZK verifier
        TreeUpdateChallengeRealHarness harness = new TreeUpdateChallengeRealHarness(
            txTestData.genesisAnchor,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(realZkVerifier)),
            ITransferVerifier(address(fakeTransferVerifier)),
            ITransactionRegistry(address(txRegistry))
        );

        harness.fundSequencer{value: 20 ether}(sequencer);

        uint256 SECONDS_PER_DAY = 86400;
        uint256 startTime = block.timestamp;

        // Build up state: Add all blocks before target
        uint256 targetBlockArrayIndex = txTestData.targetDay * 5 + txTestData.targetBlockIdx;

        for (uint256 i = 0; i < targetBlockArrayIndex; i++) {
            uint256 day = i / 5;
            uint256 blockIdx = i % 5;

            vm.warp(startTime + day * SECONDS_PER_DAY + blockIdx * 100);

            bytes32 fakeBlobHash = keccak256(abi.encodePacked("fake_blob_", i));
            bytes32[] memory blobHashes = new bytes32[](1);
            blobHashes[0] = fakeBlobHash;
            vm.blobhashes(blobHashes);

            Spine.BlockData memory blockData = Spine.BlockData({
                anchor: txTestData.blockAnchors[i],
                timestamp: 0,
                numTransactions: 1,
                numDeposits: 12,
                blockNr: 0,
                blockIndex: Spine.TimestampAndIndex(uint16(day), uint16(blockIdx)),
                sequencer: sequencer,
                blobhashes: blobHashes
            });

            uint256[] memory blockIndices = new uint256[](1);
            blockIndices[0] = 0;

            vm.prank(sequencer);
            harness.addBlockTest(blockData, blockIndices);
        }

        // Add target block with real KZG blob hash
        vm.warp(startTime + txTestData.targetDay * SECONDS_PER_DAY + txTestData.targetBlockIdx * 100);

        bytes32[] memory realBlobHashes = new bytes32[](1);
        realBlobHashes[0] = txTestData.kzgBlobHash;
        vm.blobhashes(realBlobHashes);

        Spine.BlockData memory targetBlockData = Spine.BlockData({
            anchor: txTestData.targetFinalAnchor,
            timestamp: 0,
            numTransactions: txTestData.targetNumTx,
            numDeposits: txTestData.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(uint16(txTestData.targetDay), uint16(txTestData.targetBlockIdx)),
            sequencer: sequencer,
            blobhashes: realBlobHashes
        });

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);

        // Build challenge region
        (BlobData.Region memory region, BlobData.Region memory emptyRegion, bytes memory priorAnchorProof) = _buildChallengeRegion(
            txTestData.kzgClaims,
            txTestData.kzgProofs,
            txTestData.kzgCommitment,
            txTestData.kzgBlobHash,
            txTestData.regionStart,
            txTestData.targetUpdateIndex > 0
        );

        // For transactions, updateNr is the transaction index (not the overall update index)
        // updateNr for tx = targetUpdateIndex - numDepositGroups
        uint256 updateNr = txTestData.targetUpdateIndex - txTestData.numDepositGroups;

        // Challenge with real proofs - should revert with "No Fraud"
        vm.prank(challenger);
        Spine.BlockData memory rollbackTarget;
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            targetBlockData,
            updateNr,
            txTestData.targetIsTx, // true for transaction
            region,
            emptyRegion,
            txTestData.targetPriorAnchor,
            txTestData.kzgCommitment,
            priorAnchorProof,
            txTestData.targetNewAnchor,
            txTestData.zkProof,
            rollbackTarget
        );
    }

    /// @notice Transaction integration test - Fraud case
    ///         Tests fraud detection for a transaction update with real proofs
    function test_FullIntegration_Transaction_RealZkAndKzg_Fraud() public {
        // Generate transaction fraud test data
        _generateTxFraudTestData();
        require(txFraudTestDataGenerated, "Tx fraud test data not generated");
        require(txFraudTestData.fraudMode, "Should be in fraud mode");
        require(txFraudTestData.targetIsTx, "Should target a transaction");

        // Create harness with real ZK verifier
        TreeUpdateChallengeRealHarness harness = new TreeUpdateChallengeRealHarness(
            txFraudTestData.genesisAnchor,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(realZkVerifier)),
            ITransferVerifier(address(fakeTransferVerifier)),
            ITransactionRegistry(address(txRegistry))
        );

        harness.fundSequencer{value: 20 ether}(sequencer);

        uint256 SECONDS_PER_DAY = 86400;
        uint256 startTime = block.timestamp;

        // Build up state: Add all blocks before target
        uint256 targetBlockArrayIndex = txFraudTestData.targetDay * 5 + txFraudTestData.targetBlockIdx;
        Spine.BlockData[] memory storedBlocks = new Spine.BlockData[](targetBlockArrayIndex);

        for (uint256 i = 0; i < targetBlockArrayIndex; i++) {
            uint256 day = i / 5;
            uint256 blockIdx = i % 5;

            vm.warp(startTime + day * SECONDS_PER_DAY + blockIdx * 100);

            bytes32 fakeBlobHash = keccak256(abi.encodePacked("fake_blob_", i));
            bytes32[] memory blobHashes = new bytes32[](1);
            blobHashes[0] = fakeBlobHash;
            vm.blobhashes(blobHashes);

            Spine.BlockData memory blockData = Spine.BlockData({
                anchor: txFraudTestData.blockAnchors[i],
                timestamp: 0,
                numTransactions: 1,
                numDeposits: 12,
                blockNr: 0,
                blockIndex: Spine.TimestampAndIndex(uint16(day), uint16(blockIdx)),
                sequencer: sequencer,
                blobhashes: blobHashes
            });

            uint256[] memory blockIndices = new uint256[](1);
            blockIndices[0] = 0;

            vm.prank(sequencer);
            storedBlocks[i] = harness.addBlockTest(blockData, blockIndices);
        }

        // Add target block with fraud KZG blob hash
        vm.warp(startTime + txFraudTestData.targetDay * SECONDS_PER_DAY + txFraudTestData.targetBlockIdx * 100);

        bytes32[] memory fraudBlobHashes = new bytes32[](1);
        fraudBlobHashes[0] = txFraudTestData.kzgBlobHash;
        vm.blobhashes(fraudBlobHashes);

        Spine.BlockData memory targetBlockData = Spine.BlockData({
            anchor: txFraudTestData.targetFinalAnchor,
            timestamp: 0,
            numTransactions: txFraudTestData.targetNumTx,
            numDeposits: txFraudTestData.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(
                uint16(txFraudTestData.targetDay), uint16(txFraudTestData.targetBlockIdx)
            ),
            sequencer: sequencer,
            blobhashes: fraudBlobHashes
        });

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);

        // Build challenge region
        (BlobData.Region memory region, BlobData.Region memory emptyRegion, bytes memory priorAnchorProof) = _buildChallengeRegion(
            txFraudTestData.kzgClaims,
            txFraudTestData.kzgProofs,
            txFraudTestData.kzgCommitment,
            txFraudTestData.kzgBlobHash,
            txFraudTestData.regionStart,
            txFraudTestData.targetUpdateIndex > 0
        );

        // Verify fraud: blob anchor differs from true anchor
        bytes32 trueAnchor = txFraudTestData.targetNewAnchor;
        bytes32 fraudAnchor = txFraudTestData.fraudAnchor;
        assertTrue(fraudAnchor != trueAnchor, "Fraud anchor should differ from true anchor");

        // For transactions, updateNr is the transaction index (not the overall update index)
        uint256 updateNr = txFraudTestData.targetUpdateIndex - txFraudTestData.numDepositGroups;

        // Capture sequencer state before challenge
        (bool isActiveBefore,,,,, uint64 stakeBefore,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before");
        assertTrue(stakeBefore > 0, "Sequencer should have stake before");

        // Use stored block data for rollback target
        Spine.BlockData memory rollbackTarget = storedBlocks[targetBlockArrayIndex - 1];

        // Challenge with real proofs - should SUCCEED and slash sequencer
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            targetBlockData,
            updateNr,
            txFraudTestData.targetIsTx, // true for transaction
            region,
            emptyRegion,
            txFraudTestData.targetPriorAnchor,
            txFraudTestData.kzgCommitment,
            priorAnchorProof,
            trueAnchor,
            txFraudTestData.zkProof,
            rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActiveAfter,,,,, uint64 stakeAfter, address payable challengerAfter) =
            harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed (inactive)");
        assertEq(challengerAfter, challenger, "Challenger should be recorded");
        assertTrue(stakeAfter > 0, "Stake should still be held for later claim");
    }

    // ============================================================================
    // Cross-Blob Integration Test - Tree Update spanning blob boundary
    // ============================================================================

    /// @notice Helper to build cross-blob challenge regions
    function _buildCrossblobChallengeRegions(MultiBlockTestData storage data)
        internal
        view
        returns (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes memory priorAnchorProof)
    {
        // For cross-blob, there's always a prior anchor proof at index 0 for updates > 0
        bool hasPriorAnchorProof = data.targetUpdateIndex > 0;
        uint256 regionProofOffset = hasPriorAnchorProof ? 1 : 0;

        // Build region from blob 1 (partial update data at end of blob)
        bytes32[] memory regionData = new bytes32[](data.regionLength);
        bytes[] memory regionProofs = new bytes[](data.regionLength);

        for (uint256 i = 0; i < data.regionLength; i++) {
            regionData[i] = data.kzgClaims[regionProofOffset + i];
            regionProofs[i] = data.kzgProofs[regionProofOffset + i];
        }

        region = BlobData.Region({
            length: data.regionLength,
            memoryAddress: data.regionStart,
            data: regionData,
            proofs: regionProofs,
            commitment: data.kzgCommitment,
            hash: data.kzgBlobHash
        });

        // Build extensionRegion from blob 2 (remaining update data at start of blob)
        bytes32[] memory extRegionData = new bytes32[](data.extensionRegionLength);
        bytes[] memory extRegionProofs = new bytes[](data.extensionRegionLength);

        for (uint256 i = 0; i < data.extensionRegionLength; i++) {
            extRegionData[i] = data.extensionKzgClaims[i];
            extRegionProofs[i] = data.extensionKzgProofs[i];
        }

        extensionRegion = BlobData.Region({
            length: data.extensionRegionLength,
            memoryAddress: data.extensionRegionMemoryAddress,
            data: extRegionData,
            proofs: extRegionProofs,
            commitment: data.extensionKzgCommitment,
            hash: data.extensionKzgBlobHash
        });

        priorAnchorProof = hasPriorAnchorProof ? data.kzgProofs[0] : bytes("");
    }

    /// @notice Test tree update that spans two blobs using extension regions
    /// This tests the cross-blob code path where:
    ///   - region contains the first part of the update (in blob 1, at position 4095)
    ///   - extensionRegion contains the rest (in blob 2, at positions 0-2)
    ///   - Both regions use real KZG proofs
    function test_FullIntegration_RealZkAndKzg_CrossBlob_NoFraud() public {
        // Generate cross-blob test data
        _generateCrossblobTestData();
        require(crossblobTestDataGenerated, "Cross-blob test data not generated");
        require(crossblobTestData.crossblobMode, "Should be in cross-blob mode");
        require(crossblobTestData.extensionRegionLength > 0, "Should have extension region");
        require(crossblobTestData.targetIsTx, "Cross-blob targets a transaction");

        // Verify the split is correct
        assertEq(
            crossblobTestData.regionLength + crossblobTestData.extensionRegionLength,
            4,
            "Region + extension should equal 4"
        );
        assertTrue(crossblobTestData.regionStart >= 4093, "Update should start near blob boundary");

        emit log_named_uint("Region length", crossblobTestData.regionLength);
        emit log_named_uint("Extension region length", crossblobTestData.extensionRegionLength);
        emit log_named_uint("Region start (memory address)", crossblobTestData.regionStart);

        // Create harness with real ZK verifier
        TreeUpdateChallengeRealHarness harness = new TreeUpdateChallengeRealHarness(
            crossblobTestData.genesisAnchor,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(realZkVerifier)),
            ITransferVerifier(address(fakeTransferVerifier)),
            ITransactionRegistry(address(txRegistry))
        );

        harness.fundSequencer{value: 20 ether}(sequencer);

        uint256 SECONDS_PER_DAY = 86400;
        uint256 startTime = block.timestamp;

        // Build up state: Add all blocks before target
        uint256 targetBlockArrayIndex = crossblobTestData.targetDay * 5 + crossblobTestData.targetBlockIdx;

        for (uint256 i = 0; i < targetBlockArrayIndex; i++) {
            uint256 day = i / 5;
            uint256 blockIdx = i % 5;

            vm.warp(startTime + day * SECONDS_PER_DAY + blockIdx * 100);

            // Cross-blob config: 3 deposits + 273 tx = 4 + 4095 = 4099 elements
            // This exceeds 4096, so we need 2 blob hashes for each prior block
            bytes32 fakeBlobHash1 = keccak256(abi.encodePacked("fake_blob_", i, "_1"));
            bytes32 fakeBlobHash2 = keccak256(abi.encodePacked("fake_blob_", i, "_2"));
            bytes32[] memory blobHashes = new bytes32[](2);
            blobHashes[0] = fakeBlobHash1;
            blobHashes[1] = fakeBlobHash2;
            vm.blobhashes(blobHashes);

            // Prior blocks use the cross-blob config (same numTx/numDeposits as target)
            Spine.BlockData memory blockData = Spine.BlockData({
                anchor: crossblobTestData.blockAnchors[i],
                timestamp: 0,
                numTransactions: crossblobTestData.targetNumTx, // Same as target for consistency
                numDeposits: crossblobTestData.targetNumDeposits, // Same as target for consistency
                blockNr: 0,
                blockIndex: Spine.TimestampAndIndex(uint16(day), uint16(blockIdx)),
                sequencer: sequencer,
                blobhashes: blobHashes
            });

            uint256[] memory blockIndices = new uint256[](2);
            blockIndices[0] = 0;
            blockIndices[1] = 1;

            vm.prank(sequencer);
            harness.addBlockTest(blockData, blockIndices);
        }

        // Add target block with TWO blob hashes for cross-blob scenario
        vm.warp(startTime + crossblobTestData.targetDay * SECONDS_PER_DAY + crossblobTestData.targetBlockIdx * 100);

        bytes32[] memory realBlobHashes = new bytes32[](2);
        realBlobHashes[0] = crossblobTestData.kzgBlobHash;
        realBlobHashes[1] = crossblobTestData.extensionKzgBlobHash;
        vm.blobhashes(realBlobHashes);

        Spine.BlockData memory targetBlockData = Spine.BlockData({
            anchor: crossblobTestData.targetFinalAnchor,
            timestamp: 0,
            numTransactions: crossblobTestData.targetNumTx,
            numDeposits: crossblobTestData.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(
                uint16(crossblobTestData.targetDay), uint16(crossblobTestData.targetBlockIdx)
            ),
            sequencer: sequencer,
            blobhashes: realBlobHashes
        });

        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);

        // Build cross-blob challenge regions
        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes memory priorAnchorProof) =
            _buildCrossblobChallengeRegions(crossblobTestData);

        // Verify regions are properly constructed
        assertEq(region.length, crossblobTestData.regionLength, "Region length mismatch");
        assertEq(extensionRegion.length, crossblobTestData.extensionRegionLength, "Extension length mismatch");
        assertEq(extensionRegion.memoryAddress, 0, "Extension should start at 0");

        // For transactions, updateNr is the transaction index (not the overall update index)
        uint256 updateNr = crossblobTestData.targetUpdateIndex - crossblobTestData.numDepositGroups;

        // Challenge with real proofs - should revert with "No Fraud"
        // because the ZK proof and blob data match
        vm.prank(challenger);
        Spine.BlockData memory rollbackTarget;
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            targetBlockData,
            updateNr,
            crossblobTestData.targetIsTx, // true for transaction
            region,
            extensionRegion, // This is the key difference - non-empty extension region
            crossblobTestData.targetPriorAnchor,
            crossblobTestData.kzgCommitment,
            priorAnchorProof,
            crossblobTestData.targetNewAnchor,
            crossblobTestData.zkProof,
            rollbackTarget
        );

        // Verify sequencer is still active
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    // ============================================================================
    // Cross-Blob Fraud Integration Test - Wrong anchor in extension region
    // ============================================================================

    /// @notice Test fraud detection for cross-blob tree update with wrong anchor
    /// The update spans two blobs (blob boundary at position 4096).
    /// The fraud is that the anchor in the extension region (blob 2) is incorrect.
    /// Structure: [update0 in blob1] [update1, update2, fraudAnchor in blob2]
    function test_FullIntegration_RealZkAndKzg_CrossBlob_Fraud() public {
        // Generate cross-blob fraud test data
        _generateCrossblobFraudTestData();
        require(crossblobFraudTestDataGenerated, "Cross-blob fraud test data not generated");
        require(crossblobFraudTestData.crossblobMode, "Should be in cross-blob mode");
        require(crossblobFraudTestData.fraudMode, "Should be in fraud mode");
        require(crossblobFraudTestData.extensionRegionLength > 0, "Should have extension region");
        require(crossblobFraudTestData.targetIsTx, "Cross-blob targets a transaction");

        // In fraud mode, the blob contains fraudAnchor instead of targetNewAnchor
        assertTrue(
            crossblobFraudTestData.fraudAnchor != crossblobFraudTestData.targetNewAnchor,
            "Fraud anchor should differ from correct anchor"
        );

        // Verify the split is correct
        assertEq(
            crossblobFraudTestData.regionLength + crossblobFraudTestData.extensionRegionLength,
            4,
            "Region + extension should equal 4"
        );
        assertTrue(crossblobFraudTestData.regionStart >= 4093, "Update should start near blob boundary");

        emit log_named_uint("Region length", crossblobFraudTestData.regionLength);
        emit log_named_uint("Extension region length", crossblobFraudTestData.extensionRegionLength);
        emit log_named_uint("Region start (memory address)", crossblobFraudTestData.regionStart);

        // Create harness with real ZK verifier
        TreeUpdateChallengeRealHarness harness = new TreeUpdateChallengeRealHarness(
            crossblobFraudTestData.genesisAnchor,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(realZkVerifier)),
            ITransferVerifier(address(fakeTransferVerifier)),
            ITransactionRegistry(address(txRegistry))
        );

        harness.fundSequencer{value: 20 ether}(sequencer);

        uint256 SECONDS_PER_DAY = 86400;
        uint256 startTime = block.timestamp;

        // Build up state: Add all blocks before target
        uint256 targetBlockArrayIndex = crossblobFraudTestData.targetDay * 5 + crossblobFraudTestData.targetBlockIdx;
        Spine.BlockData[] memory storedBlocks = new Spine.BlockData[](targetBlockArrayIndex);

        for (uint256 i = 0; i < targetBlockArrayIndex; i++) {
            uint256 day = i / 5;
            uint256 blockIdx = i % 5;

            vm.warp(startTime + day * SECONDS_PER_DAY + blockIdx * 100);

            // Cross-blob config: 3 deposits + 273 tx = 4 + 4095 = 4099 elements
            // This exceeds 4096, so we need 2 blob hashes for each prior block
            bytes32 fakeBlobHash1 = keccak256(abi.encodePacked("fake_blob_", i, "_1"));
            bytes32 fakeBlobHash2 = keccak256(abi.encodePacked("fake_blob_", i, "_2"));
            bytes32[] memory blobHashes = new bytes32[](2);
            blobHashes[0] = fakeBlobHash1;
            blobHashes[1] = fakeBlobHash2;
            vm.blobhashes(blobHashes);

            Spine.BlockData memory blockData = Spine.BlockData({
                anchor: crossblobFraudTestData.blockAnchors[i],
                timestamp: 0,
                numTransactions: crossblobFraudTestData.targetNumTx,
                numDeposits: crossblobFraudTestData.targetNumDeposits,
                blockNr: 0,
                blockIndex: Spine.TimestampAndIndex(uint16(day), uint16(blockIdx)),
                sequencer: sequencer,
                blobhashes: blobHashes
            });

            uint256[] memory blockIndices = new uint256[](2);
            blockIndices[0] = 0;
            blockIndices[1] = 1;

            vm.prank(sequencer);
            storedBlocks[i] = harness.addBlockTest(blockData, blockIndices);
        }

        // Add target block with TWO blob hashes for cross-blob scenario
        vm.warp(
            startTime + crossblobFraudTestData.targetDay * SECONDS_PER_DAY + crossblobFraudTestData.targetBlockIdx * 100
        );

        bytes32[] memory realBlobHashes = new bytes32[](2);
        realBlobHashes[0] = crossblobFraudTestData.kzgBlobHash;
        realBlobHashes[1] = crossblobFraudTestData.extensionKzgBlobHash;
        vm.blobhashes(realBlobHashes);

        Spine.BlockData memory targetBlockData = Spine.BlockData({
            anchor: crossblobFraudTestData.targetFinalAnchor,
            timestamp: 0,
            numTransactions: crossblobFraudTestData.targetNumTx,
            numDeposits: crossblobFraudTestData.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(
                uint16(crossblobFraudTestData.targetDay), uint16(crossblobFraudTestData.targetBlockIdx)
            ),
            sequencer: sequencer,
            blobhashes: realBlobHashes
        });

        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);

        // Build cross-blob challenge regions
        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes memory priorAnchorProof) =
            _buildCrossblobChallengeRegions(crossblobFraudTestData);

        // Verify regions are properly constructed
        assertEq(region.length, crossblobFraudTestData.regionLength, "Region length mismatch");
        assertEq(extensionRegion.length, crossblobFraudTestData.extensionRegionLength, "Extension length mismatch");
        assertEq(extensionRegion.memoryAddress, 0, "Extension should start at 0");

        // For transactions, updateNr is the transaction index (not the overall update index)
        uint256 updateNr = crossblobFraudTestData.targetUpdateIndex - crossblobFraudTestData.numDepositGroups;

        // Capture sequencer state before challenge
        (bool isActiveBefore,,,,, uint64 stakeBefore,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before");
        assertTrue(stakeBefore > 0, "Sequencer should have stake before");

        // Rollback target is the block before the fraudulent block
        Spine.BlockData memory rollbackTarget = storedBlocks[targetBlockArrayIndex - 1];

        // Challenge with real proofs - should SUCCEED because the blob contains fraudAnchor
        // but the ZK proof proves targetNewAnchor is correct
        // The challenger provides targetNewAnchor (the TRUE anchor from ZK proof)
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            targetBlockData,
            updateNr,
            crossblobFraudTestData.targetIsTx,
            region,
            extensionRegion, // Cross-blob: non-empty extension region with fraud anchor
            crossblobFraudTestData.targetPriorAnchor,
            crossblobFraudTestData.kzgCommitment,
            priorAnchorProof,
            crossblobFraudTestData.targetNewAnchor, // The TRUE anchor (ZK verified)
            crossblobFraudTestData.zkProof,
            rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActiveAfter,,,,, uint64 stakeAfter, address payable challengerAfter) =
            harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed (inactive)");
        assertEq(challengerAfter, challenger, "Challenger should be recorded");
        assertTrue(stakeAfter > 0, "Stake should still be held for later claim");
    }
}

// ============================================================================
// Test Harness with FakeBlobs for integration testing
// ============================================================================

/// @notice Integration test harness combining TreeUpdateChallenge with FakeBlobs
contract TreeUpdateChallengeIntegrationHarness is TreeUpdateChallenge, FakeBlobs {
    constructor(
        bytes32 genesis,
        IYieldRouter _yieldRouter,
        IUpdateVerifier _updateVerifier,
        ITransferVerifier _transferVerifier,
        ITransactionRegistry _txRegistry
    ) {
        GENESIS_ANCHOR = genesis;
        yieldRouter = _yieldRouter;
        predictableUpdateVerifier = _updateVerifier;
        transactionZkVerifier = _transferVerifier;
        transferRegistry = _txRegistry;
        _initializeOwner(msg.sender);
    }

    function addBlockTest(Spine.BlockData memory data, uint256[] memory indices)
        public
        returns (Spine.BlockData memory)
    {
        addBlock(data, indices);
        return data;
    }

    function validateSingle(bytes32 rootHash, bytes calldata, uint256 index, bytes32 data, bytes calldata)
        internal
        view
        override
    {
        require(access(rootHash, index) == data);
    }

    function getSequencerStatus(address _sequencer)
        public
        view
        returns (
            bool isActive,
            bool isPriority,
            uint8 priorityIndex,
            uint64 blocknumberChallenged,
            uint64 timestampChallenged,
            uint64 stakeAmount,
            address payable challengerAddr
        )
    {
        SequencerStatus memory status = sequencers[_sequencer];
        return (
            status.isActive,
            status.isPriority,
            status.priorityIndex,
            status.blocknumberChallenged,
            status.timestampChallenged,
            status.stakeAmount,
            status.challenger
        );
    }

    receive() external payable {}

    function fundSequencer(address who) public payable {
        sequencers[who].isActive = true;
        sequencers[who].stakeAmount += uint64(msg.value / (10 ** 14));
    }
}

// ============================================================================
// Test Harness with REAL KZG blob validation
// ============================================================================

/// @notice Integration test harness using real KZG blob validation
contract TreeUpdateChallengeRealHarness is TreeUpdateChallenge {
    constructor(
        bytes32 genesis,
        IYieldRouter _yieldRouter,
        IUpdateVerifier _updateVerifier,
        ITransferVerifier _transferVerifier,
        ITransactionRegistry _txRegistry
    ) {
        GENESIS_ANCHOR = genesis;
        yieldRouter = _yieldRouter;
        predictableUpdateVerifier = _updateVerifier;
        transactionZkVerifier = _transferVerifier;
        transferRegistry = _txRegistry;
        _initializeOwner(msg.sender);
    }

    function addBlockTest(Spine.BlockData memory data, uint256[] memory indices)
        public
        returns (Spine.BlockData memory)
    {
        addBlock(data, indices);
        return data;
    }

    function getSequencerStatus(address _sequencer)
        public
        view
        returns (
            bool isActive,
            bool isPriority,
            uint8 priorityIndex,
            uint64 blocknumberChallenged,
            uint64 timestampChallenged,
            uint64 stakeAmount,
            address payable challengerAddr
        )
    {
        SequencerStatus memory status = sequencers[_sequencer];
        return (
            status.isActive,
            status.isPriority,
            status.priorityIndex,
            status.blocknumberChallenged,
            status.timestampChallenged,
            status.stakeAmount,
            status.challenger
        );
    }

    receive() external payable {}

    function fundSequencer(address who) public payable {
        sequencers[who].isActive = true;
        sequencers[who].stakeAmount += uint64(msg.value / (10 ** 14));
    }
}
