// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/TransactionChallenge.sol";
import "../src/Spine.sol";
import "../src/library/BlobData.sol";
import "../circuits/verifiers/transferVerifier.sol";
import "./mocks/MockYieldRouter.sol";
import "./mocks/FakeZK.sol";
import "./mocks/FakeBlobs.sol";
import "./mocks/ConfigurableTxRegistry.sol";

/// @title TransactionChallenge Integration Test
/// @notice Comprehensive integration tests with real ZK proofs and multi-day/block scenarios
/// @dev Tests:
///      1. Multiple days with blocks (12 deposits + 1 tx per block)
///      2. Real transfer ZK proofs (Groth16)
///      3. Real KZG blob proofs
///      4. Various fraud scenarios
/// @dev IMPORTANT: Run tests with --jobs 1 to avoid FFI race conditions:
///      forge test --match-contract TransactionChallengeIntegrationTest --jobs 1
contract TransactionChallengeIntegrationTest is Test {
    // Real Groth16 verifier for transfer circuit
    Groth16Verifier realTransferVerifier;

    // Fake verifier for predictable update (not tested in TransactionChallenge)
    FakeZK fakeUpdateVerifier;

    MockYieldRouter yieldRouter;
    ConfigurableTxRegistry txRegistry;

    address sequencer = address(0x1111);
    address challenger = address(0x2222);

    uint256 constant BLOCKS_PER_DAY = 8192; // 2^13

    // Test data structure for transaction challenge
    struct TxChallengeTestData {
        bytes32 genesisAnchor;
        bool fraudMode;
        bool unregisteredMode;
        bool crossblobMode;
        bool multiTxMode;
        bool depositAnchorMode;
        bool sameBlockMode;
        // Target block info
        uint256 targetDay;
        uint256 targetBlockIdx;
        uint256 targetTreeIndex;
        uint256 targetNumDeposits;
        uint256 targetNumTx;
        bytes32 targetFinalAnchor;
        // Transaction info
        uint256 targetTxNr;
        uint256 anchorBlockNr;
        uint256 anchorUpdateNr;
        bool isDepositAnchor;
        bytes32 txAnchor;
        bytes32 blobAnchor;
        uint256 ethKey;
        // ZK proof
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        string[] publicSignals;
        // Transaction region (14 elements)
        bytes32[] txRegion;
        // Memory positions
        uint256 txMemoryAddress;
        uint256 depositsMemoryLength;
        // Region split info (for cross-blob)
        uint256 regionLength;
        uint256 extensionRegionLength;
        uint256 extensionRegionMemoryAddress;
        // Block chain data
        bytes32[] blockAnchors;
        uint256[] blockTreeIndexes;
        // Prior block
        bytes32 anchorBeforeTargetBlock;
        // KZG data for target block (blob 1)
        bytes kzgCommitment;
        bytes32 kzgBlobHash;
        bytes32[] kzgClaims;
        bytes[] kzgProofs;
        uint256[] kzgIndices;
        // KZG data for extension region (blob 2) - cross-blob only
        bytes extensionKzgCommitment;
        bytes32 extensionKzgBlobHash;
        bytes32[] extensionKzgClaims;
        bytes[] extensionKzgProofs;
        uint256[] extensionKzgIndices;
        // Full blob data
        bytes32[] blobData;
        // Prior anchor KZG data
        bytes priorAnchorCommitment;
        bytes32 priorAnchorBlobHash;
        bytes32 priorAnchorClaim;
        bytes priorAnchorProof;
        uint256 priorAnchorMemoryPosition;
    }

    // Structure to decode KZG proof binary
    struct KzgProofData {
        bytes commitment;
        uint256[] indices;
        bytes32[] claims;
        bytes32 hash;
        bytes[] proofs;
    }

    TxChallengeTestData testData;
    bool testDataGenerated;

    TxChallengeTestData fraudTestData;
    bool fraudTestDataGenerated;

    TxChallengeTestData unregisteredTestData;
    bool unregisteredTestDataGenerated;

    TxChallengeTestData crossblobTestData;
    bool crossblobTestDataGenerated;

    TxChallengeTestData crossblobFraudTestData;
    bool crossblobFraudTestDataGenerated;

    TxChallengeTestData multiTxTestData;
    bool multiTxTestDataGenerated;

    TxChallengeTestData depositAnchorTestData;
    bool depositAnchorTestDataGenerated;

    TxChallengeTestData sameBlockTestData;
    bool sameBlockTestDataGenerated;

    function setUp() public {
        realTransferVerifier = new Groth16Verifier();
        fakeUpdateVerifier = new FakeZK();
        yieldRouter = new MockYieldRouter();
        txRegistry = new ConfigurableTxRegistry();

        vm.deal(sequencer, 100 ether);
        vm.deal(challenger, 10 ether);

        // Generate test data via FFI
        _generateTestData();
    }

    /// @notice Parse JSON string into TxChallengeTestData struct
    function _parseTestDataFromJson(string memory jsonStr, TxChallengeTestData storage data) internal {
        // Parse basic info
        data.genesisAnchor = bytes32(vm.parseJsonUint(jsonStr, ".genesisAnchor"));
        data.fraudMode = vm.parseJsonBool(jsonStr, ".fraudMode");
        data.unregisteredMode = vm.parseJsonBool(jsonStr, ".unregisteredMode");
        data.crossblobMode = vm.parseJsonBool(jsonStr, ".crossblobMode");
        data.multiTxMode = vm.parseJsonBool(jsonStr, ".multiTxMode");
        data.depositAnchorMode = vm.parseJsonBool(jsonStr, ".depositAnchorMode");
        data.sameBlockMode = vm.parseJsonBool(jsonStr, ".sameBlockMode");

        // Parse config/target info
        data.targetDay = vm.parseJsonUint(jsonStr, ".config.targetDay");
        data.targetBlockIdx = vm.parseJsonUint(jsonStr, ".config.targetBlock");
        data.targetNumDeposits = vm.parseJsonUint(jsonStr, ".config.depositsPerBlock");
        data.targetNumTx = vm.parseJsonUint(jsonStr, ".config.txPerBlock");

        // Parse target block
        data.targetTreeIndex = vm.parseJsonUint(jsonStr, ".targetBlock.treeIndex");
        data.targetFinalAnchor = bytes32(vm.parseJsonUint(jsonStr, ".targetBlock.finalAnchor"));

        // Parse transaction info
        data.targetTxNr = vm.parseJsonUint(jsonStr, ".targetTxNr");
        data.anchorBlockNr = vm.parseJsonUint(jsonStr, ".anchorBlockNr");
        data.anchorUpdateNr = vm.parseJsonUint(jsonStr, ".anchorUpdateNr");
        data.isDepositAnchor = vm.parseJsonBool(jsonStr, ".isDepositAnchor");
        data.txAnchor = bytes32(vm.parseJsonUint(jsonStr, ".txAnchor"));
        data.blobAnchor = bytes32(vm.parseJsonUint(jsonStr, ".blobAnchor"));
        data.ethKey = vm.parseJsonUint(jsonStr, ".ethKey");

        // Parse ZK proof
        data.pA[0] = vm.parseJsonUint(jsonStr, ".proof._pA[0]");
        data.pA[1] = vm.parseJsonUint(jsonStr, ".proof._pA[1]");
        data.pB[0][0] = vm.parseJsonUint(jsonStr, ".proof._pB[0][0]");
        data.pB[0][1] = vm.parseJsonUint(jsonStr, ".proof._pB[0][1]");
        data.pB[1][0] = vm.parseJsonUint(jsonStr, ".proof._pB[1][0]");
        data.pB[1][1] = vm.parseJsonUint(jsonStr, ".proof._pB[1][1]");
        data.pC[0] = vm.parseJsonUint(jsonStr, ".proof._pC[0]");
        data.pC[1] = vm.parseJsonUint(jsonStr, ".proof._pC[1]");

        // Parse memory positions
        data.txMemoryAddress = vm.parseJsonUint(jsonStr, ".txMemoryAddress");
        data.depositsMemoryLength = vm.parseJsonUint(jsonStr, ".depositsMemoryLength");

        // Parse region split info (for cross-blob)
        data.regionLength = vm.parseJsonUint(jsonStr, ".regionLength");
        data.extensionRegionLength = vm.parseJsonUint(jsonStr, ".extensionRegionLength");
        data.extensionRegionMemoryAddress = vm.parseJsonUint(jsonStr, ".extensionRegionMemoryAddress");

        // Parse anchor before target block
        data.anchorBeforeTargetBlock = bytes32(vm.parseJsonUint(jsonStr, ".anchorBeforeTargetBlock"));

        // Parse transaction region (14 elements)
        data.txRegion = new bytes32[](14);
        for (uint256 i = 0; i < 14; i++) {
            string memory key = string(abi.encodePacked(".targetBlock.txRegion[", vm.toString(i), "]"));
            data.txRegion[i] = bytes32(vm.parseJsonUint(jsonStr, key));
        }

        // Parse blob data
        uint256 blobDataLength = data.depositsMemoryLength + 14; // deposits + tx region
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

        // Parse prior anchor KZG proof data from binary file
        string memory priorKzgBinaryPath = vm.parseJsonString(jsonStr, ".priorAnchorKzgBinaryPath");
        bytes memory priorKzgBinary = vm.readFileBinary(priorKzgBinaryPath);
        KzgProofData memory priorKzgData = abi.decode(priorKzgBinary, (KzgProofData));

        data.priorAnchorCommitment = priorKzgData.commitment;
        data.priorAnchorBlobHash = priorKzgData.hash;
        data.priorAnchorClaim = priorKzgData.claims[0]; // Only one claim for prior anchor
        data.priorAnchorProof = priorKzgData.proofs[0]; // Only one proof for prior anchor
        data.priorAnchorMemoryPosition = vm.parseJsonUint(jsonStr, ".priorAnchorMemoryPosition");
    }

    /// @notice Generate test data via FFI
    function _generateTestData() internal {
        string[] memory cmd = new string[](2);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, testData);
        testDataGenerated = true;
    }

    /// @notice Generate fraud test data via FFI
    function _generateFraudTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";
        cmd[2] = "--fraud";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, fraudTestData);
        fraudTestDataGenerated = true;
    }

    /// @notice Generate unregistered eth key test data via FFI
    function _generateUnregisteredTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";
        cmd[2] = "--unregistered";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, unregisteredTestData);
        unregisteredTestDataGenerated = true;
    }

    /// @notice Generate cross-blob test data via FFI
    function _generateCrossblobTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";
        cmd[2] = "--crossblob";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, crossblobTestData);
        crossblobTestDataGenerated = true;
    }

    /// @notice Generate cross-blob fraud test data via FFI
    function _generateCrossblobFraudTestData() internal {
        string[] memory cmd = new string[](4);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";
        cmd[2] = "--crossblob";
        cmd[3] = "--fraud";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, crossblobFraudTestData);
        crossblobFraudTestDataGenerated = true;
    }

    /// @notice Generate multi-tx test data via FFI
    function _generateMultiTxTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";
        cmd[2] = "--multi-tx";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, multiTxTestData);
        multiTxTestDataGenerated = true;
    }

    /// @notice Generate deposit anchor reference test data via FFI
    function _generateDepositAnchorTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";
        cmd[2] = "--deposit-anchor";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, depositAnchorTestData);
        depositAnchorTestDataGenerated = true;
    }

    /// @notice Generate same-block anchor reference test data via FFI
    function _generateSameBlockTestData() internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "node";
        cmd[1] = "script/generateTransactionChallengeTestData.js";
        cmd[2] = "--same-block";

        bytes memory pathBytes = vm.ffi(cmd);
        string memory jsonStr = vm.readFile(string(pathBytes));
        _parseTestDataFromJson(jsonStr, sameBlockTestData);
        sameBlockTestDataGenerated = true;
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

        // Verify tree index formula
        uint256 expectedTreeIndex = testData.targetDay * BLOCKS_PER_DAY + testData.targetBlockIdx;
        assertEq(testData.targetTreeIndex, expectedTreeIndex, "Tree index formula");
    }

    /// @notice Verify genesis anchor is non-zero
    function test_GenesisAnchor_IsNonZero() public view {
        require(testDataGenerated, "Test data not generated");
        assertTrue(testData.genesisAnchor != bytes32(0), "Genesis anchor should be non-zero");
    }

    /// @notice Verify transaction region has 14 elements
    function test_TxRegion_Has14Elements() public view {
        require(testDataGenerated, "Test data not generated");
        assertEq(testData.txRegion.length, 14, "Transaction region should have 14 elements");
    }

    /// @notice Verify KZG proof data exists
    function test_KzgProofData_IsValid() public view {
        require(testDataGenerated, "Test data not generated");

        assertTrue(testData.kzgCommitment.length > 0, "KZG commitment should exist");
        assertEq(testData.kzgProofs.length, 14, "Should have 14 KZG proofs for tx region");
        assertEq(testData.kzgClaims.length, 14, "Should have 14 KZG claims");
        assertTrue(testData.kzgBlobHash != bytes32(0), "KZG blob hash should exist");
    }

    // ============================================================================
    // Helper Functions for Full Integration Tests
    // ============================================================================

    /// @notice Create harness with real ZK verifier and fund sequencer
    function _createRealHarness(TxChallengeTestData storage data)
        internal
        returns (TransactionChallengeRealHarness harness)
    {
        harness = new TransactionChallengeRealHarness(
            data.genesisAnchor,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(fakeUpdateVerifier)),
            ITransferVerifier(address(realTransferVerifier)),
            ITransactionRegistry(address(txRegistry))
        );
        harness.fundSequencer{value: 20 ether}(sequencer);
    }

    /// @notice Build up state by adding all blocks before target
    function _buildBlockChain(
        TransactionChallengeRealHarness harness,
        TxChallengeTestData storage data,
        uint256 startTime
    ) internal returns (uint256 targetBlockArrayIndex, Spine.BlockData[] memory storedBlocks) {
        uint256 SECONDS_PER_DAY = 86400;
        targetBlockArrayIndex = data.targetDay * 5 + data.targetBlockIdx;
        storedBlocks = new Spine.BlockData[](targetBlockArrayIndex);

        // Calculate if blocks need 2 blob hashes
        // Formula: numDepositGroups * 4 + numTransactions * 15 > 4096
        uint256 numDepositGroups = (data.targetNumDeposits + 2) / 3; // ceil(deposits/3)
        uint256 blobElements = numDepositGroups * 4 + data.targetNumTx * 15;
        bool needsTwoBlobs = blobElements > 4096;

        for (uint256 i = 0; i < targetBlockArrayIndex; i++) {
            uint256 day = i / 5;
            uint256 blockIdx = i % 5;

            vm.warp(startTime + day * SECONDS_PER_DAY + blockIdx * 100);

            bytes32[] memory blobHashes;
            uint256[] memory blockIndices;

            if (needsTwoBlobs) {
                // Cross-blob config: 273 tx + 6 deposits = 4103 elements > 4096
                // Need 2 blob hashes for each prior block
                blobHashes = new bytes32[](2);
                blockIndices = new uint256[](2);

                if (!data.sameBlockMode && i == data.anchorBlockNr) {
                    blobHashes[0] = data.priorAnchorBlobHash;
                } else {
                    blobHashes[0] = keccak256(abi.encodePacked("fake_blob_", i, "_1"));
                }
                blobHashes[1] = keccak256(abi.encodePacked("fake_blob_", i, "_2"));
                blockIndices[0] = 0;
                blockIndices[1] = 1;
            } else {
                // Single blob is sufficient
                blobHashes = new bytes32[](1);
                blockIndices = new uint256[](1);

                if (!data.sameBlockMode && i == data.anchorBlockNr) {
                    blobHashes[0] = data.priorAnchorBlobHash;
                } else {
                    blobHashes[0] = keccak256(abi.encodePacked("fake_blob_", i));
                }
                blockIndices[0] = 0;
            }

            vm.blobhashes(blobHashes);

            Spine.BlockData memory blockData = Spine.BlockData({
                anchor: data.blockAnchors[i],
                timestamp: 0,
                numTransactions: data.targetNumTx, // Use dynamic value from config
                numDeposits: data.targetNumDeposits, // Use dynamic value from config
                blockNr: 0,
                blockIndex: Spine.TimestampAndIndex(uint16(day), uint16(blockIdx)),
                sequencer: sequencer,
                blobhashes: blobHashes
            });

            vm.prank(sequencer);
            storedBlocks[i] = harness.addBlockTest(blockData, blockIndices);
        }
    }

    /// @notice Add target block with real KZG blob hash
    function _addTargetBlock(
        TransactionChallengeRealHarness harness,
        TxChallengeTestData storage data,
        uint256 startTime
    ) internal returns (Spine.BlockData memory targetBlockData) {
        uint256 SECONDS_PER_DAY = 86400;

        vm.warp(startTime + data.targetDay * SECONDS_PER_DAY + data.targetBlockIdx * 100);

        bytes32[] memory realBlobHashes = new bytes32[](1);
        realBlobHashes[0] = data.kzgBlobHash;
        vm.blobhashes(realBlobHashes);

        targetBlockData = Spine.BlockData({
            anchor: data.targetFinalAnchor,
            timestamp: 0,
            numTransactions: data.targetNumTx,
            numDeposits: data.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(uint16(data.targetDay), uint16(data.targetBlockIdx)),
            sequencer: sequencer,
            blobhashes: realBlobHashes
        });

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);
    }

    /// @notice Build challenge region from KZG proofs for transaction
    function _buildTxChallengeRegion(TxChallengeTestData storage data)
        internal
        view
        returns (BlobData.Region memory region, BlobData.Region memory emptyRegion)
    {
        bytes32[] memory regionData = new bytes32[](14);
        bytes[] memory regionProofs = new bytes[](14);

        for (uint256 i = 0; i < 14; i++) {
            regionData[i] = data.kzgClaims[i];
            regionProofs[i] = data.kzgProofs[i];
        }

        region = BlobData.Region({
            length: 14,
            memoryAddress: data.txMemoryAddress,
            data: regionData,
            proofs: regionProofs,
            commitment: data.kzgCommitment,
            hash: data.kzgBlobHash
        });

        emptyRegion = BlobData.Region({
            length: 0,
            memoryAddress: 0,
            data: new bytes32[](0),
            proofs: new bytes[](0),
            commitment: "",
            hash: bytes32(0)
        });
    }

    /// @notice Build cross-blob challenge regions (region from blob 1, extensionRegion from blob 2)
    function _buildCrossblobChallengeRegions(TxChallengeTestData storage data)
        internal
        view
        returns (BlobData.Region memory region, BlobData.Region memory extensionRegion)
    {
        // Build region from blob 1 (partial tx data at end of blob)
        bytes32[] memory regionData = new bytes32[](data.regionLength);
        bytes[] memory regionProofs = new bytes[](data.regionLength);

        for (uint256 i = 0; i < data.regionLength; i++) {
            regionData[i] = data.kzgClaims[i];
            regionProofs[i] = data.kzgProofs[i];
        }

        region = BlobData.Region({
            length: data.regionLength,
            memoryAddress: data.txMemoryAddress,
            data: regionData,
            proofs: regionProofs,
            commitment: data.kzgCommitment,
            hash: data.kzgBlobHash
        });

        // Build extensionRegion from blob 2 (remaining tx data at start of blob)
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
    }

    /// @notice Add target block with TWO blob hashes (for cross-blob tests)
    function _addTargetBlockCrossblob(
        TransactionChallengeRealHarness harness,
        TxChallengeTestData storage data,
        uint256 startTime
    ) internal returns (Spine.BlockData memory targetBlockData) {
        uint256 SECONDS_PER_DAY = 86400;

        vm.warp(startTime + data.targetDay * SECONDS_PER_DAY + data.targetBlockIdx * 100);

        // Two blob hashes for cross-blob scenario
        bytes32[] memory realBlobHashes = new bytes32[](2);
        realBlobHashes[0] = data.kzgBlobHash;
        realBlobHashes[1] = data.extensionKzgBlobHash;
        vm.blobhashes(realBlobHashes);

        targetBlockData = Spine.BlockData({
            anchor: data.targetFinalAnchor,
            timestamp: 0,
            numTransactions: data.targetNumTx,
            numDeposits: data.targetNumDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(uint16(data.targetDay), uint16(data.targetBlockIdx)),
            sequencer: sequencer,
            blobhashes: realBlobHashes
        });

        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;

        vm.prank(sequencer);
        targetBlockData = harness.addBlockTest(targetBlockData, indices);
    }

    // ============================================================================
    // Full Integration Test - No Fraud (zkSNARK-only transaction)
    // ============================================================================

    /// @notice Test valid zkSNARK-only transaction with real ZK and KZG proofs
    /// This tests the case where ethKey == 0, so only the ZK proof needs to be valid
    function test_FullIntegration_RealZkAndKzg_NoFraud() public {
        require(testDataGenerated, "Test data not generated");
        require(!testData.fraudMode, "Should not be in fraud mode");
        require(testData.ethKey == 0, "Should be zkSNARK-only (ethKey == 0)");

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(testData);
        uint256 startTime = block.timestamp;
        (uint256 targetBlockArrayIndex, Spine.BlockData[] memory storedBlocks) =
            _buildBlockChain(harness, testData, startTime);

        // Add target block with real KZG blob hash
        Spine.BlockData memory targetBlockData = _addTargetBlock(harness, testData, startTime);

        // Verify block was added at correct position
        assertEq(targetBlockData.blockNr, targetBlockArrayIndex, "Block number should match");

        // Build challenge region with real KZG proofs
        (BlobData.Region memory region, BlobData.Region memory emptyRegion) = _buildTxChallengeRegion(testData);

        // Get the prior anchor block data
        Spine.BlockData memory priorAnchorBlock = storedBlocks[testData.anchorBlockNr];

        // For zkSNARK-only transactions (ethKey == 0), if the ZK proof is valid,
        // the challenge should revert because there's no fraud path
        // (contract checks ethKey != address(0) to require registry check)
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert(); // Reverts because ethKey == 0 means no fraud possible with valid ZK
        harness.challengeTxZK(
            targetBlockData,
            testData.targetTxNr,
            region,
            emptyRegion,
            testData.txAnchor,
            priorAnchorBlock,
            testData.priorAnchorCommitment,
            testData.priorAnchorProof,
            rollbackTarget
        );

        // Verify sequencer is still active
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    // ============================================================================
    // Full Integration Test - Fraud (Invalid ZK Proof due to wrong anchor)
    // ============================================================================

    /// @notice Test fraud detection when blob contains wrong anchor
    /// The ZK proof is valid for the correct anchor, but the blob contains a different anchor
    function test_FullIntegration_RealZkAndKzg_Fraud_WrongAnchor() public {
        // Generate fraud test data
        _generateFraudTestData();
        require(fraudTestDataGenerated, "Fraud test data not generated");
        require(fraudTestData.fraudMode, "Should be in fraud mode");

        // In fraud mode, txAnchor (what ZK proves) != blobAnchor (what's in blob)
        assertTrue(
            fraudTestData.txAnchor != fraudTestData.blobAnchor, "Fraud: blob anchor should differ from ZK anchor"
        );

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(fraudTestData);
        uint256 startTime = block.timestamp;
        (uint256 targetBlockArrayIndex, Spine.BlockData[] memory storedBlocks) =
            _buildBlockChain(harness, fraudTestData, startTime);

        // Add target block with real KZG blob hash
        Spine.BlockData memory targetBlockData = _addTargetBlock(harness, fraudTestData, startTime);

        // Build challenge region
        (BlobData.Region memory region, BlobData.Region memory emptyRegion) = _buildTxChallengeRegion(fraudTestData);

        // Get prior anchor block
        Spine.BlockData memory priorAnchorBlock = storedBlocks[fraudTestData.anchorBlockNr];

        // Debug: Check blob hash in prior anchor block
        console.log("Anchor block nr:", fraudTestData.anchorBlockNr);
        console.log("Prior anchor blob hash in stored block:");
        console.logBytes32(priorAnchorBlock.blobhashes[0]);
        console.log("Expected prior anchor blob hash:");
        console.logBytes32(fraudTestData.priorAnchorBlobHash);
        console.log("Prior anchor memory position:", fraudTestData.priorAnchorMemoryPosition);

        // Capture sequencer state before
        (bool isActiveBefore,,,,, uint64 stakeBefore,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before");
        assertTrue(stakeBefore > 0, "Sequencer should have stake before");

        // Rollback target is the block before the fraudulent block
        Spine.BlockData memory rollbackTarget = storedBlocks[targetBlockArrayIndex - 1];

        // Challenge should succeed - ZK proof verification will fail because
        // the anchor in the blob (blobAnchor) doesn't match the anchor the ZK proof was generated for (txAnchor)
        // The challenger provides blobAnchor - the anchor that IS in the blob
        vm.prank(challenger);
        harness.challengeTxZK(
            targetBlockData,
            fraudTestData.targetTxNr,
            region,
            emptyRegion,
            fraudTestData.blobAnchor, // Challenger provides the anchor that's in the blob
            priorAnchorBlock,
            fraudTestData.priorAnchorCommitment,
            fraudTestData.priorAnchorProof,
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
    // Full Integration Test - Fraud (Unregistered Eth Key Transaction)
    // ============================================================================

    /// @notice Test fraud detection for unregistered eth-keyed transaction
    /// The ZK proof is valid, but the eth key is not registered in the transaction registry
    function test_FullIntegration_RealZkAndKzg_Fraud_UnregisteredEthKey() public {
        // Generate unregistered test data
        _generateUnregisteredTestData();
        require(unregisteredTestDataGenerated, "Unregistered test data not generated");
        require(unregisteredTestData.unregisteredMode, "Should be in unregistered mode");
        require(unregisteredTestData.ethKey != 0, "Should have non-zero ethKey");

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(unregisteredTestData);
        uint256 startTime = block.timestamp;
        (uint256 targetBlockArrayIndex, Spine.BlockData[] memory storedBlocks) =
            _buildBlockChain(harness, unregisteredTestData, startTime);

        // Add target block
        Spine.BlockData memory targetBlockData = _addTargetBlock(harness, unregisteredTestData, startTime);

        // Build challenge region
        (BlobData.Region memory region, BlobData.Region memory emptyRegion) =
            _buildTxChallengeRegion(unregisteredTestData);

        // Get prior anchor block
        Spine.BlockData memory priorAnchorBlock = storedBlocks[unregisteredTestData.anchorBlockNr];

        // Configure registry to return false (unregistered)
        txRegistry.setDefaultReturn(false);

        // Capture state before
        (bool isActiveBefore,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before");

        // Rollback target
        Spine.BlockData memory rollbackTarget = storedBlocks[targetBlockArrayIndex - 1];

        // Challenge should succeed because ethKey != 0 but not registered
        vm.prank(challenger);
        harness.challengeTxZK(
            targetBlockData,
            unregisteredTestData.targetTxNr,
            region,
            emptyRegion,
            unregisteredTestData.txAnchor,
            priorAnchorBlock,
            unregisteredTestData.priorAnchorCommitment,
            unregisteredTestData.priorAnchorProof,
            rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActiveAfter,,,,,, address payable challengerAfter) =
            harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed");
        assertEq(challengerAfter, challenger, "Challenger should be recorded");
    }

    // ============================================================================
    // No Fraud Test - Registered Eth Key Transaction
    // ============================================================================

    /// @notice Test that registered eth-keyed transaction cannot be challenged
    function test_FullIntegration_RealZkAndKzg_NoFraud_RegisteredEthKey() public {
        // Generate unregistered test data but configure registry to return true
        _generateUnregisteredTestData();
        require(unregisteredTestDataGenerated, "Test data not generated");
        require(unregisteredTestData.ethKey != 0, "Should have non-zero ethKey");

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(unregisteredTestData);
        uint256 startTime = block.timestamp;
        (, Spine.BlockData[] memory storedBlocks) = _buildBlockChain(harness, unregisteredTestData, startTime);

        // Add target block
        Spine.BlockData memory targetBlockData = _addTargetBlock(harness, unregisteredTestData, startTime);

        // Build challenge region
        (BlobData.Region memory region, BlobData.Region memory emptyRegion) =
            _buildTxChallengeRegion(unregisteredTestData);

        // Get prior anchor block
        Spine.BlockData memory priorAnchorBlock = storedBlocks[unregisteredTestData.anchorBlockNr];

        // Configure registry to return TRUE (registered)
        txRegistry.setDefaultReturn(true);

        Spine.BlockData memory rollbackTarget;

        // Challenge should revert with "No Fraud" because tx is properly registered
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTxZK(
            targetBlockData,
            unregisteredTestData.targetTxNr,
            region,
            emptyRegion,
            unregisteredTestData.txAnchor,
            priorAnchorBlock,
            unregisteredTestData.priorAnchorCommitment,
            unregisteredTestData.priorAnchorProof,
            rollbackTarget
        );

        // Verify sequencer is still active
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    // ============================================================================
    // Cross-Blob Integration Test - Transaction spanning blob boundary
    // ============================================================================

    /// @notice Test transaction that spans two blobs using extension regions
    /// This tests the cross-blob code path where:
    ///   - region contains the first part of the tx (in blob 1, at position 4088-4095)
    ///   - extensionRegion contains the rest (in blob 2, at position 0-5)
    ///   - Both regions use real KZG proofs
    function test_FullIntegration_RealZkAndKzg_CrossBlob_NoFraud() public {
        // Generate cross-blob test data
        _generateCrossblobTestData();
        require(crossblobTestDataGenerated, "Cross-blob test data not generated");
        require(crossblobTestData.crossblobMode, "Should be in cross-blob mode");
        require(crossblobTestData.extensionRegionLength > 0, "Should have extension region");

        // Verify the split is correct
        assertEq(
            crossblobTestData.regionLength + crossblobTestData.extensionRegionLength,
            14,
            "Region + extension should equal 14"
        );
        assertTrue(crossblobTestData.txMemoryAddress >= 4082, "TX should start near blob boundary");

        emit log_named_uint("Region length", crossblobTestData.regionLength);
        emit log_named_uint("Extension region length", crossblobTestData.extensionRegionLength);
        emit log_named_uint("TX memory address", crossblobTestData.txMemoryAddress);

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(crossblobTestData);
        uint256 startTime = block.timestamp;
        (, Spine.BlockData[] memory storedBlocks) = _buildBlockChain(harness, crossblobTestData, startTime);

        // Add target block with TWO blob hashes
        Spine.BlockData memory targetBlockData = _addTargetBlockCrossblob(harness, crossblobTestData, startTime);

        // Build cross-blob challenge regions
        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildCrossblobChallengeRegions(crossblobTestData);

        // Verify regions are properly constructed
        assertEq(region.length, crossblobTestData.regionLength, "Region length mismatch");
        assertEq(extensionRegion.length, crossblobTestData.extensionRegionLength, "Extension length mismatch");
        assertEq(extensionRegion.memoryAddress, 0, "Extension should start at 0");

        // Get prior anchor block
        Spine.BlockData memory priorAnchorBlock = storedBlocks[crossblobTestData.anchorBlockNr];

        // For zkSNARK-only transactions (ethKey == 0), if the ZK proof is valid,
        // the challenge should revert because there's no fraud path
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert(); // Reverts because ethKey == 0 means no fraud possible with valid ZK
        harness.challengeTxZK(
            targetBlockData,
            crossblobTestData.targetTxNr,
            region,
            extensionRegion, // This is the key difference - non-empty extension region
            crossblobTestData.txAnchor,
            priorAnchorBlock,
            crossblobTestData.priorAnchorCommitment,
            crossblobTestData.priorAnchorProof,
            rollbackTarget
        );

        // Verify sequencer is still active
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    // ============================================================================
    // Cross-Blob Fraud Integration Test - Wrong anchor in prior block
    // ============================================================================

    /// @notice Test fraud detection for cross-blob transaction with wrong anchor
    /// The transaction spans two blobs (blob boundary at position 4096).
    /// The fraud is in the prior anchor block - the blob contains a different anchor
    /// than what the ZK proof was generated for.
    function test_FullIntegration_RealZkAndKzg_CrossBlob_Fraud_WrongAnchor() public {
        // Generate cross-blob fraud test data
        _generateCrossblobFraudTestData();
        require(crossblobFraudTestDataGenerated, "Cross-blob fraud test data not generated");
        require(crossblobFraudTestData.crossblobMode, "Should be in cross-blob mode");
        require(crossblobFraudTestData.fraudMode, "Should be in fraud mode");
        require(crossblobFraudTestData.extensionRegionLength > 0, "Should have extension region");

        // In fraud mode, txAnchor (what ZK proves) != blobAnchor (what's in blob)
        assertTrue(
            crossblobFraudTestData.txAnchor != crossblobFraudTestData.blobAnchor,
            "Fraud: blob anchor should differ from ZK anchor"
        );

        // Verify the split is correct
        assertEq(
            crossblobFraudTestData.regionLength + crossblobFraudTestData.extensionRegionLength,
            14,
            "Region + extension should equal 14"
        );

        emit log_named_uint("Region length", crossblobFraudTestData.regionLength);
        emit log_named_uint("Extension region length", crossblobFraudTestData.extensionRegionLength);
        emit log_named_uint("TX memory address", crossblobFraudTestData.txMemoryAddress);

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(crossblobFraudTestData);
        uint256 startTime = block.timestamp;
        (uint256 targetBlockArrayIndex, Spine.BlockData[] memory storedBlocks) =
            _buildBlockChain(harness, crossblobFraudTestData, startTime);

        // Add target block with TWO blob hashes
        Spine.BlockData memory targetBlockData = _addTargetBlockCrossblob(harness, crossblobFraudTestData, startTime);

        // Build cross-blob challenge regions
        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildCrossblobChallengeRegions(crossblobFraudTestData);

        // Verify regions are properly constructed
        assertEq(region.length, crossblobFraudTestData.regionLength, "Region length mismatch");
        assertEq(extensionRegion.length, crossblobFraudTestData.extensionRegionLength, "Extension length mismatch");
        assertEq(extensionRegion.memoryAddress, 0, "Extension should start at 0");

        // Get prior anchor block
        Spine.BlockData memory priorAnchorBlock = storedBlocks[crossblobFraudTestData.anchorBlockNr];

        // Capture sequencer state before
        (bool isActiveBefore,,,,, uint64 stakeBefore,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before");
        assertTrue(stakeBefore > 0, "Sequencer should have stake before");

        // Rollback target is the block before the fraudulent block
        Spine.BlockData memory rollbackTarget = storedBlocks[targetBlockArrayIndex - 1];

        // Challenge should succeed - ZK proof verification will fail because
        // the anchor in the blob (blobAnchor) doesn't match the anchor the ZK proof was generated for (txAnchor)
        // The challenger provides blobAnchor - the anchor that IS in the blob
        vm.prank(challenger);
        harness.challengeTxZK(
            targetBlockData,
            crossblobFraudTestData.targetTxNr,
            region,
            extensionRegion, // Cross-blob: non-empty extension region
            crossblobFraudTestData.blobAnchor, // Challenger provides the anchor that's in the blob
            priorAnchorBlock,
            crossblobFraudTestData.priorAnchorCommitment,
            crossblobFraudTestData.priorAnchorProof,
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
    // Multi-Transaction Test - Challenge mid-block transaction
    // ============================================================================

    /// @notice Test challenge of transaction 3 in a block with 5 transactions
    /// This verifies the contract correctly handles blocks with multiple transactions
    /// and can challenge any transaction by index, not just the first one
    function test_FullIntegration_MultiTx_ChallengeMidBlockTx() public {
        // Generate multi-tx test data
        _generateMultiTxTestData();
        require(multiTxTestDataGenerated, "Multi-tx test data not generated");
        require(multiTxTestData.multiTxMode, "Should be in multi-tx mode");
        require(multiTxTestData.targetNumTx == 5, "Should have 5 transactions per block");
        require(multiTxTestData.targetTxNr == 3, "Should target transaction 3");

        emit log_named_uint("Target TX number", multiTxTestData.targetTxNr);
        emit log_named_uint("Transactions per block", multiTxTestData.targetNumTx);
        emit log_named_uint("TX memory address", multiTxTestData.txMemoryAddress);

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(multiTxTestData);
        uint256 startTime = block.timestamp;
        (, Spine.BlockData[] memory storedBlocks) = _buildBlockChain(harness, multiTxTestData, startTime);

        // Add target block with real KZG blob hash
        Spine.BlockData memory targetBlockData = _addTargetBlock(harness, multiTxTestData, startTime);

        // Build challenge region with real KZG proofs
        (BlobData.Region memory region, BlobData.Region memory emptyRegion) = _buildTxChallengeRegion(multiTxTestData);

        // Get the prior anchor block data
        Spine.BlockData memory priorAnchorBlock = storedBlocks[multiTxTestData.anchorBlockNr];

        // For zkSNARK-only transactions (ethKey == 0), if the ZK proof is valid,
        // the challenge should revert because there's no fraud path
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert(); // Reverts because ethKey == 0 means no fraud possible with valid ZK
        harness.challengeTxZK(
            targetBlockData,
            multiTxTestData.targetTxNr,
            region,
            emptyRegion,
            multiTxTestData.txAnchor,
            priorAnchorBlock,
            multiTxTestData.priorAnchorCommitment,
            multiTxTestData.priorAnchorProof,
            rollbackTarget
        );

        // Verify sequencer is still active
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    // ============================================================================
    // Deposit Anchor Reference Test
    // ============================================================================

    /// @notice Test transaction that references a deposit anchor instead of transaction anchor
    /// This verifies the contract correctly handles isDepositAnchor=true
    function test_FullIntegration_DepositAnchorReference() public {
        // Generate deposit anchor test data
        _generateDepositAnchorTestData();
        require(depositAnchorTestDataGenerated, "Deposit anchor test data not generated");
        require(depositAnchorTestData.depositAnchorMode, "Should be in deposit anchor mode");
        require(depositAnchorTestData.isDepositAnchor, "isDepositAnchor should be true");

        emit log_named_uint("Anchor update nr (deposit group)", depositAnchorTestData.anchorUpdateNr);
        emit log_named_uint("Prior anchor memory position", depositAnchorTestData.priorAnchorMemoryPosition);

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(depositAnchorTestData);
        uint256 startTime = block.timestamp;
        (, Spine.BlockData[] memory storedBlocks) = _buildBlockChain(harness, depositAnchorTestData, startTime);

        // Add target block with real KZG blob hash
        Spine.BlockData memory targetBlockData = _addTargetBlock(harness, depositAnchorTestData, startTime);

        // Build challenge region with real KZG proofs
        (BlobData.Region memory region, BlobData.Region memory emptyRegion) =
            _buildTxChallengeRegion(depositAnchorTestData);

        // Get the prior anchor block data
        Spine.BlockData memory priorAnchorBlock = storedBlocks[depositAnchorTestData.anchorBlockNr];

        // For zkSNARK-only transactions, challenge should revert with no fraud
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert(); // Reverts because valid ZK proof with ethKey == 0
        harness.challengeTxZK(
            targetBlockData,
            depositAnchorTestData.targetTxNr,
            region,
            emptyRegion,
            depositAnchorTestData.txAnchor,
            priorAnchorBlock,
            depositAnchorTestData.priorAnchorCommitment,
            depositAnchorTestData.priorAnchorProof,
            rollbackTarget
        );

        // Verify sequencer is still active
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    // ============================================================================
    // Same-Block Anchor Reference Test
    // ============================================================================

    /// @notice Test transaction that references an anchor from an earlier update in the SAME block
    /// This verifies the contract correctly handles same-block anchor references
    /// where anchorBlockNr == targetBlockNr
    function test_FullIntegration_SameBlockAnchorReference() public {
        // Generate same-block test data
        _generateSameBlockTestData();
        require(sameBlockTestDataGenerated, "Same-block test data not generated");
        require(sameBlockTestData.sameBlockMode, "Should be in same-block mode");
        require(sameBlockTestData.targetNumTx == 5, "Should have 5 transactions per block");
        require(sameBlockTestData.targetTxNr == 4, "Should target transaction 4");

        emit log_named_uint("Target TX number", sameBlockTestData.targetTxNr);
        emit log_named_uint("Anchor block nr", sameBlockTestData.anchorBlockNr);
        emit log_named_uint("Anchor update nr (tx in same block)", sameBlockTestData.anchorUpdateNr);
        emit log_named_uint("Prior anchor memory position", sameBlockTestData.priorAnchorMemoryPosition);

        // Verify same-block reference
        uint256 targetBlockArrayIndex = sameBlockTestData.targetDay * 5 + sameBlockTestData.targetBlockIdx;
        assertEq(sameBlockTestData.anchorBlockNr, targetBlockArrayIndex, "Anchor should be in same block as target");

        // Create harness and build block chain
        TransactionChallengeRealHarness harness = _createRealHarness(sameBlockTestData);
        uint256 startTime = block.timestamp;
        _buildBlockChain(harness, sameBlockTestData, startTime);

        // Add target block with real KZG blob hash
        // For same-block mode, the prior anchor KZG proof comes from THIS blob
        Spine.BlockData memory targetBlockData = _addTargetBlock(harness, sameBlockTestData, startTime);

        // Build challenge region with real KZG proofs
        (BlobData.Region memory region, BlobData.Region memory emptyRegion) = _buildTxChallengeRegion(sameBlockTestData);

        // For same-block mode, the priorAnchorBlock IS the targetBlock
        // But we pass the stored target block data
        // The key difference is that the prior anchor KZG proof comes from the same blob

        // For zkSNARK-only transactions, challenge should revert with no fraud
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert(); // Reverts because valid ZK proof with ethKey == 0
        harness.challengeTxZK(
            targetBlockData,
            sameBlockTestData.targetTxNr,
            region,
            emptyRegion,
            sameBlockTestData.txAnchor,
            targetBlockData, // Same block as target!
            sameBlockTestData.priorAnchorCommitment,
            sameBlockTestData.priorAnchorProof,
            rollbackTarget
        );

        // Verify sequencer is still active
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }
}

// ============================================================================
// Test Harness with REAL KZG blob validation
// ============================================================================

/// @notice Integration test harness using real KZG blob validation
contract TransactionChallengeRealHarness is TransactionChallenge {
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
