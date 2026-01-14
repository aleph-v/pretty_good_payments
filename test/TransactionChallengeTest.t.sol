// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/TransactionChallenge.sol";
import "../src/Spine.sol";
import "./mocks/FakeBlobs.sol";
import "./mocks/FakeZk.sol";
import "./mocks/MockYieldRouter.sol";
import "./mocks/ConfigurableTxRegistry.sol";

/// @notice Harness contract that exposes internal functions and provides FakeBlobs storage
contract TransactionChallengeHarness is TransactionChallenge, FakeBlobs {
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

    /// @notice Override validateSingle to use FakeBlobs storage instead of KZG proofs
    function validateSingle(bytes32 rootHash, bytes calldata, uint256 index, bytes32 data, bytes calldata)
        internal
        view
        override
    {
        require(access(rootHash, index) == data, "FakeBlobs validation failed");
    }

    /// @notice Add a block and return the updated data with correct blockNr/timestamp
    function addBlockTest(BlockData memory data, uint256[] memory indices) public returns (BlockData memory) {
        addBlock(data, indices);
        return data;
    }

    /// @notice Get sequencer status for assertions
    function getSequencerStatus(address sequencer)
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
        SequencerStatus memory status = sequencers[sequencer];
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

    function getBlockCount() public view returns (uint256) {
        return getCurrentBlocknumber();
    }

    receive() external payable {}

    function fundSequencer(address who) public payable {
        sequencers[who].isActive = true;
        sequencers[who].stakeAmount += uint64(msg.value / (10 ** 14));
    }

    function setValueAt(bytes32 blobHash, uint256 logicalIndex, bytes32 value) public {
        uint256 storageIndex = bitReverse(logicalIndex);
        storeAt(blobHash, storageIndex, value);
    }

    function exposedTxMemoryAddress(uint256 txNumber, uint256 numDeposits) public pure returns (uint256) {
        return txMemoryAddress(txNumber, numDeposits);
    }

    function exposedNumDepositsToMemoryLength(uint256 num) public pure returns (uint256) {
        return numDepositsToMemoryLength(num);
    }

    function exposedPriorRootMemoryLocation(uint256 number, bool isDeposit, uint256 numDeposits)
        public
        pure
        returns (uint256)
    {
        return priorRootMemoryLocation(number, isDeposit, numDeposits);
    }

    function getGenesisAnchor() public view returns (bytes32) {
        return GENESIS_ANCHOR;
    }
}

contract TransactionChallengeTest is Test {
    TransactionChallengeHarness harness;
    FakeZK fakeZK;
    MockYieldRouter yieldRouter;
    ConfigurableTxRegistry txRegistry;

    address sequencer = address(0x1111);
    address challenger = address(0x2222);

    bytes32 constant GENESIS = keccak256("genesis");

    // Test constants - using realistic block sizes as requested
    uint256 constant TEST_NUM_DEPOSITS = 60;
    uint256 constant TEST_NUM_TRANSACTIONS = 75;

    function setUp() public {
        fakeZK = new FakeZK();
        yieldRouter = new MockYieldRouter();
        txRegistry = new ConfigurableTxRegistry();

        harness = new TransactionChallengeHarness(
            GENESIS,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(fakeZK)),
            ITransferVerifier(address(fakeZK)),
            ITransactionRegistry(address(txRegistry))
        );

        vm.deal(sequencer, 100 ether);
        vm.deal(challenger, 10 ether);
        harness.fundSequencer{value: 20 ether}(sequencer);
    }

    // ============================================================================
    // Helper functions
    // ============================================================================

    function _createBlockData(uint256 numDeposits, uint256 numTx) internal pure returns (Spine.BlockData memory) {
        return Spine.BlockData({
            anchor: bytes32(0),
            timestamp: 0,
            numTransactions: numTx,
            numDeposits: numDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(0, 0),
            sequencer: address(0),
            blobhashes: new bytes32[](0)
        });
    }

    function _createEmptyRegion() internal pure returns (BlobData.Region memory) {
        return BlobData.Region({
            length: 0,
            memoryAddress: 0,
            data: new bytes32[](0),
            proofs: new bytes[](0),
            commitment: "",
            hash: bytes32(0)
        });
    }

    function _createRegion(uint256 length, uint256 memoryAddress, bytes32[] memory data, bytes32 blobHash)
        internal
        pure
        returns (BlobData.Region memory)
    {
        bytes[] memory proofs = new bytes[](length);
        return BlobData.Region({
            length: length, memoryAddress: memoryAddress, data: data, proofs: proofs, commitment: "", hash: blobHash
        });
    }

    /// @notice Creates blob data for a block and stores it
    /// @param numDeposits Number of deposits in the block
    /// @param numTx Number of transactions in the block
    /// @param seed Random seed for generating data
    /// @return blobHashes The blob hashes created
    function _createAndStoreBlockData(uint256 numDeposits, uint256 numTx, uint256 seed)
        internal
        returns (bytes32[] memory blobHashes)
    {
        uint256 depositSize = harness.exposedNumDepositsToMemoryLength(numDeposits);
        uint256 txSize = numTx * 15;
        uint256 totalData = depositSize + txSize;
        if (totalData == 0) totalData = 1;

        bytes32[] memory allData = new bytes32[](totalData);
        for (uint256 i = 0; i < totalData; i++) {
            allData[i] = keccak256(abi.encodePacked("tx_challenge_test", seed, i));
        }
        blobHashes = harness.store(allData);
    }

    /// @notice Encodes transaction info matching the contract's encoding
    /// @dev Bit layout (shifted down 1 bit to avoid BLS modulus conflict):
    ///      - Bit 254: isDeposit
    ///      - Bits 253-222: blockNr (32 bits)
    ///      - Bits 221-190: updateNr (32 bits)
    ///      - Bits 159-0: ethAddress (160 bits, at LOW bits)
    function _encodeTxInfo(uint32 blockNr, uint32 updateNr, bool isDeposit, address ethKey)
        internal
        pure
        returns (bytes32)
    {
        bytes32 ret = isDeposit ? bytes32(uint256(1) << 254) : bytes32(uint256(0));
        ret = ret | bytes32((uint256(blockNr) << 222) + (uint256(updateNr) << 190));
        ret = ret | bytes32(uint256(uint160(ethKey)));
        return ret;
    }

    /// @notice Sets up a transaction at a specific index in blob data
    /// @param blobHashes The blob hashes to modify
    /// @param txNr The transaction number
    /// @param numDeposits The number of deposits in the block
    /// @param anchorBlockNr The block number the tx references for anchor
    /// @param anchorUpdateNr The update number the tx references
    /// @param isDepositAnchor Whether the anchor is a deposit
    /// @param ethKey The ethereum key for the transaction
    function _setupTransaction(
        bytes32[] memory blobHashes,
        uint256 txNr,
        uint256 numDeposits,
        uint32 anchorBlockNr,
        uint32 anchorUpdateNr,
        bool isDepositAnchor,
        address ethKey
    ) internal {
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, numDeposits);
        uint256 absoluteAddr = memAddr + 8; // raw[8] is where txInfo goes
        uint256 blobIndex = absoluteAddr / 4096;
        uint256 localAddr = absoluteAddr % 4096;

        bytes32 txInfo = _encodeTxInfo(anchorBlockNr, anchorUpdateNr, isDepositAnchor, ethKey);
        harness.setValueAt(blobHashes[blobIndex], localAddr, txInfo);
    }

    /// @notice Creates two blocks for multi-block tests
    function _createTwoBlocks()
        internal
        returns (
            Spine.BlockData memory block1,
            Spine.BlockData memory block2,
            bytes32[] memory blobHashes1,
            bytes32[] memory blobHashes2
        )
    {
        blobHashes1 = _createAndStoreBlockData(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 11111);
        block1 = _createBlockData(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS);
        block1.sequencer = sequencer;
        block1.blobhashes = blobHashes1;
        block1.anchor = keccak256("anchor1");

        uint256[] memory indices1 = new uint256[](blobHashes1.length);
        for (uint256 i = 0; i < blobHashes1.length; i++) {
            indices1[i] = i;
        }
        vm.blobhashes(blobHashes1);
        vm.prank(sequencer);
        block1 = harness.addBlockTest(block1, indices1);

        blobHashes2 = _createAndStoreBlockData(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 22222);
        block2 = _createBlockData(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS);
        block2.sequencer = sequencer;
        block2.blobhashes = blobHashes2;
        block2.anchor = keccak256("anchor2");

        uint256[] memory indices2 = new uint256[](blobHashes2.length);
        for (uint256 i = 0; i < blobHashes2.length; i++) {
            indices2[i] = i;
        }
        vm.blobhashes(blobHashes2);
        vm.prank(sequencer);
        block2 = harness.addBlockTest(block2, indices2);
    }

    /// @notice Creates and adds a single block to the chain
    function _createAndAddSingleBlock(uint256 numDeposits, uint256 numTx, uint256 seed, bytes32 anchor)
        internal
        returns (Spine.BlockData memory data, bytes32[] memory blobHashes)
    {
        blobHashes = _createAndStoreBlockData(numDeposits, numTx, seed);
        data = _createBlockData(numDeposits, numTx);
        data.sequencer = sequencer;
        data.blobhashes = blobHashes;
        data.anchor = anchor;

        uint256[] memory indices = new uint256[](blobHashes.length);
        for (uint256 i = 0; i < blobHashes.length; i++) {
            indices[i] = i;
        }
        vm.blobhashes(blobHashes);
        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);
    }

    /// @notice Builds a region for a transaction, handling blob boundary crossing
    function _buildTxRegion(bytes32[] memory blobHashes, uint256 txNr, uint256 numDeposits)
        internal
        view
        returns (BlobData.Region memory region, BlobData.Region memory extensionRegion)
    {
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, numDeposits);
        uint256 blobIndex = memAddr / 4096;
        uint256 localAddr = memAddr % 4096;

        if (localAddr + 14 <= 4096) {
            // No boundary crossing
            bytes32[] memory regionData = new bytes32[](14);
            for (uint256 i = 0; i < 14; i++) {
                regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
            }
            region = _createRegion(14, localAddr, regionData, blobHashes[blobIndex]);
            extensionRegion = _createEmptyRegion();
        } else {
            // Crosses blob boundary
            uint256 firstCount = 4096 - localAddr;
            uint256 secondCount = 14 - firstCount;

            bytes32[] memory regionData = new bytes32[](firstCount);
            for (uint256 i = 0; i < firstCount; i++) {
                regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
            }

            bytes32[] memory extData = new bytes32[](secondCount);
            for (uint256 i = 0; i < secondCount; i++) {
                extData[i] = harness.access(blobHashes[blobIndex + 1], i);
            }

            region = _createRegion(firstCount, localAddr, regionData, blobHashes[blobIndex]);
            extensionRegion = _createRegion(secondCount, 0, extData, blobHashes[blobIndex + 1]);
        }
    }

    /// @notice Gets the public inputs for a transaction ZK proof
    function _getTxPublicInputs(
        bytes32[] memory blobHashes,
        uint256 txNr,
        uint256 numDeposits,
        bytes32 anchor,
        address ethKey
    ) internal view returns (uint256[7] memory publicInputs) {
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, numDeposits);
        uint256 blobIndex = memAddr / 4096;
        uint256 localAddr = memAddr % 4096;

        // raw[9-13] are the public inputs (nullifiers and leaves)
        publicInputs[0] = uint256(anchor);
        publicInputs[1] = uint256(uint160(ethKey));

        for (uint256 i = 0; i < 5; i++) {
            uint256 addr = localAddr + 9 + i;
            if (addr < 4096) {
                publicInputs[2 + i] = uint256(harness.access(blobHashes[blobIndex], addr));
            } else {
                publicInputs[2 + i] = uint256(harness.access(blobHashes[blobIndex + 1], addr % 4096));
            }
        }
    }

    // ============================================================================
    // Encoding/Decoding Tests
    // ============================================================================
    //
    // Bit layout (shifted down 1 bit to avoid BLS modulus conflict for KZG blobs):
    // - Bit 254: isDeposit
    // - Bits 253-222: blockNr (32 bits)
    // - Bits 221-190: updateNr (32 bits)
    // - Bits 159-0: ethAddress (160 bits, at LOW bits)

    /// @notice Fuzz test for encoding/decoding roundtrip
    function testFuzz_EncodeDecode(uint32 blockNr, uint32 updateNr, bool isDeposit, address ethKey) public view {
        bytes32 encoded = harness.encodeTxIntoBytes32(blockNr, updateNr, isDeposit, ethKey);
        (uint256 decodedBlockNr, uint256 decodedUpdateNr, bool decodedIsDeposit, address decodedEthKey) =
            harness.decodeTxInfo(encoded);

        assertEq(decodedBlockNr, blockNr);
        assertEq(decodedUpdateNr, updateNr);
        assertEq(decodedIsDeposit, isDeposit);
        assertEq(decodedEthKey, ethKey);
    }

    // ============================================================================
    // Block Inclusion Tests
    // ============================================================================

    /// @notice Test that challenge reverts if block is not included
    function test_Challenge_RevertsIfBlockNotIncluded() public {
        bytes32[] memory blobHashes = _createAndStoreBlockData(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345);

        Spine.BlockData memory data = _createBlockData(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS);
        data.sequencer = sequencer;
        data.blobhashes = blobHashes;
        data.anchor = keccak256("some_anchor");
        // Don't add the block

        BlobData.Region memory region = _createEmptyRegion();
        region.length = 14;
        BlobData.Region memory extensionRegion = _createEmptyRegion();

        Spine.BlockData memory priorAnchorBlock;
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(data, 0, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", rollbackTarget);
    }

    // ============================================================================
    // Region Validation Tests
    // ============================================================================

    /// @notice Test that challenge reverts with zero-length region
    function test_Challenge_RevertsOnZeroLengthRegion() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        // Zero length region should fail assert
        BlobData.Region memory region = _createEmptyRegion();
        region.hash = blobHashes[0];

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(
            data, 0, region, _createEmptyRegion(), GENESIS, priorAnchorBlock, "", "", priorAnchorBlock
        );
    }

    /// @notice Test that challenge reverts if txNr >= numTransactions
    function test_Challenge_RevertsIfTxNrOutOfBounds() public {
        (Spine.BlockData memory data,) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        BlobData.Region memory region = _createEmptyRegion();
        region.length = 14;

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(
            data,
            TEST_NUM_TRANSACTIONS,
            region,
            _createEmptyRegion(),
            GENESIS,
            priorAnchorBlock,
            "",
            "",
            priorAnchorBlock
        );
    }

    /// @notice Test that challenge reverts if region blob hash doesn't match
    function test_Challenge_RevertsOnWrongBlobHash() public {
        (Spine.BlockData memory data,) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        uint256 txNr = 50;
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, TEST_NUM_DEPOSITS);

        bytes32[] memory regionData = new bytes32[](14);
        BlobData.Region memory region = _createRegion(14, memAddr % 4096, regionData, keccak256("wrong_hash"));

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(
            data, txNr, region, _createEmptyRegion(), GENESIS, priorAnchorBlock, "", "", priorAnchorBlock
        );
    }

    /// @notice Test that challenge reverts if region memory address is wrong
    function test_Challenge_RevertsOnWrongMemoryAddress() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        uint256 txNr = 50;
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, TEST_NUM_DEPOSITS);
        uint256 blobIndex = memAddr / 4096;

        bytes32[] memory regionData = new bytes32[](14);
        // Use wrong memory address (off by 1)
        BlobData.Region memory region = _createRegion(14, (memAddr % 4096) + 1, regionData, blobHashes[blobIndex]);
        BlobData.Region memory extensionRegion = _createEmptyRegion();

        Spine.BlockData memory priorAnchorBlock;
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(data, txNr, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", rollbackTarget);
    }

    /// @notice Test that challenge reverts if region + extension length != 14
    function test_Challenge_RevertsOnWrongTotalLength() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        uint256 txNr = 50;
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, TEST_NUM_DEPOSITS);
        uint256 blobIndex = memAddr / 4096;
        uint256 localAddr = memAddr % 4096;

        // Create region with only 10 elements instead of 14
        bytes32[] memory regionData = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
        }
        BlobData.Region memory region = _createRegion(10, localAddr, regionData, blobHashes[blobIndex]);

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        vm.expectRevert("Not enough data");
        harness.challengeTxZK(
            data, txNr, region, _createEmptyRegion(), GENESIS, priorAnchorBlock, "", "", priorAnchorBlock
        );
    }

    /// @notice Test that extension region with non-zero memoryAddress reverts
    function test_ExtensionRegion_NonZeroMemoryAddressReverts() public {
        uint256 numDeposits = 60;
        uint256 numTransactions = 270; // Enough to have tx cross blob boundary

        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(numDeposits, numTransactions, 12345, keccak256("anchor"));

        // Tx 267 starts at 80 + 267*15 = 4085, crosses into blob 1
        uint256 txNr = 267;
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, numDeposits);
        uint256 blobIndex = memAddr / 4096;
        uint256 localAddr = memAddr % 4096;

        uint256 elementsInFirstBlob = 4096 - localAddr;
        uint256 elementsInSecondBlob = 14 - elementsInFirstBlob;

        bytes32[] memory regionData = new bytes32[](elementsInFirstBlob);
        for (uint256 i = 0; i < elementsInFirstBlob; i++) {
            regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
        }

        bytes32[] memory extensionData = new bytes32[](elementsInSecondBlob);
        for (uint256 i = 0; i < elementsInSecondBlob; i++) {
            extensionData[i] = harness.access(blobHashes[blobIndex + 1], i);
        }

        BlobData.Region memory region = _createRegion(elementsInFirstBlob, localAddr, regionData, blobHashes[blobIndex]);
        // Extension region with WRONG memory address (should be 0, using 5 instead)
        BlobData.Region memory extensionRegion =
            _createRegion(elementsInSecondBlob, 5, extensionData, blobHashes[blobIndex + 1]);

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(data, txNr, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", priorAnchorBlock);
    }

    /// @notice Test that extension region fails if primary region doesn't end at blob boundary
    function test_ExtensionRegion_PrimaryNotAtBoundaryReverts() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        // Use a tx that does NOT cross blob boundary (tx 50 starts at ~830)
        uint256 txNr = 50;
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, TEST_NUM_DEPOSITS);
        uint256 blobIndex = memAddr / 4096;
        uint256 localAddr = memAddr % 4096;

        // Create a short primary region (10 elements) that doesn't end at 4096
        bytes32[] memory regionData = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
        }

        BlobData.Region memory region = _createRegion(10, localAddr, regionData, blobHashes[blobIndex]);
        // This should fail assert because (localAddr + 10) % 4096 != 0
        BlobData.Region memory extensionRegion = _createRegion(4, 0, new bytes32[](4), blobHashes[blobIndex]);

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(data, txNr, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", priorAnchorBlock);
    }

    // ============================================================================
    // Fraud Detection - Invalid Anchor Block Reference
    // ============================================================================

    /// @notice Test fraud when anchor references a future block (anchorBlockNr > data.blockNr)
    function test_Fraud_AnchorReferencesFutureBlock() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        // This is block 0, set tx to reference block 999 (future) - FRAUD
        uint256 txNr = 50;
        _setupTransaction(blobHashes, txNr, TEST_NUM_DEPOSITS, 999, 0, false, address(0));

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes, txNr, TEST_NUM_DEPOSITS);

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        harness.challengeTxZK(data, txNr, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", priorAnchorBlock);

        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed");
        assertEq(challengerAddr, challenger);
    }

    /// @notice Test fraud when same-block anchor references a later transaction
    function test_Fraud_SameBlockAnchorReferencesLaterTx() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        // Challenge tx 50, but set it to reference tx 60 in the same block - FRAUD (can't reference later tx)
        uint256 txNr = 50;
        _setupTransaction(blobHashes, txNr, TEST_NUM_DEPOSITS, uint32(data.blockNr), 60, false, address(0));

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes, txNr, TEST_NUM_DEPOSITS);

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        harness.challengeTxZK(data, txNr, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", priorAnchorBlock);

        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for referencing later tx");
        assertEq(challengerAddr, challenger);
    }

    /// @notice Test that same-block anchor referencing a deposit is allowed
    function test_NoFraud_SameBlockAnchorReferencesDeposit() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS, 12345, keccak256("anchor"));

        // Set tx 50 to reference a deposit in the same block (should be allowed)
        uint256 txNr = 50;
        uint32 anchorUpdateNr = 55; // A deposit index (must be < numDeposits = 60)
        _setupTransaction(blobHashes, txNr, TEST_NUM_DEPOSITS, uint32(data.blockNr), anchorUpdateNr, true, address(0));

        // Get the anchor for this deposit (deposit roots are at: (depositGroup) * 4 + 3)
        uint256 depositGroup = anchorUpdateNr / 3;
        bytes32 anchor = harness.access(blobHashes[0], depositGroup * 4 + 3);

        // Approve the ZK proof
        fakeZK.approveTransfer(_getTxPublicInputs(blobHashes, txNr, TEST_NUM_DEPOSITS, anchor, address(0)));

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes, txNr, TEST_NUM_DEPOSITS);

        // Challenge should revert - ethKey == 0 means zkSNARK-only, no fraud possible
        Spine.BlockData memory rollbackTarget;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(data, txNr, region, extensionRegion, anchor, data, "", "", rollbackTarget);
    }

    // ============================================================================
    // Challenger Validation - Prior Anchor Block
    // ============================================================================

    /// @notice Test that challenge reverts if prior anchor block is not in tree
    function test_Challenge_RevertsIfPriorAnchorBlockNotIncluded() public {
        (
            Spine.BlockData memory block1,
            Spine.BlockData memory block2,
            bytes32[] memory blobHashes1,
            bytes32[] memory blobHashes2
        ) = _createTwoBlocks();

        uint256 txNr = 50;
        uint32 anchorUpdateNr = 30;
        // Valid anchor reference to block1 - so noFraud path will check priorAnchorBlock
        _setupTransaction(
            blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, address(0)
        );

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        uint256 anchorMemoryLocation = harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, TEST_NUM_DEPOSITS);
        bytes32 anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);

        // Create a fake priorAnchorBlock that was never added to the tree
        Spine.BlockData memory fakePriorBlock = _createBlockData(TEST_NUM_DEPOSITS, TEST_NUM_TRANSACTIONS);
        fakePriorBlock.blockNr = block1.blockNr;
        fakePriorBlock.anchor = keccak256("fake_anchor");

        vm.prank(challenger);
        vm.expectRevert("Invalid anchor block info");
        harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, fakePriorBlock, "", "", block1);
    }

    /// @notice Test that challenge reverts if prior anchor block number doesn't match tx's anchor reference
    function test_Challenge_RevertsIfPriorAnchorBlockNumberMismatch() public {
        (
            Spine.BlockData memory block1,
            Spine.BlockData memory block2,
            bytes32[] memory blobHashes1,
            bytes32[] memory blobHashes2
        ) = _createTwoBlocks();

        uint256 txNr = 50;
        uint32 anchorUpdateNr = 30;
        // Tx references block1 as anchor block
        _setupTransaction(
            blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, address(0)
        );

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        uint256 anchorMemoryLocation = harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, TEST_NUM_DEPOSITS);
        bytes32 anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);

        // Pass block2 as priorAnchorBlock but tx references block1 - block number mismatch
        vm.prank(challenger);
        vm.expectRevert("Invalid anchor block info");
        harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, block2, "", "", block1);
    }

    /// @notice Test that challenge reverts if challenger provides wrong anchor value
    function test_Challenge_RevertsIfWrongAnchorValue() public {
        (Spine.BlockData memory block1, Spine.BlockData memory block2,, bytes32[] memory blobHashes2) =
            _createTwoBlocks();

        uint256 txNr = 50;
        uint32 anchorUpdateNr = 30;
        _setupTransaction(
            blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, address(0)
        );

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        // Provide a WRONG anchor value (not the actual root at anchorUpdateNr)
        bytes32 wrongAnchor = keccak256("wrong_anchor_value");

        // This should revert in validatePriorAnchor because the anchor doesn't match
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(block2, txNr, region, extensionRegion, wrongAnchor, block1, "", "", block1);
    }

    // ============================================================================
    // Fraud Detection - Invalid Anchor Update Number
    // ============================================================================

    /// @notice Test fraud when anchor references a tx number >= numTransactions
    function test_Fraud_AnchorUpdateNrOutOfBounds_Transaction() public {
        (Spine.BlockData memory block1, Spine.BlockData memory block2,, bytes32[] memory blobHashes2) =
            _createTwoBlocks();

        uint256 txNr = 50;
        // anchorUpdateNr = numTransactions is OUT OF BOUNDS (valid are 0 to numTx-1)
        _setupTransaction(
            blobHashes2,
            txNr,
            TEST_NUM_DEPOSITS,
            uint32(block1.blockNr),
            uint32(TEST_NUM_TRANSACTIONS),
            false,
            address(0)
        );

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        vm.prank(challenger);
        harness.challengeTxZK(block2, txNr, region, extensionRegion, GENESIS, block1, "", "", block1);

        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for out-of-bounds anchor update nr");
        assertEq(challengerAddr, challenger);
    }

    /// @notice Test boundary: anchor references deposit with updateNr == numDeposits (out of bounds)
    function test_Fraud_DepositAnchorOutOfBounds() public {
        (Spine.BlockData memory block1, Spine.BlockData memory block2,, bytes32[] memory blobHashes2) =
            _createTwoBlocks();

        uint256 txNr = 50;
        // anchorUpdateNr = numDeposits is OUT OF BOUNDS for deposits (valid are 0 to numDeposits-1)
        _setupTransaction(
            blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), uint32(TEST_NUM_DEPOSITS), true, address(0)
        );

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        vm.prank(challenger);
        harness.challengeTxZK(block2, txNr, region, extensionRegion, GENESIS, block1, "", "", block1);

        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed - deposit index out of bounds");
    }

    // ============================================================================
    // Fraud Detection - Invalid ZK Proof
    // ============================================================================

    /// @notice Test fraud when ZK proof is not approved
    function test_Fraud_InvalidZKProof() public {
        (
            Spine.BlockData memory block1,
            Spine.BlockData memory block2,
            bytes32[] memory blobHashes1,
            bytes32[] memory blobHashes2
        ) = _createTwoBlocks();

        uint256 txNr = 50;
        uint32 anchorUpdateNr = 30;
        _setupTransaction(
            blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, address(0)
        );

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        uint256 anchorMemoryLocation = harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, TEST_NUM_DEPOSITS);
        bytes32 anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);

        // ZK proof NOT approved - should be detected as fraud
        vm.prank(challenger);
        harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, block1, "", "", block1);

        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for invalid ZK proof");
        assertEq(challengerAddr, challenger);
    }

    // ============================================================================
    // Fraud Detection - Unauthorized Ethereum Key Transaction
    // ============================================================================

    /// @notice Test fraud when ethKey != 0 but transaction is not registered
    function test_Fraud_UnregisteredEthKeyTransaction() public {
        (
            Spine.BlockData memory block1,
            Spine.BlockData memory block2,
            bytes32[] memory blobHashes1,
            bytes32[] memory blobHashes2
        ) = _createTwoBlocks();

        uint256 txNr = 50;
        uint32 anchorUpdateNr = 30;
        address ethKey = address(0xDEADBEEF);
        _setupTransaction(blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, ethKey);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        uint256 anchorMemoryLocation = harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, TEST_NUM_DEPOSITS);
        bytes32 anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);

        // Approve ZK proof but registry returns false (unregistered)
        fakeZK.approveTransfer(_getTxPublicInputs(blobHashes2, txNr, TEST_NUM_DEPOSITS, anchor, ethKey));
        txRegistry.setDefaultReturn(false);

        vm.prank(challenger);
        harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, block1, "", "", block1);

        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for unregistered eth key transaction");
        assertEq(challengerAddr, challenger);
    }

    // ============================================================================
    // No Fraud Tests - Valid Transactions Should Not Be Slashable
    // ============================================================================

    /// @notice Test that a valid zkSNARK-only transaction cannot be challenged
    function test_NoFraud_ValidZkSnarkOnlyTransaction() public {
        (
            Spine.BlockData memory block1,
            Spine.BlockData memory block2,
            bytes32[] memory blobHashes1,
            bytes32[] memory blobHashes2
        ) = _createTwoBlocks();

        uint256 txNr = 50;
        uint32 anchorUpdateNr = 30;
        address ethKey = address(0); // zkSNARK-only
        _setupTransaction(blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, ethKey);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        uint256 anchorMemoryLocation = harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, TEST_NUM_DEPOSITS);
        bytes32 anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);

        // Approve ZK proof - valid transaction
        fakeZK.approveTransfer(_getTxPublicInputs(blobHashes2, txNr, TEST_NUM_DEPOSITS, anchor, ethKey));

        // Challenge should revert: ethKey == 0 means zkSNARK-only, no fraud possible
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, block1, "", "", block1);

        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    /// @notice Test that a valid eth-keyed transaction with proper registration cannot be challenged
    function test_NoFraud_ValidRegisteredEthKeyTransaction() public {
        (
            Spine.BlockData memory block1,
            Spine.BlockData memory block2,
            bytes32[] memory blobHashes1,
            bytes32[] memory blobHashes2
        ) = _createTwoBlocks();

        uint256 txNr = 50;
        uint32 anchorUpdateNr = 30;
        address ethKey = address(0xCAFEBABE);
        _setupTransaction(blobHashes2, txNr, TEST_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, ethKey);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        uint256 anchorMemoryLocation = harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, TEST_NUM_DEPOSITS);
        bytes32 anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);

        // Approve ZK proof and register transaction
        fakeZK.approveTransfer(_getTxPublicInputs(blobHashes2, txNr, TEST_NUM_DEPOSITS, anchor, ethKey));
        txRegistry.setDefaultReturn(true);

        // Challenge should revert with "No Fraud" - transaction is properly registered
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, block1, "", "", block1);

        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - no fraud");
    }

    // ============================================================================
    // Extension Region Tests - Blob Boundary Crossing
    // ============================================================================

    /// @notice Test transaction that crosses blob boundary
    /// @dev This tests the logic at line 52 which may have a bug in the conditional
    function test_ExtensionRegion_TxCrossesBlobBoundary() public {
        // We need enough data to have a tx cross the blob boundary
        // With 60 deposits = 80 slots, need tx that starts near 4096
        // Tx at index 267 would start at: 80 + 267*15 = 80 + 4005 = 4085
        // So elements 0-10 would be in blob 0, elements 11-14 would be in blob 1

        uint256 numDeposits = 60;
        uint256 numTransactions = 270; // Enough to cross boundary

        bytes32[] memory blobHashes1 = _createAndStoreBlockData(numDeposits, numTransactions, 11111);

        Spine.BlockData memory block1 = _createBlockData(numDeposits, numTransactions);
        block1.sequencer = sequencer;
        block1.blobhashes = blobHashes1;
        block1.anchor = keccak256("anchor1");

        uint256[] memory indices1 = new uint256[](blobHashes1.length);
        for (uint256 i = 0; i < blobHashes1.length; i++) {
            indices1[i] = i;
        }
        vm.blobhashes(blobHashes1);
        vm.prank(sequencer);
        block1 = harness.addBlockTest(block1, indices1);

        // Create second block with boundary-crossing tx
        bytes32[] memory blobHashes2 = _createAndStoreBlockData(numDeposits, numTransactions, 22222);

        Spine.BlockData memory block2 = _createBlockData(numDeposits, numTransactions);
        block2.sequencer = sequencer;
        block2.blobhashes = blobHashes2;
        block2.anchor = keccak256("anchor2");

        uint256[] memory indices2 = new uint256[](blobHashes2.length);
        for (uint256 i = 0; i < blobHashes2.length; i++) {
            indices2[i] = i;
        }
        vm.blobhashes(blobHashes2);
        vm.prank(sequencer);
        block2 = harness.addBlockTest(block2, indices2);

        // Find a tx that crosses the boundary
        // Deposit memory = 80 slots
        // We want tx where memAddr + 14 > 4096
        // So memAddr > 4082
        // 80 + txNr * 15 > 4082
        // txNr * 15 > 4002
        // txNr > 266.8
        // txNr = 267 starts at 80 + 267*15 = 4085
        uint256 txNr = 267;
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, numDeposits);

        // Set up an invalid anchor reference (future block) to trigger fraud
        _setupTransaction(blobHashes2, txNr, numDeposits, 999, 0, false, address(0));

        uint256 blobIndex = memAddr / 4096;
        uint256 localAddr = memAddr % 4096;

        // Calculate how many elements are in each blob
        uint256 elementsInFirstBlob = 4096 - localAddr;
        uint256 elementsInSecondBlob = 14 - elementsInFirstBlob;

        // Read data from both blobs
        bytes32[] memory regionData = new bytes32[](elementsInFirstBlob);
        for (uint256 i = 0; i < elementsInFirstBlob; i++) {
            regionData[i] = harness.access(blobHashes2[blobIndex], localAddr + i);
        }

        bytes32[] memory extensionData = new bytes32[](elementsInSecondBlob);
        for (uint256 i = 0; i < elementsInSecondBlob; i++) {
            extensionData[i] = harness.access(blobHashes2[blobIndex + 1], i);
        }

        BlobData.Region memory region =
            _createRegion(elementsInFirstBlob, localAddr, regionData, blobHashes2[blobIndex]);
        BlobData.Region memory extensionRegion =
            _createRegion(elementsInSecondBlob, 0, extensionData, blobHashes2[blobIndex + 1]);

        Spine.BlockData memory rollbackTarget = block1;

        // This should detect fraud (future block reference)
        // But may fail due to the bug in line 52 where the conditional is inverted
        vm.prank(challenger);
        harness.challengeTxZK(block2, txNr, region, extensionRegion, GENESIS, block1, "", "", rollbackTarget);

        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed");
    }

    /// @notice Test that extension region validation fails with wrong blob hash
    function test_ExtensionRegion_WrongBlobHashReverts() public {
        uint256 numDeposits = 60;
        uint256 numTransactions = 270;

        (Spine.BlockData memory data, bytes32[] memory blobHashes) =
            _createAndAddSingleBlock(numDeposits, numTransactions, 22222, keccak256("anchor"));

        uint256 txNr = 267;
        uint256 memAddr = harness.exposedTxMemoryAddress(txNr, numDeposits);
        uint256 blobIndex = memAddr / 4096;
        uint256 localAddr = memAddr % 4096;

        uint256 elementsInFirstBlob = 4096 - localAddr;
        uint256 elementsInSecondBlob = 14 - elementsInFirstBlob;

        bytes32[] memory regionData = new bytes32[](elementsInFirstBlob);
        for (uint256 i = 0; i < elementsInFirstBlob; i++) {
            regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
        }

        BlobData.Region memory region = _createRegion(elementsInFirstBlob, localAddr, regionData, blobHashes[blobIndex]);
        // Wrong blob hash for extension
        BlobData.Region memory extensionRegion =
            _createRegion(elementsInSecondBlob, 0, new bytes32[](elementsInSecondBlob), keccak256("wrong_hash"));

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTxZK(data, txNr, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", priorAnchorBlock);
    }

    // ============================================================================
    // Rollback Tests
    // ============================================================================

    /// @notice Test that successful challenge triggers rollback
    function test_Challenge_TriggersRollback() public {
        (Spine.BlockData memory block1, Spine.BlockData memory block2,, bytes32[] memory blobHashes2) =
            _createTwoBlocks();

        assertEq(harness.getBlockCount(), 2, "Should have 2 blocks");

        // Set up fraud in block2 - reference future block
        uint256 txNr = 50;
        _setupTransaction(blobHashes2, txNr, TEST_NUM_DEPOSITS, 999, 0, false, address(0));

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, TEST_NUM_DEPOSITS);

        Spine.BlockData memory priorAnchorBlock;
        vm.prank(challenger);
        harness.challengeTxZK(block2, txNr, region, extensionRegion, GENESIS, priorAnchorBlock, "", "", block1);

        assertEq(harness.getBlockCount(), 1, "Should rollback to 1 block");
    }

    // ============================================================================
    // Large Block Tests (10+ blobs)
    // ============================================================================

    // Constants for large block tests
    // 10 blobs = 40960 field elements
    // With 60 deposits (80 slots), we can fit (40960 - 80) / 15 = 2725 transactions
    uint256 constant LARGE_NUM_DEPOSITS = 60;
    uint256 constant LARGE_NUM_TRANSACTIONS = 2725;

    /// @notice Test that ALL transactions in a large 10-blob block revert with no fraud when valid
    /// @dev Tests every single transaction (2725 total) across 10 blobs
    function test_LargeBlock_AllValidTransactionsRevertNoFraud() public {
        vm.pauseGasMetering();

        // Create anchor block and large block with 10 blobs
        (Spine.BlockData memory block1, bytes32[] memory blobHashes1) =
            _createAndAddSingleBlock(LARGE_NUM_DEPOSITS, LARGE_NUM_TRANSACTIONS, 11111, keccak256("anchor1"));
        (Spine.BlockData memory block2, bytes32[] memory blobHashes2) =
            _createAndAddSingleBlock(LARGE_NUM_DEPOSITS, LARGE_NUM_TRANSACTIONS, 22222, keccak256("anchor2"));

        // Verify we have 10+ blobs
        assertGe(blobHashes2.length, 10, "Should have at least 10 blobs");

        // Test EVERY transaction in the block (2725 transactions)
        for (uint256 txNr = 0; txNr < LARGE_NUM_TRANSACTIONS; txNr++) {
            // Use a valid anchor reference - cycle through valid anchor positions
            uint32 anchorUpdateNr = uint32(txNr % LARGE_NUM_TRANSACTIONS);

            // Set up valid transaction with zkSNARK-only (ethKey = 0)
            _setupTransaction(
                blobHashes2, txNr, LARGE_NUM_DEPOSITS, uint32(block1.blockNr), anchorUpdateNr, false, address(0)
            );

            (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
                _buildTxRegion(blobHashes2, txNr, LARGE_NUM_DEPOSITS);

            // Get correct anchor
            uint256 anchorMemoryLocation =
                harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, LARGE_NUM_DEPOSITS);
            bytes32 anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);

            // Approve ZK proof
            uint256[7] memory publicInputs =
                _getTxPublicInputs(blobHashes2, txNr, LARGE_NUM_DEPOSITS, anchor, address(0));
            fakeZK.approveTransfer(publicInputs);

            // Challenge should revert - no fraud (ethKey == 0 and ZK valid)
            vm.prank(challenger);
            vm.expectRevert();
            harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, block1, "", "", block1);
        }

        // Verify sequencer still active after all challenges failed
        (bool isActive,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActive, "Sequencer should still be active - all transactions valid");

        vm.resumeGasMetering();
    }

    /// @notice Fuzz test with random fraud types across a multi-blob block
    /// @dev Fraud types: 0=invalid ZK, 1=unregistered eth key, 2=future block, 3=same block later tx, 4=out of bounds anchor
    function testFuzz_LargeBlock_RandomFraudTypes(
        uint256 txNr,
        uint256 fraudType,
        address fuzzedEthKey,
        bytes32 fuzzedAnchor1,
        bytes32 fuzzedAnchor2
    ) public {
        vm.pauseGasMetering();

        // Use slightly smaller block for faster fuzz runs but still multiple blobs
        uint256 numDeposits = 60;
        uint256 numTransactions = 1000; // ~4 blobs worth

        txNr = bound(txNr, 1, numTransactions - 1);
        fraudType = bound(fraudType, 0, 4);

        // Create anchor block and target block
        (Spine.BlockData memory block1, bytes32[] memory blobHashes1) =
            _createAndAddSingleBlock(numDeposits, numTransactions, txNr, fuzzedAnchor1);
        (Spine.BlockData memory block2, bytes32[] memory blobHashes2) =
            _createAndAddSingleBlock(numDeposits, numTransactions, txNr + fraudType, fuzzedAnchor2);

        // Verify multiple blobs
        assertGe(blobHashes2.length, 3, "Should have at least 3 blobs");

        // Set up transaction based on fraud type
        uint32 anchorBlockNr;
        uint32 anchorUpdateNr;
        bool isDepositAnchor = false;
        address ethKey = address(0);

        if (fraudType == 0) {
            // Invalid ZK proof - valid anchor but don't approve ZK
            anchorBlockNr = uint32(block1.blockNr);
            anchorUpdateNr = uint32(txNr % numTransactions);
        } else if (fraudType == 1) {
            // Unregistered eth key transaction
            anchorBlockNr = uint32(block1.blockNr);
            anchorUpdateNr = uint32(txNr % numTransactions);
            ethKey = fuzzedEthKey;
            if (ethKey == address(0)) ethKey = address(1); // Must be non-zero for this fraud type
        } else if (fraudType == 2) {
            // Future block reference
            anchorBlockNr = 999;
            anchorUpdateNr = 0;
        } else if (fraudType == 3) {
            // Same block, reference later tx
            anchorBlockNr = uint32(block2.blockNr);
            anchorUpdateNr = uint32(txNr + 1); // Reference tx after current one
        } else {
            // Out of bounds anchor update number
            anchorBlockNr = uint32(block1.blockNr);
            anchorUpdateNr = uint32(numTransactions); // Out of bounds (>= numTransactions)
        }

        _setupTransaction(blobHashes2, txNr, numDeposits, anchorBlockNr, anchorUpdateNr, isDepositAnchor, ethKey);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion) =
            _buildTxRegion(blobHashes2, txNr, numDeposits);

        // Get anchor (may be wrong for fraud types 2-4, but we need something)
        bytes32 anchor;
        Spine.BlockData memory priorAnchorBlock;

        if (fraudType <= 1) {
            // For ZK fraud and eth key fraud, we need valid anchor
            uint256 anchorMemoryLocation = harness.exposedPriorRootMemoryLocation(anchorUpdateNr, false, numDeposits);
            anchor = harness.access(blobHashes1[anchorMemoryLocation / 4096], anchorMemoryLocation % 4096);
            priorAnchorBlock = block1;

            if (fraudType == 1) {
                // Approve ZK but not eth key registration
                uint256[7] memory publicInputs = _getTxPublicInputs(blobHashes2, txNr, numDeposits, anchor, ethKey);
                fakeZK.approveTransfer(publicInputs);
                txRegistry.setDefaultReturn(false); // Not registered
            }
            // fraudType == 0: don't approve ZK (invalid proof)
        } else {
            // For anchor fraud types, use genesis as anchor
            anchor = GENESIS;
            priorAnchorBlock = block1; // Will be checked but fraud detected earlier
        }

        (bool isActiveBefore,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before challenge");

        vm.prank(challenger);
        harness.challengeTxZK(block2, txNr, region, extensionRegion, anchor, priorAnchorBlock, "", "", block1);

        (bool isActiveAfter,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed for fraud");
        assertEq(challengerAddr, challenger, "Challenger should be recorded");

        vm.resumeGasMetering();
    }
}
