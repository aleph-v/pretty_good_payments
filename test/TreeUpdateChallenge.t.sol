// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {TreeUpdateChallenge} from "../src/TreeUpdateChallenge.sol";
import {Spine} from "../src/Spine.sol";
import {Proof} from "../src/library/PredictableMerkleLib.sol";
import {BlobData} from "../src/library/BlobData.sol";
import {IYieldRouter} from "../src/interfaces/IYieldRouter.sol";
import {IUpdateVerifier} from "../src/interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "../src/interfaces/ITransferVerifier.sol";
import {ITransactionRegistry} from "../src/TransactionRegistry.sol";
import {FakeBlobs} from "./mocks/FakeBlobs.sol";
import {FakeZK} from "./mocks/FakeZK.sol";
import {MockYieldRouter} from "./mocks/MockYieldRouter.sol";
import {MockTransactionRegistry} from "./mocks/MockTransactionRegistry.sol";

contract TreeUpdateChallengeHarness is TreeUpdateChallenge, FakeBlobs {
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

    function setupBlock(BlockData memory data, bytes32 anchorBefore, uint256 blockIndex, uint256 seed, FakeZK zk)
        public
        returns (BlockData memory, bytes32[] memory ret)
    {
        uint256 depositSize = data.numDeposits % 3 == 0 ? (data.numDeposits / 3) * 4 : (data.numDeposits / 3 + 1) * 4;
        uint256 dataNeeded = depositSize + data.numTransactions * 15;
        if (dataNeeded == 0) dataNeeded = 1;

        bytes32[] memory randomData = new bytes32[](dataNeeded);
        for (uint256 i = 0; i < dataNeeded; i++) {
            randomData[i] = keccak256(abi.encodePacked(i, seed));
        }
        ret = store(randomData);

        uint256[6] memory signals;
        uint256 priorAnchor = uint256(anchorBefore);
        uint256 regions = (data.numDeposits + 2) / 3;
        for (uint256 i = 0; i < regions; i++) {
            // Signal order: [trueAnchor, priorAnchor, update0, update1, update2, treeIndex]
            uint256 newAnchor = uint256(randomData[i * 4 + 3]);
            signals = [
                newAnchor, // trueAnchor (newAnchor after updates)
                priorAnchor, // priorAnchor (anchor before this group)
                uint256(randomData[i * 4]),
                uint256(randomData[i * 4 + 1]),
                uint256(randomData[i * 4 + 2]),
                blockIndex // treeIndex
            ];
            zk.approveUpdate(signals);
            priorAnchor = newAnchor;
        }

        for (uint256 i = 0; i < data.numTransactions; i++) {
            uint256 baseOffset = depositSize + i * 15 + 11;
            // Signal order: [trueAnchor, priorAnchor, update0, update1, update2, treeIndex]
            uint256 newAnchor = uint256(randomData[baseOffset + 3]);
            signals = [
                newAnchor, // trueAnchor (newAnchor after updates)
                priorAnchor, // priorAnchor (anchor before this tx)
                uint256(randomData[baseOffset]),
                uint256(randomData[baseOffset + 1]),
                uint256(randomData[baseOffset + 2]),
                blockIndex // treeIndex
            ];
            zk.approveUpdate(signals);
            priorAnchor = newAnchor;
        }

        data.anchor = bytes32(priorAnchor);
        data.blobhashes = ret;
        return (data, ret);
    }

    function addBlockTest(BlockData memory data, uint256[] memory indices) public returns (BlockData memory) {
        addBlock(data, indices);
        return (data);
    }

    function validateSingle(bytes32 rootHash, bytes calldata, uint256 index, bytes32 data, bytes calldata)
        internal
        view
        override
    {
        require(access(rootHash, index) == data);
    }

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

    function exposedPriorRootMemoryLocation(uint256 number, bool isDeposit, uint256 numDeposits)
        public
        pure
        returns (uint256)
    {
        return priorRootMemoryLocation(number, isDeposit, numDeposits);
    }

    function exposedNumDepositsToMemoryLength(uint256 num) public pure returns (uint256) {
        return numDepositsToMemoryLength(num);
    }

    function getGenesisAnchor() public view returns (bytes32) {
        return GENESIS_ANCHOR;
    }
}

contract TreeUpdateChallengeTest is Test {
    TreeUpdateChallengeHarness harness;
    FakeZK fakeZK;
    MockYieldRouter yieldRouter;
    MockTransactionRegistry txRegistry;

    address sequencer = address(0x1111);
    address challenger = address(0x2222);

    bytes32 constant GENESIS = keccak256("genesis");

    function setUp() public {
        fakeZK = new FakeZK();
        yieldRouter = new MockYieldRouter();
        txRegistry = new MockTransactionRegistry();

        harness = new TreeUpdateChallengeHarness(
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

    /// @notice Creates, sets up, and adds a block to the chain
    function _createAndAddBlock(
        uint256 numDeposits,
        uint256 numTx,
        bytes32 priorAnchor,
        uint256 blockIndex,
        uint256 seed
    ) internal returns (Spine.BlockData memory data, bytes32[] memory blobHashes) {
        data = _createBlockData(numDeposits, numTx);
        data.sequencer = sequencer;
        (data, blobHashes) = harness.setupBlock(data, priorAnchor, blockIndex, seed, fakeZK);

        uint256[] memory indices = new uint256[](blobHashes.length);
        for (uint256 i = 0; i < blobHashes.length; i++) {
            indices[i] = i;
        }
        vm.blobhashes(blobHashes);

        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);
    }

    /// @notice Builds a region for deposit group updates (4 elements)
    function _buildDepositRegion(bytes32[] memory blobHashes, uint256 updateNr)
        internal
        view
        returns (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData)
    {
        uint256 memoryAddress = updateNr * 4;
        uint256 blobIndex = memoryAddress / 4096;
        uint256 localAddr = memoryAddress % 4096;

        if (localAddr + 4 <= 4096) {
            regionData = new bytes32[](4);
            for (uint256 i = 0; i < 4; i++) {
                regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
            }
            region = _createRegion(4, localAddr, regionData, blobHashes[blobIndex]);
            extensionRegion = _createEmptyRegion();
        } else {
            uint256 firstCount = 4096 - localAddr;
            uint256 secondCount = 4 - firstCount;

            regionData = new bytes32[](4);
            bytes32[] memory firstData = new bytes32[](firstCount);
            for (uint256 i = 0; i < firstCount; i++) {
                firstData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
                regionData[i] = firstData[i];
            }

            bytes32[] memory secondData = new bytes32[](secondCount);
            for (uint256 i = 0; i < secondCount; i++) {
                secondData[i] = harness.access(blobHashes[blobIndex + 1], i);
                regionData[firstCount + i] = secondData[i];
            }

            region = _createRegion(firstCount, localAddr, firstData, blobHashes[blobIndex]);
            extensionRegion = _createRegion(secondCount, 0, secondData, blobHashes[blobIndex + 1]);
        }
    }

    /// @notice Builds a region for transaction updates (4 elements starting at tx+11)
    function _buildTxUpdateRegion(bytes32[] memory blobHashes, uint256 updateNr, uint256 numDeposits)
        internal
        view
        returns (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData)
    {
        uint256 memoryAddress = harness.exposedTxMemoryAddress(updateNr, numDeposits) + 11;
        uint256 blobIndex = memoryAddress / 4096;
        uint256 localAddr = memoryAddress % 4096;

        if (localAddr + 4 <= 4096) {
            regionData = new bytes32[](4);
            for (uint256 i = 0; i < 4; i++) {
                regionData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
            }
            region = _createRegion(4, localAddr, regionData, blobHashes[blobIndex]);
            extensionRegion = _createEmptyRegion();
        } else {
            uint256 firstCount = 4096 - localAddr;
            uint256 secondCount = 4 - firstCount;

            regionData = new bytes32[](4);
            bytes32[] memory firstData = new bytes32[](firstCount);
            for (uint256 i = 0; i < firstCount; i++) {
                firstData[i] = harness.access(blobHashes[blobIndex], localAddr + i);
                regionData[i] = firstData[i];
            }

            bytes32[] memory secondData = new bytes32[](secondCount);
            for (uint256 i = 0; i < secondCount; i++) {
                secondData[i] = harness.access(blobHashes[blobIndex + 1], i);
                regionData[firstCount + i] = secondData[i];
            }

            region = _createRegion(firstCount, localAddr, firstData, blobHashes[blobIndex]);
            extensionRegion = _createRegion(secondCount, 0, secondData, blobHashes[blobIndex + 1]);
        }
    }

    /// @notice Gets prior anchor for a deposit group
    function _getDepositPriorAnchor(bytes32[] memory blobHashes, uint256 updateNr) internal view returns (bytes32) {
        if (updateNr == 0) return GENESIS;
        uint256 priorRootOffset = updateNr * 4 - 1;
        return harness.access(blobHashes[priorRootOffset / 4096], priorRootOffset % 4096);
    }

    /// @notice Gets prior anchor for a transaction
    function _getTxPriorAnchor(bytes32[] memory blobHashes, uint256 updateNr, uint256 numDeposits)
        internal
        view
        returns (bytes32)
    {
        uint256 depositSize = harness.exposedNumDepositsToMemoryLength(numDeposits);
        if (updateNr == 0) {
            if (numDeposits == 0) return GENESIS;
            return harness.access(blobHashes[(depositSize - 1) / 4096], (depositSize - 1) % 4096);
        }
        uint256 priorRootOffset = depositSize + (updateNr - 1) * 15 + 14;
        return harness.access(blobHashes[priorRootOffset / 4096], priorRootOffset % 4096);
    }

    // ============================================================================
    // Challenge validation tests
    // ============================================================================

    function test_Challenge_RevertsIfBlockNotIncluded() public {
        // Setup block but DON'T add it
        Spine.BlockData memory data = _createBlockData(3, 0);
        data.sequencer = sequencer;
        (data,) = harness.setupBlock(data, GENESIS, 0, 12345, fakeZK);

        BlobData.Region memory region = _createEmptyRegion();
        region.length = 4;

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 0, false, region, _createEmptyRegion(), GENESIS, "", "", bytes32(uint256(1)), zkProof, rollbackTarget
        );
    }

    function test_Challenge_RevertsOnZeroLengthRegion() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(3, 0, GENESIS, 0, 12345);

        BlobData.Region memory region = _createEmptyRegion();
        region.hash = blobHashes[0];

        Proof memory zkProof;
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 0, false, region, _createEmptyRegion(), GENESIS, "", "", bytes32(uint256(1)), zkProof, data
        );
    }

    /// @notice Test that challenge reverts if updateNr >= numTransactions for transactions
    function test_Challenge_RevertsIfTxUpdateNrOutOfBounds() public {
        (Spine.BlockData memory data,) = _createAndAddBlock(3, 5, GENESIS, 0, 12345);

        BlobData.Region memory region = _createEmptyRegion();
        region.length = 4;

        Proof memory zkProof;
        // updateNr = 5 is out of bounds (valid range is 0-4 for 5 transactions)
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 5, true, region, _createEmptyRegion(), GENESIS, "", "", bytes32(uint256(1)), zkProof, data
        );
    }

    /// @notice Test that challenge reverts if updateNr >= ceil(numDeposits/3) for deposits
    function test_Challenge_RevertsIfDepositUpdateNrOutOfBounds() public {
        // 6 deposits = 2 groups (indices 0, 1), valid updateNr range is 0-1
        (Spine.BlockData memory data,) = _createAndAddBlock(6, 0, GENESIS, 0, 12345);

        BlobData.Region memory region = _createEmptyRegion();
        region.length = 4;

        Proof memory zkProof;
        // updateNr = 2 is out of bounds
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 2, false, region, _createEmptyRegion(), GENESIS, "", "", bytes32(uint256(1)), zkProof, data
        );
    }

    /// @notice Test edge case: 1 deposit = 1 group, updateNr=1 is out of bounds
    function test_Challenge_RevertsIfDepositUpdateNrOutOfBounds_SingleDeposit() public {
        (Spine.BlockData memory data,) = _createAndAddBlock(1, 0, GENESIS, 0, 12345);

        BlobData.Region memory region = _createEmptyRegion();
        region.length = 4;

        Proof memory zkProof;
        // updateNr = 1 is out of bounds (valid is only 0)
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 1, false, region, _createEmptyRegion(), GENESIS, "", "", bytes32(uint256(1)), zkProof, data
        );
    }

    /// @notice Test edge case: 4 deposits = 2 groups, updateNr=2 is out of bounds
    function test_Challenge_RevertsIfDepositUpdateNrOutOfBounds_FourDeposits() public {
        (Spine.BlockData memory data,) = _createAndAddBlock(4, 0, GENESIS, 0, 12345);

        BlobData.Region memory region = _createEmptyRegion();
        region.length = 4;

        Proof memory zkProof;
        // updateNr = 2 is out of bounds
        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 2, false, region, _createEmptyRegion(), GENESIS, "", "", bytes32(uint256(1)), zkProof, data
        );
    }

    /// @notice Test that valid updateNr at boundary works (numTransactions-1)
    function test_Challenge_ValidTxUpdateNrAtBoundary() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(0, 3, GENESIS, 0, 12345);

        // updateNr = 2 is valid (last tx, index numTransactions-1)
        uint256 updateNr = 2;
        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildTxUpdateRegion(blobHashes, updateNr, 0);

        bytes32 priorAnchor = _getTxPriorAnchor(blobHashes, updateNr, 0);
        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(priorAnchor),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        // Should not revert with out of bounds - will revert with "No Fraud" instead
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            data, updateNr, true, region, extensionRegion, priorAnchor, "", "", trueAnchor, zkProof, data
        );
    }

    function test_Challenge_FailsWithoutApprovedZKProof() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(3, 0, GENESIS, 0, 12345);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion,) = _buildDepositRegion(blobHashes, 0);

        // Create a ZK proof that is NOT approved
        Proof memory zkProof = Proof({
            _pA: [uint256(1), uint256(2)],
            _pB: [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            _pC: [uint256(7), uint256(8)]
        });

        vm.prank(challenger);
        vm.expectRevert("Invalid ZK update proof");
        harness.challengeTreeUpdate(
            data, 0, false, region, extensionRegion, GENESIS, "", "", bytes32(uint256(999)), zkProof, data
        );
    }

    // ============================================================================
    // Successful challenge and slashing tests
    // ============================================================================

    function test_Challenge_SlashesSequencerOnFraud() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(3, 0, GENESIS, 0, 12345);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildDepositRegion(blobHashes, 0);

        // Approve a ZK proof showing the correct anchor is different (fraud)
        bytes32 trueAnchor = keccak256("different_anchor");
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(GENESIS),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;

        (bool isActiveBefore,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore);

        vm.prank(challenger);
        harness.challengeTreeUpdate(data, 0, false, region, extensionRegion, GENESIS, "", "", trueAnchor, zkProof, data);

        (bool isActiveAfter,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed");
        assertEq(challengerAddr, challenger, "Challenger should be recorded");
    }

    /// @notice Test that valid deposit-only blocks reject fraud challenges
    function test_Challenge_RevertsOnValidBlock() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(1, 0, GENESIS, 0, 12345);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildDepositRegion(blobHashes, 0);

        // The true anchor equals what's in the blob (no fraud)
        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(GENESIS),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        // Challenge should revert with "No Fraud" since this is a valid block
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(data, 0, false, region, extensionRegion, GENESIS, "", "", trueAnchor, zkProof, data);
    }

    // ============================================================================
    // isLast identification tests - verify correct behavior in all cases
    // ============================================================================

    /// @notice 6 deposits block: updateNr=0 is NOT the last
    function test_IsLast_SixDeposits_NotLast() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(6, 0, GENESIS, 0, 12345);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildDepositRegion(blobHashes, 0);

        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(GENESIS),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        // isLast = (0 == 6/3) = false, trueAnchor == sequencerSubmittedRoot -> "No Fraud"
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(data, 0, false, region, extensionRegion, GENESIS, "", "", trueAnchor, zkProof, data);
    }

    /// @notice Single transaction block: updateNr=0 is the last (and only) transaction
    function test_IsLast_SingleTransaction() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(0, 1, GENESIS, 0, 12345);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildTxUpdateRegion(blobHashes, 0, 0);

        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(GENESIS),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        // updateNr=0 with numTransactions=1: isLast = true, trueAnchor == data.anchor -> "No Fraud"
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(data, 0, true, region, extensionRegion, GENESIS, "", "", trueAnchor, zkProof, data);
    }

    /// @notice Two transactions: last tx (updateNr=1) correctly identified as isLast
    function test_IsLast_TwoTransactions_LastTx() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(0, 2, GENESIS, 0, 12345);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildTxUpdateRegion(blobHashes, 1, 0);

        bytes32 priorAnchor = _getTxPriorAnchor(blobHashes, 1, 0);
        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(priorAnchor),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        // updateNr=1 with numTransactions=2: isLast = true, trueAnchor == data.anchor -> "No Fraud"
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            data, 1, true, region, extensionRegion, priorAnchor, "", "", trueAnchor, zkProof, data
        );
    }

    /// @notice Mixed block: 3 deposits + 1 transaction, tx is the last update
    function test_IsLast_MixedBlock() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(3, 1, GENESIS, 0, 12345);

        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildTxUpdateRegion(blobHashes, 0, 3);

        bytes32 priorAnchor = _getTxPriorAnchor(blobHashes, 0, 3);
        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(priorAnchor),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        // updateNr=0 with numTransactions=1: isLast = true, trueAnchor == data.anchor -> "No Fraud"
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            data, 0, true, region, extensionRegion, priorAnchor, "", "", trueAnchor, zkProof, data
        );
    }

    /// @notice Deposits-only block with FRAUD: last deposit group has wrong anchor in header
    /// @dev Tests isLast logic when numTransactions == 0:
    ///      isLast = (updateNr == (numDeposits - 1) / 3)
    ///      For 6 deposits: (6-1)/3 = 1, so updateNr=1 is the last group
    ///      Sequencer should be slashed when blob is correct but header anchor lies
    function test_IsLast_DepositsOnly_LastGroupFraud_SlashesSequencer() public {
        // Create a 6-deposit block with ZERO transactions (2 groups: 0 and 1)
        // isLast for deposits with 0 tx: updateNr == (numDeposits - 1) / 3 = (6-1)/3 = 1
        Spine.BlockData memory data = _createBlockData(6, 0); // 6 deposits, 0 transactions
        data.sequencer = sequencer;
        (data,) = harness.setupBlock(data, GENESIS, 0, 12345, fakeZK);

        // Save the correct anchor computed by setupBlock
        bytes32 correctAnchor = data.anchor;

        // FRAUD: Modify the anchor in the block header to be wrong
        data.anchor = keccak256("fraudulent_header_anchor");
        require(data.anchor != correctAnchor, "Test setup: anchors must differ");

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;
        vm.blobhashes(data.blobhashes);

        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);

        // Challenge the LAST deposit group (updateNr=1)
        // For 6 deposits with 0 tx: isLast = (1 == (6-1)/3) = (1 == 1) = true
        uint256 updateNr = 1;
        uint256 memoryAddress = updateNr * 4; // Group 1 starts at slot 4

        bytes32[] memory regionData = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            regionData[i] = harness.access(data.blobhashes[0], memoryAddress + i);
        }

        BlobData.Region memory region = _createRegion(4, memoryAddress, regionData, data.blobhashes[0]);
        BlobData.Region memory extensionRegion = _createEmptyRegion();

        // Prior anchor is the anchor after group 0 (at slot 3)
        bytes32 priorAnchor = harness.access(data.blobhashes[0], 3);

        // The trueAnchor from blob matches the correct anchor (sequencer put correct data in blob)
        bytes32 trueAnchor = regionData[3];
        assertEq(trueAnchor, correctAnchor, "Blob should contain the correct anchor");
        assertTrue(trueAnchor != data.anchor, "Header anchor should be wrong (fraud)");

        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(priorAnchor),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Verify sequencer is active before challenge
        (bool isActiveBefore,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before challenge");

        // Challenge should succeed because:
        // - trueAnchor == sequencerSubmittedRoot (blob has correct root)
        // - isLast == true (numTransactions=0, updateNr=1 == (6-1)/3 = 1)
        // - trueAnchor != data.anchor (header lies!)
        // This triggers the fraud path and slashes the sequencer
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            data, updateNr, false, region, extensionRegion, priorAnchor, "", "", trueAnchor, zkProof, rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActiveAfter,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed for header anchor fraud");
        assertEq(challengerAddr, challenger, "Challenger should be recorded");
    }

    // ============================================================================
    // Rollback tests
    // ============================================================================

    function test_Rollback_ResetsBlockCount() public {
        // Add first block
        (Spine.BlockData memory data1,) = _createAndAddBlock(3, 0, GENESIS, 0, 111);
        assertEq(harness.getBlockCount(), 1);

        // Add second block
        (Spine.BlockData memory data2, bytes32[] memory blobHashes2) = _createAndAddBlock(3, 0, data1.anchor, 1, 222);
        assertEq(harness.getBlockCount(), 2);

        // Challenge second block to trigger rollback
        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildDepositRegion(blobHashes2, 0);

        bytes32 trueAnchor = keccak256("fraud");
        uint256 treeIndex = uint256(data2.blockIndex.day) * (2 ** 13) + uint256(data2.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(data1.anchor),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;

        vm.prank(challenger);
        harness.challengeTreeUpdate(
            data2, 0, false, region, extensionRegion, data1.anchor, "", "", trueAnchor, zkProof, data1
        );

        assertEq(harness.getBlockCount(), 1, "Should rollback to block 1");
    }

    // ============================================================================
    // Edge case tests for extension regions
    // ============================================================================

    /// @notice Test extension region when tx data crosses blob boundary
    /// @dev With numDeposits=3, tx 272 starts at memoryAddress 4095, crossing into blob 1
    ///      region.length=1 (element at 4095), extensionRegion.length=3 (elements at 0,1,2 in blob 1)
    function test_ExtensionRegion_TxCrossesBlobBoundary() public {
        // We need enough data to span 2 blobs and place tx 272 at the boundary
        // With 3 deposits (4 slots) + 273 transactions (273*15 = 4095 slots) = 4099 total slots
        // Tx 272 update data starts at: depositsLength + 272*15 + 11 = 4 + 4080 + 11 = 4095
        // This places leaf0 at 4095 (blob 0), leaf1-leaf2-root at 0-1-2 (blob 1)

        uint256 numDeposits = 3;
        uint256 numTransactions = 273;
        uint256 targetTx = 272;

        // Calculate total data needed
        uint256 depositSize = 4; // 3 deposits = 1 group = 4 slots
        uint256 txSize = numTransactions * 15;
        uint256 totalData = depositSize + txSize; // 4 + 4095 = 4099

        // Create and store data spanning 2 blobs
        bytes32[] memory allData = new bytes32[](totalData);
        for (uint256 i = 0; i < totalData; i++) {
            allData[i] = keccak256(abi.encodePacked("boundary_test", i));
        }
        bytes32[] memory blobHashes = harness.store(allData);
        assertEq(blobHashes.length, 2, "Should span 2 blobs");

        // Set up the block data
        Spine.BlockData memory data;
        data.numDeposits = numDeposits;
        data.numTransactions = numTransactions;
        data.sequencer = sequencer;
        data.blobhashes = blobHashes;
        data.blockNr = 0;
        data.blockIndex = Spine.TimestampAndIndex(0, 0);

        // Calculate positions for tx 272
        uint256 memoryAddress = harness.exposedTxMemoryAddress(targetTx, numDeposits) + 11;
        assertEq(memoryAddress, 4095, "Tx 272 should start at 4095");

        // The update data spans: 4095 (blob 0), 0-2 (blob 1)
        // Region: length=1 at memoryAddress=4095 in blob 0
        // ExtensionRegion: length=3 at memoryAddress=0 in blob 1

        bytes32[] memory regionData = new bytes32[](1);
        regionData[0] = harness.access(blobHashes[0], 4095); // leaf0 in blob 0

        bytes32[] memory extensionData = new bytes32[](3);
        extensionData[0] = harness.access(blobHashes[1], 0); // leaf1 in blob 1
        extensionData[1] = harness.access(blobHashes[1], 1); // leaf2 in blob 1
        extensionData[2] = harness.access(blobHashes[1], 2); // root in blob 1

        BlobData.Region memory region = _createRegion(1, 4095, regionData, blobHashes[0]);
        BlobData.Region memory extensionRegion = _createRegion(3, 0, extensionData, blobHashes[1]);

        // Set up prior anchor (root from tx 271)
        // Tx 271 root is at: depositsLength + 271*15 + 14 = 4 + 4065 + 14 = 4083
        bytes32 priorAnchor = harness.access(blobHashes[0], 4083);

        // The final anchor should be the root from tx 272 (in extension region)
        bytes32 sequencerSubmittedRoot = extensionData[2];
        data.anchor = sequencerSubmittedRoot;

        // Add the block first
        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;
        vm.blobhashes(blobHashes);

        // Need to manually include the block since we're not using setupBlock
        // IMPORTANT: Capture the returned data which has updated timestamp/blockNr
        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);

        // Approve ZK proof for this update showing fraud (different anchor)
        bytes32 trueAnchor = keccak256("fraud_at_boundary");
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        uint256[6] memory signals = [
            uint256(trueAnchor),
            uint256(priorAnchor),
            uint256(regionData[0]), // leaf0 from region
            uint256(extensionData[0]), // leaf1 from extension
            uint256(extensionData[1]), // leaf2 from extension
            treeIndex
        ];
        fakeZK.approveUpdate(signals);

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Challenge should succeed - fraud detected at boundary crossing tx
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            data, targetTx, true, region, extensionRegion, priorAnchor, "", "", trueAnchor, zkProof, rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed");
        assertEq(challengerAddr, challenger, "Challenger should be recorded");
    }

    // ============================================================================
    // Fraud detection tests - different fraud scenarios
    // ============================================================================

    /// @notice Test fraud where intermediate root is wrong (trueAnchor != sequencerSubmittedRoot)
    /// @dev This triggers the else branch at line 80 - direct slash without isLast check
    function test_Fraud_WrongIntermediateRoot() public {
        // Create a block with multiple deposit groups (6 deposits = 2 groups)
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(6, 0, GENESIS, 0, 12345);

        // Challenge the FIRST deposit group (updateNr=0, not the last)
        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildDepositRegion(blobHashes, 0);

        // The sequencer's submitted root is regionData[3], but we claim the TRUE root is different (fraud!)
        bytes32 trueAnchor = keccak256("wrong_intermediate_root");
        require(trueAnchor != regionData[3], "Test setup: anchors must differ");

        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);
        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(GENESIS),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Challenge should succeed via the ELSE branch - trueAnchor != sequencerSubmittedRoot -> direct slash
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            data, 0, false, region, extensionRegion, GENESIS, "", "", trueAnchor, zkProof, rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for wrong intermediate root");
        assertEq(challengerAddr, challenger);
    }

    /// @notice Test fraud where block header anchor is wrong but intermediate roots are correct
    /// @dev This tests: trueAnchor == sequencerSubmittedRoot BUT trueAnchor != data.anchor
    ///      The sequencer computed the merkle tree correctly but lied in the block header.
    ///      Uses 5 deposits (2 groups) to test the isLast formula: isLast = (updateNr == numDeposits/3)
    ///      For 5 deposits: isLast when updateNr == 5/3 = 1 (last group index is 1) ✓
    function test_Fraud_WrongAnchorInBlockHeader() public {
        // Create a 5-deposit block (2 groups: indices 0 and 1)
        // Group 0: slots 0-3, Group 1: slots 4-7
        // isLast = (updateNr == 5/3) = (updateNr == 1)
        Spine.BlockData memory data = _createBlockData(5, 0);
        data.sequencer = sequencer;
        (data,) = harness.setupBlock(data, GENESIS, 0, 12345, fakeZK);

        // IMPORTANT: Modify the anchor in the block header to be wrong
        // The setupBlock computed the correct anchor, but we'll change it
        bytes32 correctAnchor = data.anchor;
        data.anchor = keccak256("wrong_header_anchor"); // Lie in header!

        uint256[] memory indices = new uint256[](1);
        indices[0] = 0;
        vm.blobhashes(data.blobhashes);

        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);

        // Challenge the LAST deposit group (updateNr=1, group 1 at slots 4-7)
        uint256 updateNr = 1;
        uint256 memoryAddress = updateNr * 4; // = 4

        bytes32[] memory regionData = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            regionData[i] = harness.access(data.blobhashes[0], memoryAddress + i);
        }

        BlobData.Region memory region = _createRegion(4, memoryAddress, regionData, data.blobhashes[0]);
        BlobData.Region memory extensionRegion = _createEmptyRegion();

        // Prior anchor is the root of group 0 (at slot 3)
        bytes32 priorAnchor = harness.access(data.blobhashes[0], 3);

        // The trueAnchor matches the sequencer's submitted root in the blob
        bytes32 trueAnchor = regionData[3];
        assertEq(trueAnchor, correctAnchor, "Blob contains correct root");
        assertTrue(trueAnchor != data.anchor, "But header has wrong anchor");

        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        uint256[6] memory signals = [
            uint256(trueAnchor),
            uint256(priorAnchor),
            uint256(regionData[0]),
            uint256(regionData[1]),
            uint256(regionData[2]),
            treeIndex
        ];
        fakeZK.approveUpdate(signals);

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Challenge should succeed because:
        // - trueAnchor == sequencerSubmittedRoot (blob has correct root)
        // - isLast == true (updateNr=1 == 5/3=1)
        // - trueAnchor != data.anchor (but header lies!)
        // This passes the require(isLast && trueAnchor != data.anchor) and slashes
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            data, updateNr, false, region, extensionRegion, priorAnchor, "", "", trueAnchor, zkProof, rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActive,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for wrong header anchor");
        assertEq(challengerAddr, challenger);
    }

    // ============================================================================
    // Comprehensive no-fraud tests for large blocks
    // ============================================================================

    /// @notice Test that valid blocks reject fraud challenges at EVERY update index
    /// @dev Creates a 10-blob max size block and loops through every possible fraud index
    ///      showing that our valid test setup fails with "No Fraud" revert errors.
    ///      Note: For deposits, updateNr is the GROUP index (0, 1, 2, ...), not individual deposit.
    ///      The priorRootMemoryLocation formula uses `updateNr * 4 - 1` which expects group indices.
    function test_NoFraud_EveryUpdateIndexInLargeBlock() public {
        vm.pauseGasMetering();

        // Setup for a 10-blob block:
        // - 30 deposits = ceil(30/3) * 4 = 40 slots (10 deposit groups)
        // - 2456 transactions = 2456 * 15 = 36840 slots
        // - Total = 36880 slots (spans 10 blobs: slots 0-36879)
        uint256 numDeposits = 30;
        uint256 numTransactions = 2456;

        // Calculate total data needed
        uint256 depositSize = ((numDeposits + 2) / 3) * 4; // 40 slots
        uint256 txSize = numTransactions * 15; // 36840 slots
        uint256 totalData = depositSize + txSize; // 36880 slots
        uint256 numDepositGroups = (numDeposits + 2) / 3; // 10 groups

        // Create and store data spanning 10 blobs
        bytes32[] memory allData = new bytes32[](totalData);
        for (uint256 i = 0; i < totalData; i++) {
            allData[i] = keccak256(abi.encodePacked("large_block_test", i));
        }
        bytes32[] memory blobHashes = harness.store(allData);
        assertEq(blobHashes.length, 10, "Should span exactly 10 blobs");

        // Set up the block data
        Spine.BlockData memory data;
        data.numDeposits = numDeposits;
        data.numTransactions = numTransactions;
        data.sequencer = sequencer;
        data.blobhashes = blobHashes;
        data.blockNr = 0;
        data.blockIndex = Spine.TimestampAndIndex(0, 0);

        // The final anchor is the root from the last transaction
        // Last tx root is at: depositSize + (numTransactions-1)*15 + 14 = 40 + 2455*15 + 14 = 36879
        bytes32 finalAnchor = harness.access(blobHashes[9], 36879 % 4096);
        data.anchor = finalAnchor;

        // Add the block
        uint256[] memory indices = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) {
            indices[i] = i;
        }
        vm.blobhashes(blobHashes);

        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);

        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Re-approve all ZK proofs with correct signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        bytes32 priorAnchor = GENESIS;
        for (uint256 i = 0; i < numDepositGroups; i++) {
            uint256 baseOffset = i * 4;
            bytes32 newAnchor = allData[baseOffset + 3];
            uint256[6] memory signals = [
                uint256(newAnchor), // trueAnchor
                uint256(priorAnchor), // priorAnchor
                uint256(allData[baseOffset]),
                uint256(allData[baseOffset + 1]),
                uint256(allData[baseOffset + 2]),
                treeIndex
            ];
            fakeZK.approveUpdate(signals);
            priorAnchor = newAnchor;
        }

        for (uint256 i = 0; i < numTransactions; i++) {
            uint256 baseOffset = depositSize + i * 15 + 11;
            bytes32 newAnchor = allData[baseOffset + 3];
            uint256[6] memory signals = [
                uint256(newAnchor), // trueAnchor
                uint256(priorAnchor), // priorAnchor
                uint256(allData[baseOffset]),
                uint256(allData[baseOffset + 1]),
                uint256(allData[baseOffset + 2]),
                treeIndex
            ];
            fakeZK.approveUpdate(signals);
            priorAnchor = newAnchor;
        }

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Test every deposit GROUP index (0 to numDepositGroups-1)
        // updateNr is now the GROUP index, so memoryAddress = updateNr * 4
        for (uint256 updateNr = 0; updateNr < numDepositGroups; updateNr++) {
            uint256 memoryAddress = updateNr * 4;
            uint256 blobIndex = memoryAddress / 4096;
            uint256 localAddress = memoryAddress % 4096;

            bytes32[] memory regionData = new bytes32[](4);
            for (uint256 j = 0; j < 4; j++) {
                regionData[j] = harness.access(blobHashes[blobIndex], localAddress + j);
            }

            BlobData.Region memory region = _createRegion(4, localAddress, regionData, blobHashes[blobIndex]);
            BlobData.Region memory extensionRegion = _createEmptyRegion();

            // Get prior anchor for this deposit group
            // priorRootMemoryLocation(updateNr) = updateNr * 4 - 1 = previous group's root
            bytes32 challengePriorAnchor;
            if (updateNr == 0) {
                // First group uses GENESIS
                challengePriorAnchor = GENESIS;
            } else {
                // Prior root is at updateNr * 4 - 1 = (updateNr - 1) * 4 + 3
                uint256 priorRootOffset = updateNr * 4 - 1;
                uint256 priorBlobIndex = priorRootOffset / 4096;
                challengePriorAnchor = harness.access(blobHashes[priorBlobIndex], priorRootOffset % 4096);
            }

            bytes32 trueAnchor = regionData[3]; // The correct root

            vm.prank(challenger);
            vm.expectRevert("No Fraud");
            harness.challengeTreeUpdate(
                data,
                updateNr,
                false,
                region,
                extensionRegion,
                challengePriorAnchor,
                "",
                "",
                trueAnchor,
                zkProof,
                rollbackTarget
            );
        }

        // Test every transaction index
        for (uint256 updateNr = 0; updateNr < numTransactions; updateNr++) {
            uint256 memoryAddress = harness.exposedTxMemoryAddress(updateNr, numDeposits) + 11;
            uint256 blobIndex = memoryAddress / 4096;
            uint256 localAddress = memoryAddress % 4096;

            // Handle blob boundary crossing
            BlobData.Region memory region;
            BlobData.Region memory extensionRegion;

            if (localAddress + 4 <= 4096) {
                // All 4 elements in same blob
                bytes32[] memory regionData = new bytes32[](4);
                for (uint256 j = 0; j < 4; j++) {
                    regionData[j] = harness.access(blobHashes[blobIndex], localAddress + j);
                }
                region = _createRegion(4, localAddress, regionData, blobHashes[blobIndex]);
                extensionRegion = _createEmptyRegion();
            } else {
                // Elements cross blob boundary
                uint256 firstBlobCount = 4096 - localAddress;
                uint256 secondBlobCount = 4 - firstBlobCount;

                bytes32[] memory regionData = new bytes32[](firstBlobCount);
                for (uint256 j = 0; j < firstBlobCount; j++) {
                    regionData[j] = harness.access(blobHashes[blobIndex], localAddress + j);
                }

                bytes32[] memory extensionData = new bytes32[](secondBlobCount);
                for (uint256 j = 0; j < secondBlobCount; j++) {
                    extensionData[j] = harness.access(blobHashes[blobIndex + 1], j);
                }

                region = _createRegion(firstBlobCount, localAddress, regionData, blobHashes[blobIndex]);
                extensionRegion = _createRegion(secondBlobCount, 0, extensionData, blobHashes[blobIndex + 1]);
            }

            // Get prior anchor for this transaction
            bytes32 challengePriorAnchor;
            if (updateNr == 0) {
                // First tx, prior is last deposit root
                uint256 lastDepositRootOffset = depositSize - 1;
                uint256 priorBlobIndex = lastDepositRootOffset / 4096;
                challengePriorAnchor = harness.access(blobHashes[priorBlobIndex], lastDepositRootOffset % 4096);
            } else {
                // Prior tx's root is at depositSize + (updateNr-1)*15 + 14
                uint256 priorRootOffset = depositSize + (updateNr - 1) * 15 + 14;
                uint256 priorBlobIndex = priorRootOffset / 4096;
                challengePriorAnchor = harness.access(blobHashes[priorBlobIndex], priorRootOffset % 4096);
            }

            // Get the true anchor (root at position 3 relative to update start)
            bytes32 trueAnchor;
            uint256 rootOffset = memoryAddress + 3;
            if (rootOffset < 4096 * (blobIndex + 1)) {
                trueAnchor = harness.access(blobHashes[blobIndex], rootOffset % 4096);
            } else {
                trueAnchor = harness.access(blobHashes[blobIndex + 1], rootOffset % 4096);
            }

            vm.prank(challenger);
            vm.expectRevert("No Fraud");
            harness.challengeTreeUpdate(
                data,
                updateNr,
                true,
                region,
                extensionRegion,
                challengePriorAnchor,
                "",
                "",
                trueAnchor,
                zkProof,
                rollbackTarget
            );
        }

        vm.resumeGasMetering();
    }

    /// @notice Fuzz test that randomly selects an update location, injects fraud, and verifies slashing
    /// @dev Uses vm.pauseGasMetering() due to high gas usage. Takes direct fuzz parameters for
    ///      better coverage by Foundry's fuzzer.
    /// @param numDeposits Number of deposits in the block (bounded to 1-100)
    /// @param numTransactions Number of transactions in the block (bounded to 1-100)
    /// @param updateNr The update index to challenge (bounded based on isTx)
    /// @param isTx Whether to challenge a transaction (true) or deposit group (false)
    function test_Fuzz_FraudAtRandomLocation(uint256 numDeposits, uint256 numTransactions, uint256 updateNr, bool isTx)
        public
    {
        vm.pauseGasMetering();

        // Bound inputs to reasonable ranges
        numDeposits = bound(numDeposits, 0, 3071);
        numTransactions = bound(numTransactions, 0, 1000);

        vm.assume(numDeposits != 0 || numTransactions != 0);
        if (isTx) {
            vm.assume(numTransactions > 0);
        } else {
            vm.assume(numDeposits > 0);
        }

        uint256 numDepositGroups = (numDeposits + 2) / 3;

        // Bound updateNr based on whether we're challenging a tx or deposit
        if (isTx) {
            updateNr = bound(updateNr, 0, numTransactions - 1);
        } else {
            updateNr = bound(updateNr, 0, numDepositGroups - 1);
        }

        // Calculate total data needed
        uint256 depositSize = ((numDeposits + 2) / 3) * 4;
        uint256 txSize = numTransactions * 15;
        uint256 totalData = depositSize + txSize;

        // Create and store data
        bytes32[] memory allData = new bytes32[](totalData);
        for (uint256 i = 0; i < totalData; i++) {
            allData[i] = keccak256(abi.encodePacked("fuzz_fraud_test", numDeposits, numTransactions, i));
        }
        bytes32[] memory blobHashes = harness.store(allData);

        // Set up the block data
        Spine.BlockData memory data;
        data.numDeposits = numDeposits;
        data.numTransactions = numTransactions;
        data.sequencer = sequencer;
        data.blobhashes = blobHashes;
        data.blockNr = 0;
        data.blockIndex = Spine.TimestampAndIndex(0, 0);

        // The final anchor is the root from the last transaction
        uint256 finalRootOffset = numTransactions != 0 ? depositSize + (numTransactions - 1) * 15 + 14 : depositSize - 1;
        uint256 finalBlobIndex = finalRootOffset / 4096;
        bytes32 finalAnchor = harness.access(blobHashes[finalBlobIndex], finalRootOffset % 4096);
        data.anchor = finalAnchor;

        // Add the block
        uint256[] memory indices = new uint256[](blobHashes.length);
        for (uint256 i = 0; i < blobHashes.length; i++) {
            indices[i] = i;
        }
        vm.blobhashes(blobHashes);

        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);

        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        uint256 memoryAddress;
        bytes32 challengePriorAnchor;

        if (isTx) {
            // Target a transaction
            memoryAddress = harness.exposedTxMemoryAddress(updateNr, numDeposits) + 11;

            // Get prior anchor
            if (updateNr == 0) {
                // Prior anchor for first tx is either the last deposit root or GENESIS if no deposits
                if (numDeposits == 0) {
                    challengePriorAnchor = GENESIS;
                } else {
                    uint256 lastDepositRootOffset = depositSize - 1;
                    uint256 priorBlobIndex = lastDepositRootOffset / 4096;
                    challengePriorAnchor = harness.access(blobHashes[priorBlobIndex], lastDepositRootOffset % 4096);
                }
            } else {
                uint256 priorRootOffset = depositSize + (updateNr - 1) * 15 + 14;
                uint256 priorBlobIndex = priorRootOffset / 4096;
                challengePriorAnchor = harness.access(blobHashes[priorBlobIndex], priorRootOffset % 4096);
            }
        } else {
            // Target a deposit GROUP - updateNr is the group index
            memoryAddress = updateNr * 4;

            // Get prior anchor for this deposit group
            if (updateNr == 0) {
                challengePriorAnchor = GENESIS;
            } else {
                // Prior root is at updateNr * 4 - 1 = previous group's root
                uint256 priorRootOffset = updateNr * 4 - 1;
                uint256 priorBlobIndex = priorRootOffset / 4096;
                challengePriorAnchor = harness.access(blobHashes[priorBlobIndex], priorRootOffset % 4096);
            }
        }

        uint256 blobIndex = memoryAddress / 4096;
        uint256 localAddress = memoryAddress % 4096;

        // Read the current data at this location
        bytes32[] memory regionData = new bytes32[](4);
        for (uint256 j = 0; j < 4; j++) {
            uint256 addr = localAddress + j;
            if (addr < 4096) {
                regionData[j] = harness.access(blobHashes[blobIndex], addr);
            } else {
                regionData[j] = harness.access(blobHashes[blobIndex + 1], addr % 4096);
            }
        }

        // The sequencer's submitted root (what's in the blob)
        bytes32 sequencerSubmittedRoot = regionData[3];

        // Inject fraud: compute the CORRECT anchor via ZK and show it differs
        // We do this by approving a ZK proof with a different trueAnchor
        bytes32 trueAnchor = keccak256(abi.encodePacked("fraud_anchor", numDeposits, numTransactions, updateNr, isTx));
        vm.assume(trueAnchor != sequencerSubmittedRoot); // Skip if collision (extremely unlikely)

        // Approve the ZK proof showing the true anchor is different from what sequencer submitted
        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        uint256[6] memory signals = [
            uint256(trueAnchor),
            uint256(challengePriorAnchor),
            uint256(regionData[0]),
            uint256(regionData[1]),
            uint256(regionData[2]),
            treeIndex
        ];
        fakeZK.approveUpdate(signals);

        // Build the region(s)
        BlobData.Region memory region;
        BlobData.Region memory extensionRegion;

        if (localAddress + 4 <= 4096) {
            region = _createRegion(4, localAddress, regionData, blobHashes[blobIndex]);
            extensionRegion = _createEmptyRegion();
        } else {
            uint256 firstBlobCount = 4096 - localAddress;
            uint256 secondBlobCount = 4 - firstBlobCount;

            bytes32[] memory firstData = new bytes32[](firstBlobCount);
            for (uint256 j = 0; j < firstBlobCount; j++) {
                firstData[j] = regionData[j];
            }

            bytes32[] memory secondData = new bytes32[](secondBlobCount);
            for (uint256 j = 0; j < secondBlobCount; j++) {
                secondData[j] = regionData[firstBlobCount + j];
            }

            region = _createRegion(firstBlobCount, localAddress, firstData, blobHashes[blobIndex]);
            extensionRegion = _createRegion(secondBlobCount, 0, secondData, blobHashes[blobIndex + 1]);
        }

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Verify sequencer is active before challenge
        (bool isActiveBefore,,,,,,) = harness.getSequencerStatus(sequencer);
        assertTrue(isActiveBefore, "Sequencer should be active before challenge");

        // Challenge - should succeed and slash the sequencer
        vm.prank(challenger);
        harness.challengeTreeUpdate(
            data,
            updateNr,
            isTx,
            region,
            extensionRegion,
            challengePriorAnchor,
            "",
            "",
            trueAnchor,
            zkProof,
            rollbackTarget
        );

        // Verify sequencer was slashed
        (bool isActiveAfter,,,,,, address payable challengerAddr) = harness.getSequencerStatus(sequencer);
        assertFalse(isActiveAfter, "Sequencer should be slashed after fraud");
        assertEq(challengerAddr, challenger, "Challenger should be recorded");

        vm.resumeGasMetering();
    }

    // ============================================================================
    // Deposit group index tests (updateNr is now GROUP index, not deposit index)
    // ============================================================================

    /// @notice Test challenging second deposit group with updateNr=1 (group index)
    /// @dev Now that updateNr is the group index:
    ///      - memoryAddress = updateNr * 4 = 1 * 4 = 4 (group 1's start)
    ///      - priorRootMemoryLocation(1) = 1 * 4 - 1 = 3 (group 0's root) ✓
    function test_DepositGroup1_ValidChallenge() public {
        // Create a block with 6 deposits (2 groups: 0 and 1)
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(6, 0, GENESIS, 0, 12345);

        // Challenge the SECOND deposit group using updateNr=1 (group index)
        uint256 updateNr = 1;
        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildDepositRegion(blobHashes, updateNr);

        bytes32 priorAnchor = _getDepositPriorAnchor(blobHashes, updateNr);
        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(priorAnchor),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Should revert with "No Fraud" since the root matches
        // Note: isLast = (updateNr == (6+2)/3) = (1 == 2) = false
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            data, updateNr, false, region, extensionRegion, priorAnchor, "", "", trueAnchor, zkProof, rollbackTarget
        );
    }

    /// @notice Test that updateNr=0 still works correctly (uses GENESIS path)
    function test_DepositGroup0_ValidChallenge() public {
        (Spine.BlockData memory data, bytes32[] memory blobHashes) = _createAndAddBlock(6, 0, GENESIS, 0, 12345);

        // Challenge with updateNr=0 (first group) - uses GENESIS as prior
        (BlobData.Region memory region, BlobData.Region memory extensionRegion, bytes32[] memory regionData) =
            _buildDepositRegion(blobHashes, 0);

        bytes32 trueAnchor = regionData[3];
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        fakeZK.approveUpdate(
            [
                uint256(trueAnchor),
                uint256(GENESIS),
                uint256(regionData[0]),
                uint256(regionData[1]),
                uint256(regionData[2]),
                treeIndex
            ]
        );

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        // Should work correctly and revert with "No Fraud"
        vm.prank(challenger);
        vm.expectRevert("No Fraud");
        harness.challengeTreeUpdate(
            data, 0, false, region, extensionRegion, GENESIS, "", "", trueAnchor, zkProof, rollbackTarget
        );
    }

    // ============================================================================
    // Extension region validation tests
    // ============================================================================

    /// @notice Helper struct to reduce stack depth in extension region tests
    struct ExtensionTestSetup {
        bytes32[] blobHashes;
        bytes32 regionDataElement;
        bytes32 extensionData0;
        bytes32 extensionData1;
        bytes32 extensionData2;
        bytes32 priorAnchor;
    }

    /// @notice Sets up common data for extension region validation tests
    function _setupExtensionRegionTest() internal returns (ExtensionTestSetup memory setup) {
        uint256 numTransactions = 273;
        uint256 totalData = 4 + numTransactions * 15;

        bytes32[] memory allData = new bytes32[](totalData);
        for (uint256 i = 0; i < totalData; i++) {
            allData[i] = keccak256(abi.encodePacked("extension_validation_test", i));
        }

        setup.blobHashes = harness.store(allData);
        setup.regionDataElement = harness.access(setup.blobHashes[0], 4095);
        setup.extensionData0 = harness.access(setup.blobHashes[1], 0);
        setup.extensionData1 = harness.access(setup.blobHashes[1], 1);
        setup.extensionData2 = harness.access(setup.blobHashes[1], 2);
        setup.priorAnchor = harness.access(setup.blobHashes[0], 4083);
    }

    /// @notice Creates and adds block for extension region tests
    function _addExtensionTestBlock(ExtensionTestSetup memory setup) internal returns (Spine.BlockData memory data) {
        data.numDeposits = 3;
        data.numTransactions = 273;
        data.sequencer = sequencer;
        data.blobhashes = setup.blobHashes;
        data.anchor = setup.extensionData2;

        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;
        vm.blobhashes(setup.blobHashes);

        vm.prank(sequencer);
        data = harness.addBlockTest(data, indices);
    }

    /// @notice Test extension region validation - wrong blob hash reverts
    function test_ExtensionRegion_WrongHashReverts() public {
        ExtensionTestSetup memory setup = _setupExtensionRegionTest();
        Spine.BlockData memory data = _addExtensionTestBlock(setup);

        bytes32[] memory regionData = new bytes32[](1);
        regionData[0] = setup.regionDataElement;
        BlobData.Region memory region = _createRegion(1, 4095, regionData, setup.blobHashes[0]);

        bytes32[] memory extensionData = new bytes32[](3);
        extensionData[0] = setup.extensionData0;
        extensionData[1] = setup.extensionData1;
        extensionData[2] = setup.extensionData2;

        BlobData.Region memory badHashExtension = _createRegion(3, 0, extensionData, keccak256("wrong_hash"));

        bytes32 trueAnchor = keccak256("some_anchor");
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        uint256[6] memory signals = [
            uint256(trueAnchor),
            uint256(setup.priorAnchor),
            uint256(regionData[0]),
            uint256(extensionData[0]),
            uint256(extensionData[1]),
            treeIndex
        ];
        fakeZK.approveUpdate(signals);

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 272, true, region, badHashExtension, setup.priorAnchor, "", "", trueAnchor, zkProof, rollbackTarget
        );
    }

    /// @notice Test extension region validation - wrong memory address reverts (must be 0)
    function test_ExtensionRegion_WrongMemoryAddressReverts() public {
        ExtensionTestSetup memory setup = _setupExtensionRegionTest();
        Spine.BlockData memory data = _addExtensionTestBlock(setup);

        bytes32[] memory regionData = new bytes32[](1);
        regionData[0] = setup.regionDataElement;
        BlobData.Region memory region = _createRegion(1, 4095, regionData, setup.blobHashes[0]);

        bytes32[] memory extensionData = new bytes32[](3);
        extensionData[0] = setup.extensionData0;
        extensionData[1] = setup.extensionData1;
        extensionData[2] = setup.extensionData2;

        BlobData.Region memory badAddrExtension = _createRegion(3, 1, extensionData, setup.blobHashes[1]);

        bytes32 trueAnchor = keccak256("some_anchor");
        uint256 treeIndex = uint256(data.blockIndex.day) * (2 ** 13) + uint256(data.blockIndex.index);

        // Signal order: [trueAnchor, priorAnchor, u0, u1, u2, treeIndex]
        uint256[6] memory signals = [
            uint256(trueAnchor),
            uint256(setup.priorAnchor),
            uint256(regionData[0]),
            uint256(extensionData[0]),
            uint256(extensionData[1]),
            treeIndex
        ];
        fakeZK.approveUpdate(signals);

        Proof memory zkProof;
        Spine.BlockData memory rollbackTarget;

        vm.prank(challenger);
        vm.expectRevert();
        harness.challengeTreeUpdate(
            data, 272, true, region, badAddrExtension, setup.priorAnchor, "", "", trueAnchor, zkProof, rollbackTarget
        );
    }
}
