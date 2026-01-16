// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {DepositChallenge} from "../src/DepositChallenge.sol";
import {Spine} from "../src/Spine.sol";
import {FakeBlobs} from "./mocks/FakeBlobs.sol";
import {NoFraud, DepositIndexOutOfBounds} from "../src/library/Errors.sol";

contract DepositChallengeHarness is DepositChallenge, FakeBlobs {
    constructor() {
        _initializeOwner(msg.sender);
    }

    function setupBlocks(BlockData memory data, uint256 seed) public returns (BlockData memory, bytes32[] memory ret) {
        uint256 depositSize = data.numDeposits % 3 == 0 ? (data.numDeposits / 3) * 4 : (data.numDeposits / 3 + 1) * 4;
        uint256 dataNeeded = depositSize + data.numTransactions * 15;
        if (dataNeeded == 0) dataNeeded = 1;
        bytes32[] memory randomData = new bytes32[](dataNeeded);
        for (uint256 i = 0; i < dataNeeded; i++) {
            randomData[i] = keccak256(abi.encodePacked(i, seed));
        }
        ret = store(randomData);
        data.blobhashes = ret;
        return (data, ret);
    }

    function addBlockTest(BlockData memory data, uint256[] memory indices) public returns (BlockData memory) {
        addBlock(data, indices);
        return data;
    }

    function validateSingle(bytes32 rootHash, bytes calldata, uint256 index, bytes32 data, bytes calldata)
        internal
        view
        override
    {
        require(access(rootHash, index) == data, "Blob data mismatch");
    }

    function fundSequencer() public payable {
        sequencers[msg.sender].isActive = true;
        sequencers[msg.sender].stakeAmount += uint64(msg.value / (10 ** 14));
    }

    function getSequencerStatus(address seq) public view returns (bool isActive, address payable challenger) {
        return (sequencers[seq].isActive, sequencers[seq].challenger);
    }

    function getBlockCount() public view returns (uint256) {
        return getCurrentBlocknumber();
    }

    function getLeafMemoryAddress(uint256 depositNr, uint256 numDeposits) public pure returns (uint256) {
        return leafMemoryAddress(depositNr, numDeposits, true, 0);
    }

    function setPerBlockDeposit(uint256 blockNr, bytes32 depositLeaf) public {
        perBlockDeposits[blockNr].push(depositLeaf);
    }

    function getPerBlockDepositsLength(uint256 blockNr) public view returns (uint256) {
        return perBlockDeposits[blockNr].length;
    }

    receive() external payable {}
}

contract DepositChallengeTest is Test {
    DepositChallengeHarness harness;
    address sequencer = address(0x1234);
    address challenger = address(0x5678);

    function setUp() public {
        harness = new DepositChallengeHarness();
        vm.deal(sequencer, 100 ether);
        vm.prank(sequencer);
        harness.fundSequencer{value: 20 ether}();
    }

    function _createBlock(uint256 numDeposits, uint256 numTx, uint256 seed)
        internal
        returns (Spine.BlockData memory, bytes32[] memory)
    {
        Spine.BlockData memory blockData = Spine.BlockData({
            anchor: keccak256(abi.encodePacked("anchor", seed)),
            timestamp: block.timestamp,
            numTransactions: numTx,
            numDeposits: numDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(0, 0),
            sequencer: sequencer,
            blobhashes: new bytes32[](1)
        });
        (blockData,) = harness.setupBlocks(blockData, seed);
        return (blockData, blockData.blobhashes);
    }

    function _addBlock(Spine.BlockData memory blockData) internal returns (Spine.BlockData memory) {
        vm.blobhashes(blockData.blobhashes);
        uint256[] memory indices = new uint256[](blockData.blobhashes.length);
        for (uint256 i = 0; i < blockData.blobhashes.length; i++) {
            indices[i] = i;
        }
        return harness.addBlockTest(blockData, indices);
    }

    function _setDeposits(uint256 blockNr, uint256 count) internal {
        for (uint256 i = 0; i < count; i++) {
            harness.setPerBlockDeposit(blockNr, keccak256(abi.encodePacked("deposit", i)));
        }
    }

    // ==================== CORE TESTS ====================

    function test_ChallengeWrongLeaf_Success() public {
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(3, 1, 123);
        blockData = _addBlock(blockData);
        assertEq(harness.getBlockCount(), 1, "Should have 1 block before");

        harness.setPerBlockDeposit(blockData.blockNr, keccak256("expected_deposit"));

        uint256 leafAddr = harness.getLeafMemoryAddress(0, 3);
        bytes32 wrongLeaf = harness.access(blobhashes[0], leafAddr);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 0, wrongLeaf, "", "", emptyPrior);

        (bool isActive, address payable currentChallenger) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed");
        assertEq(currentChallenger, challenger, "Challenger should be recorded");
        assertEq(harness.getBlockCount(), 0, "Block should be rolled back");
    }

    function test_ChallengeWrongLeaf_NoFraud_Reverts() public {
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(3, 1, 456);
        blockData = _addBlock(blockData);

        uint256 leafAddr = harness.getLeafMemoryAddress(0, 3);
        bytes32 actualLeaf = harness.access(blobhashes[0], leafAddr);

        // Must set all 3 deposits so count matches numDeposits
        harness.setPerBlockDeposit(blockData.blockNr, actualLeaf);
        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit1"));
        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit2"));

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(NoFraud.selector);
        harness.challengeDepositWrongLeaf(blockData, 0, actualLeaf, "", "", emptyPrior);
    }

    // ==================== BOUNDS & VALIDATION ====================

    function test_DepositNr_OutOfBounds_Reverts() public {
        (Spine.BlockData memory blockData,) = _createBlock(3, 1, 789);
        blockData = _addBlock(blockData);
        _setDeposits(blockData.blockNr, 3);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(DepositIndexOutOfBounds.selector);
        harness.challengeDepositWrongLeaf(blockData, 3, bytes32(0), "", "", emptyPrior);
    }

    function test_ZeroDeposits_Reverts() public {
        (Spine.BlockData memory blockData,) = _createBlock(0, 1, 222);
        blockData = _addBlock(blockData);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(DepositIndexOutOfBounds.selector);
        harness.challengeDepositWrongLeaf(blockData, 0, bytes32(0), "", "", emptyPrior);
    }

    function test_NonIncludedBlock_Reverts() public {
        // Test 1: Completely fake block
        Spine.BlockData memory fakeBlock = Spine.BlockData({
            anchor: keccak256("fake"),
            timestamp: block.timestamp,
            numTransactions: 1,
            numDeposits: 3,
            blockNr: 999,
            blockIndex: Spine.TimestampAndIndex(0, 0),
            sequencer: sequencer,
            blobhashes: new bytes32[](1)
        });
        fakeBlock.blobhashes[0] = keccak256("fake_blob");

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(); // Reverts with panic (array out of bounds) for non-existent block
        harness.challengeDepositWrongLeaf(fakeBlock, 0, bytes32(0), "", "", emptyPrior);

        // Test 2: Real block with modified data
        (Spine.BlockData memory blockData,) = _createBlock(3, 1, 333);
        blockData = _addBlock(blockData);
        blockData.numDeposits = 5; // Modify after adding

        vm.prank(challenger);
        vm.expectRevert(); // Reverts with panic (array out of bounds) for modified block
        harness.challengeDepositWrongLeaf(blockData, 0, bytes32(0), "", "", emptyPrior);
    }

    function test_BlobDataMismatch_Reverts() public {
        (Spine.BlockData memory blockData,) = _createBlock(3, 1, 2828);
        blockData = _addBlock(blockData);
        _setDeposits(blockData.blockNr, 3);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert("Blob data mismatch");
        harness.challengeDepositWrongLeaf(blockData, 0, keccak256("wrong_leaf"), "", "", emptyPrior);
    }

    // ==================== NUM DEPOSITS MISMATCH ====================

    function test_NumDepositsMismatch_TriggersSlash() public {
        // Block claims 3 deposits but perBlockDeposits is empty
        (Spine.BlockData memory blockData,) = _createBlock(3, 1, 2525);
        blockData = _addBlock(blockData);

        assertEq(harness.getPerBlockDepositsLength(blockData.blockNr), 0);
        assertEq(blockData.numDeposits, 3);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 0, bytes32(0), "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed");
        assertEq(harness.getBlockCount(), 0, "Block should be rolled back");
    }

    // ==================== DOUBLE CHALLENGE ====================

    function test_DoubleChallenge_SecondReverts() public {
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(3, 1, 2222);
        blockData = _addBlock(blockData);
        _setDeposits(blockData.blockNr, 3);

        uint256 leafAddr = harness.getLeafMemoryAddress(0, 3);
        bytes32 wrongLeaf = harness.access(blobhashes[0], leafAddr);

        Spine.BlockData memory emptyPrior;

        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 0, wrongLeaf, "", "", emptyPrior);

        // Block rolled back, second challenge should fail
        vm.prank(challenger);
        vm.expectRevert(); // Reverts with panic (array out of bounds) after rollback
        harness.challengeDepositWrongLeaf(blockData, 1, wrongLeaf, "", "", emptyPrior);
    }

    // ==================== FUZZ TEST ====================

    function testFuzz_ValidChallenge(uint256 seed, uint8 numDeposits, uint8 depositNr) public {
        numDeposits = uint8(bound(numDeposits, 1, 100));
        depositNr = uint8(bound(depositNr, 0, numDeposits - 1));

        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(numDeposits, 1, seed);
        blockData = _addBlock(blockData);

        for (uint256 i = 0; i < numDeposits; i++) {
            harness.setPerBlockDeposit(blockData.blockNr, keccak256(abi.encodePacked("expected", i, seed)));
        }

        uint256 leafAddr = harness.getLeafMemoryAddress(depositNr, numDeposits);
        bytes32 wrongLeaf = harness.access(blobhashes[0], leafAddr);

        // Skip if by chance they match
        bytes32 expected = keccak256(abi.encodePacked("expected", uint256(depositNr), seed));
        if (wrongLeaf == expected) return;

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, depositNr, wrongLeaf, "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed");
    }
}
