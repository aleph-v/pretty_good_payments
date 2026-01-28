// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DepositChallenge} from "../src/DepositChallenge.sol";
import {Spine} from "../src/Spine.sol";
import {FakeBlobs} from "./mocks/FakeBlobs.sol";
import {
    NoFraud,
    NotPartialDepositGroup,
    DepositPaddingIndexOutOfBounds
} from "../src/library/Errors.sol";
import {LibBit} from "solady/utils/LibBit.sol";

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

    function setBlobDataAtIndex(bytes32 blobHash, uint256 index, bytes32 value) public {
        // storeAt stores directly, but access reads with bit reversal
        // So we need to bit reverse the index before storing
        uint256 reversed = LibBit.reverseBits(index) >> 244;
        storedBlobData[blobHash][reversed] = value;
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

    function test_DepositNr_OutOfBounds_FullGroup_Reverts() public {
        // With full group (numDeposits=3), depositNr=3 reverts with NotPartialDepositGroup
        // because the new partial group logic intercepts the case
        (Spine.BlockData memory blockData,) = _createBlock(3, 1, 789);
        blockData = _addBlock(blockData);
        _setDeposits(blockData.blockNr, 3);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(NotPartialDepositGroup.selector);
        harness.challengeDepositWrongLeaf(blockData, 3, bytes32(0), "", "", emptyPrior);
    }

    function test_ZeroDeposits_Reverts() public {
        // With zero deposits (numDeposits=0), depositNr=0 reverts with NotPartialDepositGroup
        // because 0 % 3 == 0 is a "full group" (no partial)
        (Spine.BlockData memory blockData,) = _createBlock(0, 1, 222);
        blockData = _addBlock(blockData);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(NotPartialDepositGroup.selector);
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

    // ==================== PARTIAL GROUP PADDING TESTS ====================

    function test_PartialGroup_OneDeposit_NonZeroPaddingAtIndex1_Success() public {
        // numDeposits=1, so positions 1 and 2 must be zero (partial group of 3)
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(1, 1, 5001);
        blockData = _addBlock(blockData);

        // Set the one expected deposit
        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit0"));

        // Set non-zero value at padding position 1 (this is fraud)
        // leafMemoryAddress(depositNr=1, numDeposits=2, isDeposit=true, which=0) gives us the address
        uint256 paddingAddr = harness.getLeafMemoryAddress(1, 2);
        bytes32 nonZeroValue = keccak256("malicious_padding");
        harness.setBlobDataAtIndex(blobhashes[0], paddingAddr, nonZeroValue);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 1, nonZeroValue, "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for non-zero padding");
        assertEq(harness.getBlockCount(), 0, "Block should be rolled back");
    }

    function test_PartialGroup_OneDeposit_NonZeroPaddingAtIndex2_Success() public {
        // numDeposits=1, challenge position 2 (second padding position)
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(1, 1, 5002);
        blockData = _addBlock(blockData);

        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit0"));

        // Set non-zero value at padding position 2
        uint256 paddingAddr = harness.getLeafMemoryAddress(2, 3);
        bytes32 nonZeroValue = keccak256("malicious_padding_2");
        harness.setBlobDataAtIndex(blobhashes[0], paddingAddr, nonZeroValue);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 2, nonZeroValue, "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for non-zero padding");
    }

    function test_PartialGroup_TwoDeposits_NonZeroPaddingAtIndex2_Success() public {
        // numDeposits=2, so position 2 must be zero
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(2, 1, 5003);
        blockData = _addBlock(blockData);

        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit0"));
        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit1"));

        // Set non-zero value at padding position 2
        uint256 paddingAddr = harness.getLeafMemoryAddress(2, 3);
        bytes32 nonZeroValue = keccak256("malicious_padding");
        harness.setBlobDataAtIndex(blobhashes[0], paddingAddr, nonZeroValue);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 2, nonZeroValue, "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for non-zero padding");
    }

    function test_PartialGroup_FourDeposits_NonZeroPaddingAtIndex4_Success() public {
        // numDeposits=4, so positions 4 and 5 must be zero (second group has 1 real deposit)
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(4, 1, 5004);
        blockData = _addBlock(blockData);

        for (uint256 i = 0; i < 4; i++) {
            harness.setPerBlockDeposit(blockData.blockNr, keccak256(abi.encodePacked("deposit", i)));
        }

        // Set non-zero value at padding position 4
        uint256 paddingAddr = harness.getLeafMemoryAddress(4, 5);
        bytes32 nonZeroValue = keccak256("malicious_padding");
        harness.setBlobDataAtIndex(blobhashes[0], paddingAddr, nonZeroValue);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 4, nonZeroValue, "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for non-zero padding");
    }

    function test_PartialGroup_FiveDeposits_NonZeroPaddingAtIndex5_Success() public {
        // numDeposits=5, so position 5 must be zero (second group has 2 real deposits)
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(5, 1, 5005);
        blockData = _addBlock(blockData);

        for (uint256 i = 0; i < 5; i++) {
            harness.setPerBlockDeposit(blockData.blockNr, keccak256(abi.encodePacked("deposit", i)));
        }

        // Set non-zero value at padding position 5
        uint256 paddingAddr = harness.getLeafMemoryAddress(5, 6);
        bytes32 nonZeroValue = keccak256("malicious_padding");
        harness.setBlobDataAtIndex(blobhashes[0], paddingAddr, nonZeroValue);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, 5, nonZeroValue, "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for non-zero padding");
    }

    function test_PartialGroup_ZeroPaddingLeaf_NoFraud_Reverts() public {
        // numDeposits=1, padding position 1 is correctly zero - no fraud
        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(1, 1, 5006);
        blockData = _addBlock(blockData);

        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit0"));

        // Padding position should already be zero (default), but let's explicitly set it
        uint256 paddingAddr = harness.getLeafMemoryAddress(1, 2);
        harness.setBlobDataAtIndex(blobhashes[0], paddingAddr, bytes32(0));

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(NoFraud.selector);
        harness.challengeDepositWrongLeaf(blockData, 1, bytes32(0), "", "", emptyPrior);
    }

    function test_FullGroup_CannotChallengePadding_Reverts() public {
        // numDeposits=3 (full group), cannot challenge position 3 as padding
        (Spine.BlockData memory blockData,) = _createBlock(3, 1, 5007);
        blockData = _addBlock(blockData);

        for (uint256 i = 0; i < 3; i++) {
            harness.setPerBlockDeposit(blockData.blockNr, keccak256(abi.encodePacked("deposit", i)));
        }

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(NotPartialDepositGroup.selector);
        harness.challengeDepositWrongLeaf(blockData, 3, bytes32(0), "", "", emptyPrior);
    }

    function test_FullGroup_SixDeposits_CannotChallengePadding_Reverts() public {
        // numDeposits=6 (two full groups), cannot challenge position 6 as padding
        (Spine.BlockData memory blockData,) = _createBlock(6, 1, 5008);
        blockData = _addBlock(blockData);

        for (uint256 i = 0; i < 6; i++) {
            harness.setPerBlockDeposit(blockData.blockNr, keccak256(abi.encodePacked("deposit", i)));
        }

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(NotPartialDepositGroup.selector);
        harness.challengeDepositWrongLeaf(blockData, 6, bytes32(0), "", "", emptyPrior);
    }

    function test_PartialGroup_TooFarOut_Reverts() public {
        // numDeposits=1, try to challenge position 3 (outside the partial group)
        (Spine.BlockData memory blockData,) = _createBlock(1, 1, 5009);
        blockData = _addBlock(blockData);

        harness.setPerBlockDeposit(blockData.blockNr, keccak256("deposit0"));

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(DepositPaddingIndexOutOfBounds.selector);
        harness.challengeDepositWrongLeaf(blockData, 3, bytes32(0), "", "", emptyPrior);
    }

    function test_PartialGroup_FourDeposits_TooFarOut_Reverts() public {
        // numDeposits=4, try to challenge position 6 (outside the partial group of 4,5)
        (Spine.BlockData memory blockData,) = _createBlock(4, 1, 5010);
        blockData = _addBlock(blockData);

        for (uint256 i = 0; i < 4; i++) {
            harness.setPerBlockDeposit(blockData.blockNr, keccak256(abi.encodePacked("deposit", i)));
        }

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        vm.expectRevert(DepositPaddingIndexOutOfBounds.selector);
        harness.challengeDepositWrongLeaf(blockData, 6, bytes32(0), "", "", emptyPrior);
    }

    function testFuzz_PartialGroup_NonZeroPadding(uint256 seed, uint8 numDeposits) public {
        // Ensure partial group (not divisible by 3) and at least 1 deposit
        numDeposits = uint8(bound(numDeposits, 1, 100));
        vm.assume(numDeposits % 3 != 0);

        (Spine.BlockData memory blockData, bytes32[] memory blobhashes) = _createBlock(numDeposits, 1, seed);
        blockData = _addBlock(blockData);

        for (uint256 i = 0; i < numDeposits; i++) {
            harness.setPerBlockDeposit(blockData.blockNr, keccak256(abi.encodePacked("deposit", i, seed)));
        }

        // Challenge the first padding position (numDeposits)
        uint256 paddingIndex = numDeposits;
        uint256 paddingAddr = harness.getLeafMemoryAddress(paddingIndex, paddingIndex + 1);
        bytes32 nonZeroValue = keccak256(abi.encodePacked("malicious", seed));
        harness.setBlobDataAtIndex(blobhashes[0], paddingAddr, nonZeroValue);

        Spine.BlockData memory emptyPrior;
        vm.prank(challenger);
        harness.challengeDepositWrongLeaf(blockData, paddingIndex, nonZeroValue, "", "", emptyPrior);

        (bool isActive,) = harness.getSequencerStatus(sequencer);
        assertFalse(isActive, "Sequencer should be slashed for non-zero padding");
    }
}
