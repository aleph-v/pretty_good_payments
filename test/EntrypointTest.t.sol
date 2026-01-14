// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Entrypoint.sol";
import {FakeZK} from "./mocks/FakeZk.sol";
import {FakeBlobs} from "./mocks/FakeBlobs.sol";
import {MockTransactionRegistry} from "./mocks/MockTransactionRegistry.sol";
import {MockYieldRouter} from "./mocks/MockYieldRouter.sol";

contract EntrypointHarness is Entrypoint, FakeBlobs {
    constructor(
        bytes32 genesis,
        IYieldRouter _yieldRouter,
        IUpdateVerifier _predictableUpdateVerifier,
        ITransferVerifier _transactionZkVerifier,
        ITransactionRegistry _transferRegistry
    ) Entrypoint(genesis, _yieldRouter, _predictableUpdateVerifier, _transactionZkVerifier, _transferRegistry) {
        _initializeOwner(msg.sender);
    }

    function setupBlobData(uint256 numDeposits, uint256 numTx, uint256 seed) public returns (bytes32[] memory) {
        uint256 depositSize = numDeposits % 3 == 0 ? (numDeposits / 3) * 4 : (numDeposits / 3 + 1) * 4;
        uint256 dataNeeded = depositSize + numTx * 15;
        if (dataNeeded == 0) dataNeeded = 1;
        bytes32[] memory randomData = new bytes32[](dataNeeded);
        for (uint256 i = 0; i < dataNeeded; i++) {
            randomData[i] = keccak256(abi.encodePacked(i, seed));
        }
        return store(randomData);
    }

    function fundSequencer(address who) external payable {
        sequencers[who].isActive = true;
        sequencers[who].stakeAmount += uint64(msg.value / (10 ** 14));
    }

    function getSequencerBlobUse(uint256 epoch, address seq) external view returns (uint256) {
        return sequencerBlobUse[epoch][seq];
    }

    function getTotalBlobUse(uint256 epoch) external view returns (uint256) {
        return totalBlobUse[epoch];
    }

    receive() external payable {}
}

contract EntrypointTest is Test {
    EntrypointHarness entrypoint;
    MockYieldRouter yieldRouter;
    FakeZK fakeZK;
    MockTransactionRegistry txRegistry;

    address sequencer1 = address(0x1111);
    address sequencer2 = address(0x2222);

    bytes32 constant GENESIS = keccak256("genesis");
    uint256 constant EPOCH_LENGTH = 10;
    uint256 constant CHALLENGE_PERIOD = 100;

    function setUp() public {
        yieldRouter = new MockYieldRouter();
        fakeZK = new FakeZK();
        txRegistry = new MockTransactionRegistry();

        entrypoint = new EntrypointHarness(
            GENESIS,
            IYieldRouter(address(yieldRouter)),
            IUpdateVerifier(address(fakeZK)),
            ITransferVerifier(address(fakeZK)),
            ITransactionRegistry(address(txRegistry))
        );

        vm.deal(sequencer1, 100 ether);
        vm.deal(sequencer2, 100 ether);
        entrypoint.fundSequencer{value: 20 ether}(sequencer1);
        entrypoint.fundSequencer{value: 20 ether}(sequencer2);
    }

    function _createBlockData(uint256 numDeposits, uint256 numTx, uint256 seed)
        internal
        returns (Spine.BlockData memory, uint256[] memory)
    {
        bytes32[] memory blobhashes = entrypoint.setupBlobData(numDeposits, numTx, seed);
        vm.blobhashes(blobhashes);

        Spine.BlockData memory data = Spine.BlockData({
            anchor: keccak256(abi.encodePacked("anchor", seed)),
            timestamp: 0,
            numTransactions: numTx,
            numDeposits: numDeposits,
            blockNr: 0,
            blockIndex: Spine.TimestampAndIndex(0, 0),
            sequencer: address(0),
            blobhashes: blobhashes
        });

        uint256[] memory indices = new uint256[](blobhashes.length);
        for (uint256 i = 0; i < blobhashes.length; i++) {
            indices[i] = i;
        }
        return (data, indices);
    }

    function test_CurrentEpoch() public {
        // Epoch calculation
        (uint256 epoch0, bool closed0) = entrypoint.currentEpoch();
        assertEq(epoch0, 0);
        assertTrue(closed0, "Start of epoch should be closed period");

        vm.warp(block.timestamp + 10);
        (uint256 epoch1,) = entrypoint.currentEpoch();
        assertEq(epoch1, 1);

        // Closed period is first half of epoch
        vm.warp(block.timestamp + 14); // 24 seconds total, epoch 2, 4 seconds in
        (, bool closed1) = entrypoint.currentEpoch();
        assertTrue(closed1);

        vm.warp(block.timestamp + 1); // 25 seconds, 5 seconds into epoch = open period
        (, bool closed2) = entrypoint.currentEpoch();
        assertFalse(closed2);
    }

    function test_IsFinalized() public {
        // minEpochsWait = CHALLENGE_PERIOD/EPOCH_LENGTH + 1 = 11
        assertFalse(entrypoint.isFinalized(0), "Epoch 0 not finalized at epoch 0");

        vm.warp(block.timestamp + 110); // epoch 11
        assertFalse(entrypoint.isFinalized(0), "Epoch 0 not finalized at epoch 11");

        vm.warp(block.timestamp + 10); // epoch 12
        assertTrue(entrypoint.isFinalized(0), "Epoch 0 finalized at epoch 12");

        // At epoch 20, check various epochs
        vm.warp(block.timestamp + 80); // epoch 20
        assertFalse(entrypoint.isFinalized(10), "Recent epoch not finalized");
        assertTrue(entrypoint.isFinalized(8), "Old epoch finalized");
    }

    function test_Post_BlobUseTracking() public {
        entrypoint.addFirstLook(sequencer1);

        // Test priority bonus in closed period
        (uint256 epoch, bool inClosedPeriod) = entrypoint.currentEpoch();
        assertTrue(inClosedPeriod);

        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(3, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);

        uint256 expectedRaw = 10 * 15 + 4; // 154 (3 deposits = 4 blob units)
        assertEq(entrypoint.getSequencerBlobUse(epoch, sequencer1), expectedRaw * 2, "Priority bonus 2x");

        // Test no bonus in open period
        vm.warp(block.timestamp + 7);
        (, inClosedPeriod) = entrypoint.currentEpoch();
        assertFalse(inClosedPeriod);

        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(0, 10, 200);
        vm.prank(sequencer2);
        entrypoint.post(data2, indices2);

        assertEq(entrypoint.getSequencerBlobUse(epoch, sequencer2), 150, "No bonus in open period");
        assertEq(entrypoint.getTotalBlobUse(epoch), expectedRaw * 2 + 150, "Total tracks both");
    }

    function test_Post_EdgeCases() public {
        // Works with no priority sequencers (open period only)
        vm.warp(block.timestamp + 7);
        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(1, 1, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);
        assertGt(entrypoint.getSequencerBlobUse(0, sequencer1), 0);

        // Works at epoch 0 with priority sequencer
        entrypoint.addFirstLook(sequencer2);
        vm.warp(block.timestamp - 7); // back to start
        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(1, 1, 200);
        vm.prank(sequencer2);
        entrypoint.post(data2, indices2);
        assertGt(entrypoint.getSequencerBlobUse(0, sequencer2), 0);

        // Works when prior epoch had no activity
        vm.warp(block.timestamp + 55);
        (uint256 epoch,) = entrypoint.currentEpoch();
        assertEq(entrypoint.getTotalBlobUse(epoch - 1), 0);
        (Spine.BlockData memory data3, uint256[] memory indices3) = _createBlockData(1, 1, 300);
        vm.prank(sequencer2);
        entrypoint.post(data3, indices3);
        assertGt(entrypoint.getSequencerBlobUse(epoch, sequencer2), 0);
    }

    function test_Post_IsAllowed() public {
        entrypoint.addFirstLook(sequencer1);
        entrypoint.addFirstLook(sequencer2);

        // In closed period, only priority sequencer allowed
        vm.warp(block.timestamp + 20);
        (uint256 epoch, bool inClosedPeriod) = entrypoint.currentEpoch();
        assertTrue(inClosedPeriod);

        address nonPrioritySeq = (epoch % 2 == 0) ? sequencer2 : sequencer1;
        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(1, 1, 100);
        vm.prank(nonPrioritySeq);
        vm.expectRevert();
        entrypoint.post(data1, indices1);

        // In open period, any active sequencer allowed
        vm.warp(block.timestamp + 7);
        (, inClosedPeriod) = entrypoint.currentEpoch();
        assertFalse(inClosedPeriod);

        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(1, 1, 200);
        vm.prank(nonPrioritySeq);
        entrypoint.post(data2, indices2); // should not revert
    }

    function test_GetPercentInEpoch() public {
        entrypoint.addFirstLook(sequencer1);
        vm.warp(block.timestamp + 7); // open period

        // Single sequencer gets 100%
        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(0, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);

        vm.warp(block.timestamp + 10); // next epoch
        assertEq(entrypoint.getPercentInEpoch(sequencer1, 0), 1e18, "Single sequencer = 100%");

        // Sequencer with no activity gets 0%
        assertEq(entrypoint.getPercentInEpoch(sequencer2, 0), 0, "No activity = 0%");

        // Empty epoch returns 0
        assertEq(entrypoint.getTotalBlobUse(1), 0);
        vm.warp(block.timestamp + 10);
        assertEq(entrypoint.getPercentInEpoch(sequencer1, 1), 0, "Empty epoch = 0%");
    }

    function test_GetPercentInEpoch_MultipleSequencers() public {
        entrypoint.addFirstLook(sequencer1);
        vm.warp(block.timestamp + 7);

        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(0, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);

        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(0, 10, 200);
        vm.prank(sequencer2);
        entrypoint.post(data2, indices2);

        vm.warp(block.timestamp + 10);
        assertEq(entrypoint.getPercentInEpoch(sequencer1, 0), 0.5e18);
        assertEq(entrypoint.getPercentInEpoch(sequencer2, 0), 0.5e18);
    }

    function test_GetPercentInEpoch_RevertsForCurrentEpoch() public {
        entrypoint.addFirstLook(sequencer1);
        (Spine.BlockData memory data, uint256[] memory indices) = _createBlockData(0, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data, indices);

        (uint256 epoch,) = entrypoint.currentEpoch();
        vm.expectRevert("Not finished");
        entrypoint.getPercentInEpoch(sequencer1, epoch);
    }
}
