// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Entrypoint} from "../src/Entrypoint.sol";
import {Spine} from "../src/Spine.sol";
import {IYieldRouter} from "../src/interfaces/IYieldRouter.sol";
import {IUpdateVerifier} from "../src/interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "../src/interfaces/ITransferVerifier.sol";
import {ITransactionRegistry} from "../src/TransactionRegistry.sol";
import {PredictableMerkleLib, Leaf} from "../src/library/PredictableMerkleLib.sol";
import {FakeZK} from "./mocks/FakeZk.sol";
import {FakeBlobs} from "./mocks/FakeBlobs.sol";
import {MockTransactionRegistry} from "./mocks/MockTransactionRegistry.sol";
import {MockYieldRouter} from "./mocks/MockYieldRouter.sol";
import {EpochNotFinished, NotAllowed} from "../src/library/Errors.sol";

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

    // Expose constants for testing
    function getEpochLength() external pure returns (uint256) {
        return EPOCH_LENGTH;
    }

    function getChallengePeriod() external pure returns (uint256) {
        return CHALLENGE_PERIOD;
    }

    // Setup deposits for a specific block using real leaf hashes (bypasses actual deposit flow for testing)
    function setupDepositsForBlock(uint256 blockNr, uint256 count, address asset) external {
        for (uint256 i = 0; i < count; i++) {
            Leaf memory leaf = Leaf({
                asset: asset,
                amount: 1 ether * (i + 1),
                blinding: BLINDING, // Use the constant blinding factor
                publicKey: bytes32(uint256(i + 1))
            });
            perBlockDeposits[blockNr].push(PredictableMerkleLib.hash(leaf));
        }
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

        // Block number must be sequential
        uint256 currentBlockNr = entrypoint.getCurrentBlocknumber();

        Spine.BlockData memory data = Spine.BlockData({
            anchor: keccak256(abi.encodePacked("anchor", seed)),
            timestamp: 0,
            numTransactions: numTx,
            numDeposits: numDeposits,
            blockNr: currentBlockNr,
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

    // Helper to create block data that matches actual registered deposits for the current block
    function _createBlockDataWithActualDeposits(uint256 numTx, uint256 seed)
        internal
        returns (Spine.BlockData memory, uint256[] memory)
    {
        uint256 currentBlockNr = entrypoint.getCurrentBlocknumber();
        // Get the actual deposit count for this block from the contract
        uint256 actualDeposits = entrypoint.getDepositArray(currentBlockNr).length;
        return _createBlockData(actualDeposits, numTx, seed);
    }

    function test_CurrentEpoch() public {
        uint256 epochLength = entrypoint.getEpochLength();

        // Epoch calculation
        (uint256 epoch0, bool closed0) = entrypoint.currentEpoch();
        assertEq(epoch0, 0);
        assertTrue(closed0, "Start of epoch should be closed period");

        vm.warp(block.timestamp + epochLength);
        (uint256 epoch1,) = entrypoint.currentEpoch();
        assertEq(epoch1, 1);

        // Closed period is first half of epoch
        // Warp to second epoch + 40% into epoch (closed period is first half)
        vm.warp(block.timestamp + epochLength + (epochLength * 4 / 10));
        (, bool closed1) = entrypoint.currentEpoch();
        assertTrue(closed1);

        // Warp a bit more to reach open period (>50% into epoch)
        vm.warp(block.timestamp + (epochLength / 10)); // now at 50%+ into epoch
        (, bool closed2) = entrypoint.currentEpoch();
        assertFalse(closed2);
    }

    function test_IsFinalized() public {
        uint256 epochLength = entrypoint.getEpochLength();
        uint256 challengePeriod = entrypoint.getChallengePeriod();

        // minEpochsWait = CHALLENGE_PERIOD/EPOCH_LENGTH + 1
        uint256 minEpochsWait = challengePeriod / epochLength + 1;

        assertFalse(entrypoint.isFinalized(0), "Epoch 0 not finalized at epoch 0");

        // Warp to exactly minEpochsWait epochs (should NOT be finalized yet)
        vm.warp(block.timestamp + minEpochsWait * epochLength);
        assertFalse(entrypoint.isFinalized(0), "Epoch 0 not finalized at minEpochsWait");

        // Warp one more epoch (should now be finalized)
        vm.warp(block.timestamp + epochLength);
        assertTrue(entrypoint.isFinalized(0), "Epoch 0 finalized at minEpochsWait + 1");

        // Warp further and check various epochs
        vm.warp(block.timestamp + 8 * epochLength); // several more epochs
        (uint256 currentEpoch,) = entrypoint.currentEpoch();

        // Recent epoch should not be finalized
        if (currentEpoch > minEpochsWait) {
            assertFalse(entrypoint.isFinalized(currentEpoch - minEpochsWait), "Recent epoch not finalized");
        }
        // Old epoch should be finalized
        if (currentEpoch > minEpochsWait + 2) {
            assertTrue(entrypoint.isFinalized(currentEpoch - minEpochsWait - 2), "Old epoch finalized");
        }
    }

    function test_Post_BlobUseTracking() public {
        uint256 epochLength = entrypoint.getEpochLength();

        entrypoint.addFirstLook(sequencer1);

        // Test priority bonus in closed period
        (uint256 epoch, bool inClosedPeriod) = entrypoint.currentEpoch();
        assertTrue(inClosedPeriod);

        // Setup deposits for block 0 using real leaves
        entrypoint.setupDepositsForBlock(0, 3, address(0x1234));

        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(3, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);

        uint256 expectedRaw = 10 * 15 + 4; // 154 (3 deposits = 4 blob units)
        assertEq(entrypoint.getSequencerBlobUse(epoch, sequencer1), expectedRaw * 2, "Priority bonus 2x");

        // Test no bonus in open period (warp to > 50% into epoch)
        vm.warp(block.timestamp + (epochLength * 7 / 10));
        (, inClosedPeriod) = entrypoint.currentEpoch();
        assertFalse(inClosedPeriod);

        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(0, 10, 200);
        vm.prank(sequencer2);
        entrypoint.post(data2, indices2);

        assertEq(entrypoint.getSequencerBlobUse(epoch, sequencer2), 150, "No bonus in open period");
        assertEq(entrypoint.getTotalBlobUse(epoch), expectedRaw * 2 + 150, "Total tracks both");
    }

    function test_Post_EdgeCases() public {
        uint256 epochLength = entrypoint.getEpochLength();

        // Works with no priority sequencers (open period only)
        vm.warp(block.timestamp + (epochLength * 7 / 10)); // warp to open period
        // Setup 1 deposit for block 0 using real leaves
        entrypoint.setupDepositsForBlock(0, 1, address(0x1234));
        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(1, 1, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);
        assertGt(entrypoint.getSequencerBlobUse(0, sequencer1), 0);

        // Works at epoch 0 with priority sequencer
        entrypoint.addFirstLook(sequencer2);
        vm.warp(block.timestamp - (epochLength * 7 / 10)); // back to start
        // Setup 1 deposit for block 1 using real leaves
        entrypoint.setupDepositsForBlock(1, 1, address(0x1234));
        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(1, 1, 200);
        vm.prank(sequencer2);
        entrypoint.post(data2, indices2);
        assertGt(entrypoint.getSequencerBlobUse(0, sequencer2), 0);

        // Works when prior epoch had no activity
        vm.warp(block.timestamp + epochLength * 5 + (epochLength / 2)); // skip several epochs
        (uint256 epoch,) = entrypoint.currentEpoch();
        assertEq(entrypoint.getTotalBlobUse(epoch - 1), 0);
        // Setup 1 deposit for block 2 using real leaves
        entrypoint.setupDepositsForBlock(2, 1, address(0x1234));
        (Spine.BlockData memory data3, uint256[] memory indices3) = _createBlockData(1, 1, 300);
        vm.prank(sequencer2);
        entrypoint.post(data3, indices3);
        assertGt(entrypoint.getSequencerBlobUse(epoch, sequencer2), 0);
    }

    function test_Post_IsAllowed() public {
        uint256 epochLength = entrypoint.getEpochLength();

        entrypoint.addFirstLook(sequencer1);
        entrypoint.addFirstLook(sequencer2);

        // In closed period, only priority sequencer allowed
        // Warp to epoch 2, early in closed period
        vm.warp(block.timestamp + epochLength * 2);
        (uint256 epoch, bool inClosedPeriod) = entrypoint.currentEpoch();
        assertTrue(inClosedPeriod);

        address nonPrioritySeq = (epoch % 2 == 0) ? sequencer2 : sequencer1;
        // Setup 1 deposit for block 0 using real leaves
        entrypoint.setupDepositsForBlock(0, 1, address(0x1234));
        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(1, 1, 100);
        vm.prank(nonPrioritySeq);
        vm.expectRevert(NotAllowed.selector);
        entrypoint.post(data1, indices1);

        // In open period, any active sequencer allowed
        vm.warp(block.timestamp + (epochLength * 7 / 10));
        (, inClosedPeriod) = entrypoint.currentEpoch();
        assertFalse(inClosedPeriod);

        // Setup 1 deposit for block 0 (block 0 wasn't posted due to revert, so still at block 0)
        // Note: deposits were already set up above for block 0
        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(1, 1, 200);
        vm.prank(nonPrioritySeq);
        entrypoint.post(data2, indices2); // should not revert
    }

    function test_GetPercentInEpoch() public {
        uint256 epochLength = entrypoint.getEpochLength();

        entrypoint.addFirstLook(sequencer1);
        vm.warp(block.timestamp + (epochLength * 7 / 10)); // open period

        // Single sequencer gets 100%
        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(0, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);

        vm.warp(block.timestamp + epochLength); // next epoch
        assertEq(entrypoint.getPercentInEpoch(sequencer1, 0), 1e18, "Single sequencer = 100%");

        // Sequencer with no activity gets 0%
        assertEq(entrypoint.getPercentInEpoch(sequencer2, 0), 0, "No activity = 0%");

        // Empty epoch returns 0 (current epoch is 1, so we check epoch 1 has no activity)
        assertEq(entrypoint.getTotalBlobUse(1), 0);
        // Warp to epoch 2+ to check epoch 1
        vm.warp(block.timestamp + epochLength);
        assertEq(entrypoint.getPercentInEpoch(sequencer1, 1), 0, "Empty epoch = 0%");
    }

    function test_GetPercentInEpoch_MultipleSequencers() public {
        uint256 epochLength = entrypoint.getEpochLength();

        entrypoint.addFirstLook(sequencer1);
        vm.warp(block.timestamp + (epochLength * 7 / 10)); // open period

        // Each block must use the current block number (which increments after each post)
        (Spine.BlockData memory data1, uint256[] memory indices1) = _createBlockData(0, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data1, indices1);

        // Now block 0 is posted, so this creates data for block 1
        (Spine.BlockData memory data2, uint256[] memory indices2) = _createBlockData(0, 10, 200);
        vm.prank(sequencer2);
        entrypoint.post(data2, indices2);

        vm.warp(block.timestamp + epochLength); // next epoch
        assertEq(entrypoint.getPercentInEpoch(sequencer1, 0), 0.5e18);
        assertEq(entrypoint.getPercentInEpoch(sequencer2, 0), 0.5e18);
    }

    function test_GetPercentInEpoch_RevertsForCurrentEpoch() public {
        entrypoint.addFirstLook(sequencer1);
        (Spine.BlockData memory data, uint256[] memory indices) = _createBlockData(0, 10, 100);
        vm.prank(sequencer1);
        entrypoint.post(data, indices);

        (uint256 epoch,) = entrypoint.currentEpoch();
        vm.expectRevert(EpochNotFinished.selector);
        entrypoint.getPercentInEpoch(sequencer1, epoch);
    }
}
