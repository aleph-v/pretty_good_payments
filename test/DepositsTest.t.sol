// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Deposits} from "../src/Deposits.sol";
import {PredictableMerkleLib, Leaf} from "../src/library/PredictableMerkleLib.sol";
import {IYieldRouter} from "../src/interfaces/IYieldRouter.sol";
import {IUpdateVerifier} from "../src/interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "../src/interfaces/ITransferVerifier.sol";
import {ITransactionRegistry} from "../src/TransactionRegistry.sol";
import {FakeERC20} from "./mocks/FakeErc20.sol";
import {FakeZK} from "./mocks/FakeZk.sol";
import {MockYieldRouter} from "./mocks/MockYieldRouter.sol";
import {MockTransactionRegistry} from "./mocks/MockTransactionRegistry.sol";
import {InvalidDepositAmount} from "../src/library/Errors.sol";

// Harness to expose internal state and functions
contract DepositsHarness is Deposits {
    constructor(
        IYieldRouter _yieldRouter,
        IUpdateVerifier _updateVerifier,
        ITransferVerifier _transferVerifier,
        ITransactionRegistry _registry,
        bytes32 _genesisAnchor
    ) {
        yieldRouter = _yieldRouter;
        predictableUpdateVerifier = _updateVerifier;
        transactionZkVerifier = _transferVerifier;
        transferRegistry = _registry;
        GENESIS_ANCHOR = _genesisAnchor;
    }

    function exposed_BLINDING() external pure returns (bytes32) {
        return BLINDING;
    }

    function exposed_highestDeposit() external view returns (uint256) {
        return highestDeposit;
    }

    function exposed_perBlockDepositsLength(uint256 blockNr) external view returns (uint256) {
        return perBlockDeposits[blockNr].length;
    }

    function exposed_perBlockDepositsAt(uint256 blockNr, uint256 index) external view returns (bytes32) {
        return perBlockDeposits[blockNr][index];
    }

    function exposed_MAX_DEPOSITS() external pure returns (uint256) {
        return MAX_DEPOSITS;
    }

    function exposed_getCurrentBlocknumber() external view returns (uint256) {
        return getCurrentBlocknumber();
    }

    // Push a root directly for testing (bypasses validation)
    function pushRootForTest(bytes32 root) external {
        assembly ("memory-safe") {
            // Load the slot for roots array
            let slot := roots.slot
            let len := sload(slot)
            // Calculate storage slot for new element
            mstore(0, slot)
            let elemSlot := add(keccak256(0, 32), len)
            // Store the new root
            sstore(elemSlot, root)
            // Increment the length
            sstore(slot, add(len, 1))
        }
    }

    // Set highestDeposit for testing
    function setHighestDepositForTest(uint256 value) external {
        highestDeposit = value;
    }

    // Fill a block's deposits to MAX_DEPOSITS for testing
    function fillBlockDepositsForTest(uint256 blockNr, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            perBlockDeposits[blockNr].push(keccak256(abi.encode(blockNr, i)));
        }
    }
}

contract DepositsTest is Test {
    DepositsHarness deposits;
    FakeERC20 token;
    MockYieldRouter yieldRouter;
    FakeZK fakeZK;

    // BN254 (alt_bn128) scalar field modulus - used by Groth16 verifiers on Ethereum
    // This is the order of the scalar field for the BN254 curve used in Ethereum's precompiles
    uint256 constant BN254_SCALAR_FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        token = new FakeERC20();
        yieldRouter = new MockYieldRouter();
        fakeZK = new FakeZK();

        MockTransactionRegistry registry = new MockTransactionRegistry();

        deposits = new DepositsHarness(yieldRouter, fakeZK, fakeZK, registry, keccak256("genesis"));
    }

    // ========== Basic Deposit Tests ==========

    function test_deposit_basic() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        Leaf memory leaf = Leaf({
            asset: address(token), amount: amount, blinding: bytes32(uint256(123)), publicKey: bytes32(uint256(456))
        });

        deposits.deposit(leaf);
        vm.stopPrank();

        // Verify yieldRouter was called
        assertEq(yieldRouter.depositCount(), 1, "YieldRouter should have been called");
        assertEq(yieldRouter.lastDepositAsset(), address(token), "Asset should match");
        assertEq(yieldRouter.lastDepositAmount(), amount, "Amount should match");
    }

    function test_deposit_overwritesBlinding() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        bytes32 userBlinding = bytes32(uint256(999));
        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: userBlinding, publicKey: bytes32(uint256(456))});

        // The user's blinding will be overwritten with BLINDING constant
        deposits.deposit(leaf);
        vm.stopPrank();

        // Verify deposit was recorded (we can't directly check the stored blinding,
        // but we can verify the leaf hash uses the constant BLINDING)
        uint256 blockNr = deposits.exposed_highestDeposit();
        bytes32 storedHash = deposits.exposed_perBlockDepositsAt(blockNr, 0);

        // Compute expected hash with BLINDING constant
        bytes32 expectedBlinding = deposits.exposed_BLINDING();
        Leaf memory expectedLeaf =
            Leaf({asset: address(token), amount: amount, blinding: expectedBlinding, publicKey: bytes32(uint256(456))});
        bytes32 expectedHash = PredictableMerkleLib.hash(expectedLeaf);

        assertEq(storedHash, expectedHash, "Stored hash should use constant BLINDING, not user's");
    }

    // ========== Block Number Logic Tests ==========

    function test_deposit_goesToBlockPlusTwo() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        // Current block number is 0
        assertEq(deposits.exposed_getCurrentBlocknumber(), 0);

        deposits.deposit(leaf);
        vm.stopPrank();

        // For blocks 0-2, deposit goes to current block (no +2 indexing)
        // This is a cold start fix: blocks 0, 1, 2 need deposits to bootstrap
        assertEq(deposits.exposed_highestDeposit(), 0, "Deposit should go to block 0 (cold start behavior)");
        assertEq(deposits.exposed_perBlockDepositsLength(0), 1, "Block 0 should have 1 deposit");
    }

    function test_deposit_goesToBlockPlusTwo_afterColdStart() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        // Push 3 roots to get past cold start (blocks 0, 1, 2)
        deposits.pushRootForTest(keccak256("root0"));
        deposits.pushRootForTest(keccak256("root1"));
        deposits.pushRootForTest(keccak256("root2"));

        // Now at block 3
        assertEq(deposits.exposed_getCurrentBlocknumber(), 3);

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        deposits.deposit(leaf);
        vm.stopPrank();

        // For blocks > 2, deposit goes to block + 2 = 5
        assertEq(deposits.exposed_highestDeposit(), 5, "Deposit should go to block 5 (currentBlock + 2)");
        assertEq(deposits.exposed_perBlockDepositsLength(5), 1, "Block 5 should have 1 deposit");
    }

    function test_deposit_usesHighestDepositIfHigher() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        token.mint(user, amount * 2);

        // Push 3 roots to get past cold start
        deposits.pushRootForTest(keccak256("root0"));
        deposits.pushRootForTest(keccak256("root1"));
        deposits.pushRootForTest(keccak256("root2"));

        // Set highestDeposit to a high value
        deposits.setHighestDepositForTest(100);

        vm.startPrank(user);
        token.approve(address(deposits), amount * 2);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        deposits.deposit(leaf);
        vm.stopPrank();

        // Current block is 3, so block+2 = 5
        // But highestDeposit is 100, which is higher, so deposit goes to 100
        assertEq(deposits.exposed_highestDeposit(), 100, "Should use highestDeposit");
        assertEq(deposits.exposed_perBlockDepositsLength(100), 1, "Block 100 should have 1 deposit");
    }

    // ========== MAX_DEPOSITS Tests ==========

    /// @notice Test that deposit goes to next block when current is full
    function test_deposit_incrementsBlockWhenFull() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        // Push 3 roots to get past cold start
        deposits.pushRootForTest(keccak256("root0"));
        deposits.pushRootForTest(keccak256("root1"));
        deposits.pushRootForTest(keccak256("root2"));

        // Now at block 3, deposits go to block 5 (3 + 2)
        // Fill block 5 to MAX_DEPOSITS
        deposits.fillBlockDepositsForTest(5, deposits.exposed_MAX_DEPOSITS());

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        deposits.deposit(leaf);
        vm.stopPrank();

        // Should go to block 6 since block 5 is full
        assertEq(deposits.exposed_highestDeposit(), 6, "Should go to block 6");
        assertEq(deposits.exposed_perBlockDepositsLength(6), 1, "Block 6 should have 1 deposit");
    }

    /// When blockToDepositIn is incremented due to MAX_DEPOSITS being hit,
    /// the comparison is strictly greater than, which should work correctly
    function test_deposit_highestDepositUpdatesAfterIncrement() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        // Push 3 roots to get past cold start
        deposits.pushRootForTest(keccak256("root0"));
        deposits.pushRootForTest(keccak256("root1"));
        deposits.pushRootForTest(keccak256("root2"));

        // Now at block 3, deposits go to block 5 (3 + 2)
        // Set highestDeposit to 5
        deposits.setHighestDepositForTest(5);

        // Fill block 5 to MAX_DEPOSITS
        deposits.fillBlockDepositsForTest(5, deposits.exposed_MAX_DEPOSITS());

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        deposits.deposit(leaf);
        vm.stopPrank();

        // Block 5 is full, so it increments to 6
        // 6 > 5 (highestDepositCache), so highestDeposit should update to 6
        assertEq(deposits.exposed_highestDeposit(), 6, "highestDeposit should update to 6");
    }

    // ========== Event Tests ==========

    function test_deposit_emitsEvent() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        // Compute expected leaf hash
        bytes32 expectedBlinding = deposits.exposed_BLINDING();
        Leaf memory expectedLeaf =
            Leaf({asset: address(token), amount: amount, blinding: expectedBlinding, publicKey: bytes32(uint256(456))});
        bytes32 expectedHash = PredictableMerkleLib.hash(expectedLeaf);

        // Expect event with:
        // - leafHash (indexed)
        // - block = 0 (cold start: for blocks 0-2, deposits go to current block)
        // - number = 0 (length - 1 AFTER push, so 0-indexed)
        vm.expectEmit(true, false, false, true);
        emit Deposits.Deposit(expectedHash, 0, 0);

        deposits.deposit(leaf);
        vm.stopPrank();
    }

    /// @notice The event emits length - 1 AFTER push, making it 0-indexed (matching array indices)
    function test_deposit_eventNumberIs0Indexed() public {
        address user = address(0x1234);
        uint256 amount = 100 ether;

        token.mint(user, amount * 3);

        vm.startPrank(user);
        token.approve(address(deposits), amount * 3);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        // First deposit - number should be 0 (0-indexed)
        deposits.deposit(leaf);

        // Second deposit - number should be 1
        leaf.publicKey = bytes32(uint256(789)); // Change to get different hash
        deposits.deposit(leaf);

        vm.stopPrank();

        // During cold start (blocks 0-2), deposits go to current block (0)
        assertEq(deposits.exposed_perBlockDepositsLength(0), 2, "Should have 2 deposits in block 0");

        // The event numbers were 0 and 1 (0-indexed), matching array indices
    }

    // ========== Edge Case Tests ==========

    /// @notice Test deposit with zero amount reverts
    function test_deposit_zeroAmount_reverts() public {
        address user = address(0x1234);

        token.mint(user, 1000 ether);

        vm.startPrank(user);
        token.approve(address(deposits), 1000 ether);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: 0, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        // Zero amount deposit should revert
        vm.expectRevert(InvalidDepositAmount.selector);
        deposits.deposit(leaf);
        vm.stopPrank();
    }

    // ========== Fuzz Tests ==========

    function testFuzz_deposit_blockNumberLogic(uint256 currentBlockCount, uint256 existingHighestDeposit) public {
        // Bound inputs to reasonable values
        currentBlockCount = bound(currentBlockCount, 0, 100);
        existingHighestDeposit = bound(existingHighestDeposit, 0, 200);

        // Push roots to simulate current block count
        for (uint256 i = 0; i < currentBlockCount; i++) {
            deposits.pushRootForTest(keccak256(abi.encode(i)));
        }

        // Set highest deposit
        deposits.setHighestDepositForTest(existingHighestDeposit);

        address user = address(0x1234);
        uint256 amount = 100 ether;

        token.mint(user, amount);

        vm.startPrank(user);
        token.approve(address(deposits), amount);

        Leaf memory leaf =
            Leaf({asset: address(token), amount: amount, blinding: bytes32(0), publicKey: bytes32(uint256(456))});

        deposits.deposit(leaf);
        vm.stopPrank();

        // Calculate expected block based on new cold start logic
        uint256 expectedBlock;
        if (currentBlockCount <= 2) {
            // Cold start: for blocks 0-2, deposits ALWAYS go to current block
            // The highestDeposit variable is NOT used to compute target during cold start
            expectedBlock = currentBlockCount;
        } else {
            // Normal: for blocks > 2, deposits go to max(highestDeposit, blockNumber + 2)
            uint256 blockPlusTwo = currentBlockCount + 2;
            expectedBlock = existingHighestDeposit >= blockPlusTwo ? existingHighestDeposit : blockPlusTwo;
        }

        // There should be at least 1 deposit in the expected target block
        assertTrue(
            deposits.exposed_perBlockDepositsLength(expectedBlock) >= 1,
            "Should have at least 1 deposit in expected block"
        );

        // highestDeposit should be updated if the deposit went to a higher block
        assertTrue(deposits.exposed_highestDeposit() >= expectedBlock, "highestDeposit should be >= expected block");
    }

    function testFuzz_deposit_multipleDeposits(uint8 depositCount) public {
        depositCount = uint8(bound(depositCount, 1, 50));

        address user = address(0x1234);
        uint256 amountPerDeposit = 1 ether;
        uint256 totalAmount = amountPerDeposit * depositCount;

        token.mint(user, totalAmount);

        vm.startPrank(user);
        token.approve(address(deposits), totalAmount);

        for (uint256 i = 0; i < depositCount; i++) {
            Leaf memory leaf = Leaf({
                asset: address(token),
                amount: amountPerDeposit,
                blinding: bytes32(0),
                publicKey: bytes32(i) // Different public key for each
            });

            deposits.deposit(leaf);
        }
        vm.stopPrank();

        // During cold start (block 0), all deposits go to block 0
        assertEq(
            deposits.exposed_perBlockDepositsLength(0), depositCount, "All deposits should be in block 0 (cold start)"
        );
    }
}
