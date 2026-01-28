// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @title Errors
/// @notice Unified error definitions for the Pretty Good Payments protocol
/// @dev Custom errors are more gas efficient than require strings

// ============================================================================
// Block and Chain Errors
// ============================================================================

/// @notice Block data does not match stored root hash
error BlockNotIncluded();

/// @notice Block has not passed the challenge period
error BlockNotConfirmed();

/// @notice Anchor is not in the current chain state
error AnchorNotIncluded();

/// @notice Anchor does not match genesis anchor
error InvalidGenesisAnchor();

/// @notice Anchor index does not match expected block number
error AnchorIndexMismatch();

/// @notice Prior block root hash does not match
error PriorRootMismatch();

/// @notice Rollback index is out of bounds
error RollbackIndexOutOfBounds();

/// @notice Zero blobhash indicates missing blob
error ZeroBlobHash();

/// @notice Block has no transactions or deposits
error EmptyBlock();

// ============================================================================
// Capacity and Bounds Errors
// ============================================================================

/// @notice Transaction index exceeds block transaction count
error TxIndexOutOfBounds();

/// @notice Deposit index exceeds block deposit count
error DepositIndexOutOfBounds();

/// @notice Update index exceeds bounds for transaction or deposit updates
error UpdateIndexOutOfBounds();

/// @notice Block exceeds maximum allowed deposits
error TooManyDeposits();

/// @notice Block exceeds maximum allowed transactions
error TooManyTransactions();

/// @notice Blob capacity insufficient for block data
error InsufficientBlobCapacity();

/// @notice Deposit amount cannot be zero
error InvalidDepositAmount();

/// @notice Maximum deposits per block exceeded (internal assertion)
error MaxDepositsExceeded();

/// @notice Which parameter must be less than 3 for leaves
error InvalidLeafWhich();

/// @notice Which parameter must be less than 2 for nullifiers
error InvalidNullifierWhich();

/// @notice Deposit number exceeds valid range
error InvalidDepositNumber();

// ============================================================================
// Region and Blob Errors
// ============================================================================

/// @notice Region has zero length
error EmptyRegion();

/// @notice Region blob hash does not match expected
error RegionBlobHashMismatch();

/// @notice Region memory address does not match expected
error RegionMemoryAddressMismatch();

/// @notice Combined region length does not match expected total
error RegionLengthMismatch();

/// @notice Extension region memory address must be zero
error ExtensionMemoryNotZero();

/// @notice Region must be at blob boundary for extension
error RegionNotAtBlobBoundary();

/// @notice Region data length does not match declared length
error RegionDataLengthMismatch();

// ============================================================================
// ZK Proof Errors
// ============================================================================

/// @notice ZK proof verification failed
error InvalidZKProof();

/// @notice KZG proof verification failed (defined in assembly for precompile)
error InvalidProof();

// ============================================================================
// Sequencer and Registry Errors
// ============================================================================

/// @notice Caller is not allowed to post blocks
error NotAllowed();

/// @notice Sequencer has already been challenged
error AlreadyChallenged();

/// @notice Sequencer is not active
error SequencerNotActive();

/// @notice Challenge window has not elapsed
error ChallengeWindowNotElapsed();

/// @notice Exit window has not elapsed
error ExitWindowNotElapsed();

/// @notice Sequencer has no pending exit
error NoPendingExit();

/// @notice ETH transfer failed
error PayoutFailed();

/// @notice Stake amount exceeds maximum
error StakeExceedsMaximum();

/// @notice Epoch has not finished yet
error EpochNotFinished();

/// @notice Sequencer would get slashed for this block so we don't allow it
error WrongNumberOfDeposits();

/// @notice Sequencer will revert if they submit at the wrong block number to prevent accidental fraud
error WrongBlockNumber();

// ============================================================================
// Yield Router Errors
// ============================================================================

/// @notice Caller is not the bridge contract
error NotBridge();

/// @notice Token has not been transferred to router
error TokenNotTransferred();

/// @notice ERC20 token not enabled for yield
error TokenNotEnabled();

/// @notice Sequencer already paid for this epoch and token
error AlreadyPaid();

/// @notice Sequencer is challenged and cannot withdraw
error SequencerChallenged();

///@notice Epoch is not ready to withdraw
error EpochNotFinal();

// ============================================================================
// Transaction Registry Errors
// ============================================================================

/// @notice Signature does not match expected signer
error InvalidSignature();

// ============================================================================
// Withdraw Errors
// ============================================================================

/// @notice Leaf has already been withdrawn
error AlreadyWithdrawn();

/// @notice Public key must be zero for withdrawal
error PublicKeyNotZero();

// ============================================================================
// Nullifier Errors
// ============================================================================

/// @notice Cannot challenge same nullifier location
error SameNullifierLocation();

/// @notice First nullifier must be from earlier or same block
error InvalidNullifierOrder();

// ============================================================================
// Fraud Proof Errors
// ============================================================================

/// @notice No fraud detected - challenge invalid
error NoFraud();

/// @notice Ethereum key address cannot be zero for eth-keyed transactions
error ZeroEthKey();

/// @notice Invalid anchor block information provided
error InvalidAnchorBlockInfo();

// ============================================================================
// Deposit Challenge Errors
// ============================================================================

/// @notice Cannot challenge padding on full deposit group (numDeposits % 3 == 0)
error NotPartialDepositGroup();

/// @notice Deposit padding index is beyond the partial group boundary
error DepositPaddingIndexOutOfBounds();

/// @notice Block exceeds maximum leaf capacity (65,536 leaves per block)
error TooManyLeaves();
