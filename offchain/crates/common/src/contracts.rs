//! Contract bindings generated via alloy::sol! macro.
//!
//! These bindings are generated from the Solidity contracts in the parent project.

use alloy::sol;

// All types and contracts in one sol! block to resolve cross-references
sol! {
    /// Timestamp and block index within a day
    #[derive(Debug, Default, PartialEq, Eq)]
    struct TimestampAndIndex {
        uint128 day;
        uint128 index;
    }

    /// Block data structure - the core unit of L2 state
    #[derive(Debug, Default)]
    struct BlockData {
        bytes32 anchor;
        uint256 timestamp;
        uint256 numTransactions;
        uint256 numDeposits;
        uint256 blockNr;
        TimestampAndIndex blockIndex;
        address sequencer;
        bytes32[] blobhashes;
    }

    /// KZG-proven region of blob memory
    #[derive(Debug, Default)]
    struct Region {
        uint256 length;
        uint256 memoryAddress;
        bytes32[] data;
        bytes[] proofs;
        bytes commitment;
        bytes32 hash;
    }

    /// Groth16 proof structure
    #[derive(Debug, Default)]
    struct Proof {
        uint256[2] _pA;
        uint256[2][2] _pB;
        uint256[2] _pC;
    }

    /// Leaf (note) structure
    #[derive(Debug, Default)]
    struct Leaf {
        address asset;
        uint256 amount;
        bytes32 blinding;
        bytes32 publicKey;
    }

    // Entrypoint contract - main entry for block submission
    #[sol(rpc)]
    contract Entrypoint {
        event NewRoot(uint256 indexed blocknumber, bytes32 indexed anchor, bytes32 indexed l2BlockHash, BlockData data);
        event Rollback(uint256 from, uint256 to);
        event Deposit(bytes32 indexed leafHash, uint256 block, uint256 number);

        function post(BlockData memory data, uint256[] memory blobIndices) external;
        function getCurrentBlocknumber() external view returns (uint256);
        function isConfirmed(BlockData memory data) external view returns (bool);
        function isBlockIncluded(BlockData memory data) external view returns (bool);
        function isAnchorIncluded(bytes32 anchor, uint64 expectedIndex, bytes24 partialHash) external view returns (bool);

        // From Deposits
        function deposit(Leaf memory leaf) external;
        function getDepositArray(uint256 blockNr) external view returns (bytes32[] memory);
        function perBlockDeposits(uint256 blockNr, uint256 index) external view returns (bytes32);

        // From SequencerRegistry
        function fund() external payable;
        function isAllowed(address sequencer) external view returns (bool);
        function requiredStake() external view returns (uint256);

        // From Spine
        function GENESIS_ANCHOR() external view returns (bytes32);
        function START() external view returns (uint256);
        function lastTimestamp() external view returns (uint128 day, uint128 index);
    }

    // DepositChallenge contract
    #[sol(rpc)]
    contract DepositChallenge {
        function challengeDepositWrongLeaf(
            BlockData memory data,
            uint256 depositNr,
            bytes32 sequencerSubmittedLeaf,
            bytes calldata commitment,
            bytes calldata proof,
            BlockData memory priorBlock
        ) external;
    }

    // NullifierChallenge contract
    /// Data needed to prove a nullifier exists at a specific location in a block
    struct NullifierLoader {
        BlockData data;
        uint256 txNr;
        uint256 whichNullifier;
        bytes commitment;
        bytes proof;
    }

    #[sol(rpc)]
    contract NullifierChallenge {
        function challengeNullifier(
            bytes32 reusedNullifier,
            NullifierLoader calldata first,
            NullifierLoader calldata second,
            BlockData memory rollbackTargetBlock
        ) external;
    }

    // TransactionChallenge contract
    #[sol(rpc)]
    contract TransactionChallenge {
        function challengeTxZK(
            BlockData memory data,
            uint256 txNr,
            Region calldata region,
            Region calldata extensionRegion,
            bytes32 anchor,
            BlockData memory priorAnchorBlock,
            bytes calldata priorAnchorCommitment,
            bytes calldata priorAnchorProof,
            BlockData memory rollbackTargetBlock
        ) external;

        function encodeTxIntoBytes32(
            uint32 blockNr,
            uint32 updateNr,
            bool isDeposit,
            address ethAddress
        ) external pure returns (bytes32);

        function decodeTxInfo(bytes32 data) external pure returns (
            uint256 blockNr,
            uint256 txNr,
            bool isDeposit,
            address ethAddress
        );
    }

    // TreeUpdateChallenge contract
    #[sol(rpc)]
    contract TreeUpdateChallenge {
        function challengeTreeUpdate(
            BlockData memory data,
            uint256 updateNr,
            bool isTx,
            Region calldata region,
            Region calldata extensionRegion,
            bytes32 priorAnchor,
            bytes calldata priorAnchorCommitment,
            bytes calldata priorAnchorProof,
            bytes32 trueAnchor,
            Proof memory zk,
            BlockData memory rollbackTargetBlock
        ) external;
    }

    /// Sequencer status struct
    #[derive(Debug, Default)]
    struct SequencerStatus {
        bool isActive;
        bool isPriority;
        uint8 priorityIndex;
        uint64 blocknumberChallenged;
        uint64 timestampChallenged;
        uint64 stakeAmount;
        address challenger;
    }

    // SequencerRegistry contract
    #[sol(rpc)]
    contract SequencerRegistry {
        event SequencerSlashed(address indexed sequencer, address indexed challenger);

        function fund() external payable;
        function registerExit() external;
        function exit(address who) external;
        function isAllowed(address sequencer) external view returns (bool);
        function requiredStake() external view returns (uint256);
        function currentEpoch() external view returns (uint256 epoch, bool isClosed);
        function sequencers(address who) external view returns (SequencerStatus memory);
        function isChallenged(address who) external view returns (bool);
    }

    // Deposits contract
    #[sol(rpc)]
    contract Deposits {
        function deposit(Leaf memory leaf) external;
        function perBlockDeposits(uint256 blockNr, uint256 index) external view returns (bytes32);
        function getDepositArray(uint256 blockNr) external view returns (bytes32[] memory);
    }

    // Withdraw contract
    #[sol(rpc)]
    contract Withdraw {
        function withdraw(
            Leaf memory leaf,
            BlockData memory data,
            uint256 txNr,
            uint256 which,
            bytes calldata commitment,
            bytes calldata proof
        ) external;

        function withdrawn(uint256 blockNr, uint256 key) external view returns (bool);
    }

    // Verifier interfaces
    #[sol(rpc)]
    interface IUpdateVerifier {
        function verifyProof(
            uint256[2] calldata _pA,
            uint256[2][2] calldata _pB,
            uint256[2] calldata _pC,
            uint256[6] calldata _pubSignals
        ) external view returns (bool);
    }

    #[sol(rpc)]
    interface ITransferVerifier {
        function verifyProof(
            uint256[2] calldata _pA,
            uint256[2][2] calldata _pB,
            uint256[2] calldata _pC,
            uint256[7] calldata _pubSignals
        ) external view returns (bool);
    }

    // FakeERC20 for testing
    #[sol(rpc)]
    contract FakeERC20 {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};

    #[test]
    fn test_block_data_default() {
        let data = BlockData::default();
        assert_eq!(data.anchor, B256::ZERO);
        assert_eq!(data.numTransactions, U256::ZERO);
    }

    #[test]
    fn test_timestamp_and_index() {
        let ts = TimestampAndIndex { day: 100, index: 5 };
        assert_eq!(ts.day, 100);
        assert_eq!(ts.index, 5);
    }
}
