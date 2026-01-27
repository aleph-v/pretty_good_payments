// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Spine} from "./Spine.sol";
import {PredictableMerkleLib, Leaf} from "./library/PredictableMerkleLib.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {InvalidDepositAmount, MaxDepositsExceeded} from "./library/Errors.sol";

/// @title Deposits
/// @notice Handles L1 deposit creation for the L2 privacy-preserving payment system
/// @dev Deposits survive L2 reorgs - sequencers must include deposits in order or be slashed.
///      Deposits target block max(highestDeposit, currentBlock+2) to give sequencers a submission window.

contract Deposits is Spine {
    using PredictableMerkleLib for Leaf;
    using SafeERC20 for IERC20;

    // A preset constant blinding factor set less than the BLS modulus
    bytes32 public constant BLINDING = bytes32(
        uint256(keccak256("0x")) % 21888242871839275222246405745257275088548364400416034343698204186575808495617
    );
    uint256 public highestDeposit;
    //Records the required deposits in each block
    mapping(uint256 => bytes32[]) public perBlockDeposits;

    event Deposit(bytes32 indexed leafHash, uint256 block, uint256 number);

    /// @notice Returns all deposit leaf hashes recorded for a given L2 block number
    /// @dev Used by challengers to validate that sequencers include the correct deposits in blobs
    /// @param blockNr The L2 block number to fetch deposits for
    /// @return Array of deposit leaf hashes in the order they were added
    function getDepositArray(uint256 blockNr) external view returns (bytes32[] memory) {
        return perBlockDeposits[blockNr];
    }

    /// @notice Creates a deposit by transferring tokens to yield router and recording the leaf hash
    /// @dev Leaf hash is computed via Poseidon. Deposit targets max(highestDeposit, currentBlock+2).
    /// @param leaf Deposit leaf with asset, amount, and publicKey. amount must be > 0.
    ///        leaf.blinding will be overwritten with BLINDING constant.
    function deposit(Leaf memory leaf) external {
        if (leaf.amount == 0) revert InvalidDepositAmount();
        // First we transfer from the user to the yield system and trigger deposit
        IERC20(leaf.asset).safeTransferFrom(msg.sender, address(yieldRouter), leaf.amount);
        yieldRouter.triggerDeposit(leaf.asset, leaf.amount);

        // The blinding factors have internal hash structure so to special case them for recursive zk we have a constant in deposits
        leaf.blinding = BLINDING;
        bytes32 leafHash = leaf.hash();

        // The plus two here is to give sequencers a window in the happy path so that deposit tx do not break their submission flow
        uint256 blockNumber = getCurrentBlocknumber();
        uint256 blockToDepositIn = blockNumber;
        // This fixes a cold start problem where if the genesis root is empty then no non fraud blocks can be issued for the first or
        // second block as we do not allow empty blocks and the first and second blocks cannot have transactions or deposits.
        uint256 highestDepositCache = highestDeposit;
        if (blockNumber > 2) {
            uint256 blockPlusTwo = blockNumber + 2;
            blockToDepositIn = highestDepositCache >= blockPlusTwo ? highestDepositCache : blockPlusTwo;
        }

        if (perBlockDeposits[blockToDepositIn].length >= MAX_DEPOSITS) {
            blockToDepositIn++;
        }
        // We should never hit this, but we include it to prevent breakage in the fault system
        if (perBlockDeposits[blockToDepositIn].length >= MAX_DEPOSITS) revert MaxDepositsExceeded();

        perBlockDeposits[blockToDepositIn].push(leafHash);
        if (blockToDepositIn > highestDepositCache) {
            highestDeposit = blockToDepositIn;
        }
        emit Deposit(leafHash, blockToDepositIn, perBlockDeposits[blockToDepositIn].length - 1);
    }
}
