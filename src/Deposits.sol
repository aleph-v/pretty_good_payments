// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Spine} from "./Spine.sol";
import {PredictableMerkleLib, Leaf} from "./library/PredictableMerkleLib.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol";

// Deposits are structured such that even if the L2 reorgs because of bad block submission the deposits remain valid
// each leaf is appended to either the highest ever seen position for deposits or to the current block number + 2.
// The sequencer is required to include the deposits in order and include exactly the deposits in perBlockDeposit
// or they will be slashed in fraud proof.

// TODO - There is a griefing attack in this system where a sequencer makes 1000s of fake blocks and reorgs them all
//        to delay deposits, but this costs a lot of stake. It remains to be seen if we want to fix it, but we can just
//        a "requested block" field and enforce that its not less than the current head + 2

contract Deposits is Spine {
    using PredictableMerkleLib for Leaf;

    // A preset constant blinding factor set less than the BLS modulus
    bytes32 constant BLINDING = bytes32(
        uint256(keccak256("0x")) % 21888242871839275222246405745257275088548364400416034343698204186575808495617
    );
    uint256 highestDeposit;
    //Records the required deposits in each block
    mapping(uint256 => bytes32[]) public perBlockDeposits;

    event Deposit(bytes32 indexed leafHash, uint256 block, uint256 number);

    // Works by doing the poseidon hashing of leaf and then pushing it into the deposits for the next possible block
    // If the chain is reorged due to fraud this deposits tree does not rollback, new blocks created at new indices must
    // also include the same deposits.
    function deposit(Leaf memory leaf) external {
        require(leaf.amount != 0, "Invalid amount");
        // First we transfer from the user to the yield system and trigger deposit
        IERC20(leaf.asset).transferFrom(msg.sender, address(yieldRouter), leaf.amount);
        yieldRouter.triggerDeposit(leaf.asset, leaf.amount);

        // The blinding factors have internal hash structure so to special case them for recursive zk we have a constant in deposits
        leaf.blinding = BLINDING;
        bytes32 leafHash = leaf.hash();

        // The plus two here is to give sequencers a window in the happy path so that deposit tx do not break their submission flow
        uint256 blockPlusTwo = getCurrentBlocknumber() + 2;
        uint256 highestDepositCache = highestDeposit;
        uint256 blockToDepositIn = highestDepositCache >= blockPlusTwo ? highestDepositCache : blockPlusTwo;
        if (perBlockDeposits[blockToDepositIn].length >= MAX_DEPOSITS) {
            blockToDepositIn++;
        }
        // We should never hit this, but we include it to prevent breakage in the fault system
        assert(perBlockDeposits[blockToDepositIn].length < MAX_DEPOSITS);

        perBlockDeposits[blockToDepositIn].push(leafHash);
        if (blockToDepositIn > highestDepositCache) {
            highestDeposit = blockToDepositIn;
        }
        emit Deposit(leafHash, blockToDepositIn, perBlockDeposits[blockToDepositIn].length - 1);
    }
}
