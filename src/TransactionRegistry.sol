// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface ITransactionRegistry {
    function allow(bytes32[5] memory fields) external;
    function query(address sender, bytes32[5] memory fields) external view returns (bool);
}

///@notice This contract allows ethereum addresses to give permission to the roll up to execute transactions with
///         ethereum keyed accounts. These accounts loose privacy over the sender (and time of transaction) but
///         conceal destination and amounts. The notes have a public key equal to an eth address and must approve
///         the output nullifiers and output notes before the transaction is approved or the transaction will be
///         challenged.

/// TODO - There is an edge case griefing here where a sequencer withholds an approval tx then tries to front run a
///        challenge transaction -- will not fix, recommend private relayer
/// TODO - Add a path to sign approvals instead of directly calling
contract TransactionRegistry {
    mapping(bytes32 => bool) public allowed;

    event Allowed(address indexed from, bytes32[5] data);

    /// @notice Allows an ethereum account to approve an l2 proof inclusion for an ethereum keyed account
    /// @param fields [nullifier, nullifier, nullifier, note hash, note hash]
    ///  TODO - We might want to clean this code a bit because its not amazing
    function allow(bytes32[5] memory fields) external {
        bytes32 hashed;
        assembly ("memory-safe") {
            mstore(add(fields, 160), caller())
            hashed := keccak256(fields, 192)
        }
        allowed[hashed] = true;

        // We want to format this well for the event so we do a quick conversion then emit

        emit Allowed(msg.sender, fields);
    }

    /// @notice Used by the transaction challenge system to query which ethereum owned transactions have been approved
    /// @param sender The ethereum address which is being queried
    /// @param fields the data in the proof [nullifier, nullifier, nullifier, noteOut, noteOut]
    function query(address sender, bytes32[5] memory fields) external view returns (bool) {
        bytes32 hashed;
        assembly ("memory-safe") {
            mstore(add(fields, 160), sender)
            hashed := keccak256(fields, 192)
        }
        return (allowed[hashed]);
    }
}
