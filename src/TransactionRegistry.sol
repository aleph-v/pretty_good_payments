// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {InvalidSignature} from "./library/Errors.sol";

interface ITransactionRegistry {
    function allow(bytes32[5] memory fields) external;
    function query(address sender, bytes32[5] memory fields) external view returns (bool);
}

/// @title TransactionRegistry
/// @notice Allows ethereum addresses to authorize L2 transactions for ethereum-keyed accounts
/// @dev Ethereum-keyed accounts sacrifice sender privacy but conceal destination and amounts.
///      The note's publicKey equals an eth address and must approve nullifiers/outputs before
///      the transaction is included, or it will be challenged via TransactionChallenge.

contract TransactionRegistry is EIP712 {
    mapping(bytes32 => bool) public allowed;

    event Allowed(address indexed from, bytes32[5] data);

    // Note we mostly just use this struct for the 712 support
    bytes32 constant TYPE_HASH = keccak256("NullifiersAndNotes(bytes32[2] nullifiers,bytes32[3] notes,address signer)");

    struct NullifiersAndNotes {
        bytes32[2] nullifiers;
        bytes32[3] notes;
        address signer;
    }

    constructor() EIP712("PaymentApproval", "1") {}

    /// @notice Allows an ethereum account to approve an l2 proof inclusion for an ethereum keyed account
    /// @param fields [nullifier, nullifier, note hash, note hash, note hash]
    function allow(bytes32[5] memory fields) external {
        bytes32 hashed = customHash(fields, msg.sender);
        allowed[hashed] = true;
        emit Allowed(msg.sender, fields);
    }

    /// @notice Used by the transaction challenge system to query which ethereum owned transactions have been approved
    /// @param sender The ethereum address which is being queried
    /// @param fields the data in the proof [nullifier, nullifier, noteOut, noteOut, noteOut]
    function query(address sender, bytes32[5] memory fields) external view returns (bool) {
        return (allowed[customHash(fields, sender)]);
    }

    /// @notice Allows signature-based approval of L2 transactions without on-chain transaction from signer
    /// @dev Uses EIP-712 typed data signing. Anyone can submit the approval with a valid signature.
    /// @param fields Struct containing nullifiers[2], notes[3], and signer address
    /// @param signature ECDSA signature over the EIP-712 typed hash. Must be from fields.signer.
    function approveByQuery(NullifiersAndNotes memory fields, bytes calldata signature) external {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encodePacked(
                    TYPE_HASH,
                    keccak256(abi.encodePacked(fields.nullifiers)),
                    keccak256(abi.encodePacked(fields.notes)),
                    fields.signer
                )
            )
        );
        address signer = ECDSA.recoverCalldata(digest, signature);
        if (signer != fields.signer) revert InvalidSignature();

        bytes32[5] memory converted;
        converted[0] = fields.nullifiers[0];
        converted[1] = fields.nullifiers[1];
        converted[2] = fields.notes[0];
        converted[3] = fields.notes[1];
        converted[4] = fields.notes[2];
        allowed[customHash(converted, signer)] = true;

        emit Allowed(signer, converted);
    }

    /// @notice Does the assembly hash using the sender and the fields, hard writes the sender into memory after the fields
    ///         WARNING this may overwrite memory so this should be used last in a function
    /// @param fields [nullifier, nullifier, noteOut, noteOut, noteOut]
    /// @param who The sender
    /// @return hashed The hash
    function customHash(bytes32[5] memory fields, address who) internal pure returns (bytes32 hashed) {
        assembly ("memory-safe") {
            mstore(add(fields, 160), who)
            hashed := keccak256(fields, 192)
        }
    }
}
