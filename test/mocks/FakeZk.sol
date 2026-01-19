// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {IUpdateVerifier} from "../../src/interfaces/IUpdateVerifier.sol";
import {ITransferVerifier} from "../../src/interfaces/ITransferVerifier.sol";
// To avoid having to call out out and generate real zk proofs we setup this contract to allow calls to pass or fail

contract FakeZK is IUpdateVerifier, ITransferVerifier {
    mapping(bytes32 => bool) approvedProofs;

    function approveUpdate(uint256[6] memory _pubSignals) external {
        approvedProofs[keccak256(abi.encodePacked(_pubSignals))] = true;
    }

    function approveTransfer(uint256[7] memory _pubSignals) external {
        approvedProofs[keccak256(abi.encodePacked(_pubSignals))] = true;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[7] calldata _pubSignals
    ) external view returns (bool) {
        return approvedProofs[keccak256(abi.encodePacked(_pubSignals))];
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata _pubSignals
    ) external view returns (bool) {
        return approvedProofs[keccak256(abi.encodePacked(_pubSignals))];
    }
}
