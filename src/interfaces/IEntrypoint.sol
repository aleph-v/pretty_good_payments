// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// We may have many special purpose versions of these based on the yield integrations.

interface IEntrypoint {
    function getPercentInEpoch(address sequencer, uint256 epoch) external view returns (uint256);
    function isFinalized(uint256 epoch) external view returns (bool);
    function isChallenged(address who) external view returns (bool);
}
