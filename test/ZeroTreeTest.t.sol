// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ZeroTree} from "../src/library/ZeroTree.sol";

contract ZeroTreeTest is Test {
    function test_ComputeZeroTreeRoot() public pure {
        bytes32 root = ZeroTree.computeZeroTreeRoot();
        console.log("Zero Tree Root:");
        console.logBytes32(root);
    }
}
