// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/library/BlobData.sol";
import {console} from "forge-std/console.sol";

contract BlobDataTest is BlobData {
    function validateSingleTest(
        bytes32 rootHash,
        bytes calldata commitment,
        uint256 index,
        bytes32 data,
        bytes calldata proof
    ) external {
        validateSingle(rootHash, commitment, index, data, proof);
    }
}

contract CounterTest is Test {
    BlobDataTest blob;

    struct TestData {
        bytes blob;
        bytes commitment;
        uint256 index;
        bytes32 claim;
        bytes32 hash;
        bytes proof;
    }

    function setUp() public {
        blob = new BlobDataTest();
    }

    function test_SingleProof() public {
        bytes memory hexString = vm.readFileBinary("./script/testVector.bin");
        TestData memory data = abi.decode(hexString, (TestData));
        bytes32[] memory blobhashes = new bytes32[](1);
        blobhashes[0] = data.hash;
        vm.blobhashes(blobhashes);
        console.logBytes32(blobhash(0));

        blob.validateSingleTest(data.hash, data.commitment, data.index, data.claim, data.proof);
    }

    function test_SingleProofReverts() public {
        bytes memory hexString = vm.readFileBinary("./script/testVector.bin");
        TestData memory data = abi.decode(hexString, (TestData));
        bytes32[] memory blobhashes = new bytes32[](1);
        blobhashes[0] = data.hash;
        vm.blobhashes(blobhashes);
        console.logBytes32(blobhash(0));
        vm.expectRevert();
        blob.validateSingleTest(
            data.hash & (bytes32)(uint256(2 ** 240 - 1)), data.commitment, data.index, data.claim, data.proof
        );
        vm.expectRevert();
        blob.validateSingleTest(data.hash, data.commitment, data.index + 1, data.claim, data.proof);
        vm.expectRevert();
        blob.validateSingleTest(
            data.hash, data.commitment, data.index, (bytes32)((uint256)(data.claim) + 1), data.proof
        );
    }
}
