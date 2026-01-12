// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {LibBit} from "solady/utils/LibBit.sol";
import {BlobData} from "../../src/library/BlobData.sol";

// The system uses a large amount of blob data tricks in order to track data in commitments but perfectly replicating this
// through a large number of tests is both slow and requires calling out to script libs instead we have built a mock model
// of the blob data system which uses storage to create persistent commitments to data. This will let us initiate tests
// pretending to be using blobs while instead using storage.
// Our fake blob storage uses a fake blob hash which is an incrementing hashed counter, stores the incoming data in bit reversed order
// and stores exactly 4096 elements in each array, but disregards the kzg proof components. When we do integration testing we will use
// real kzg and also do extensive unit tests of the kzg lib.

contract FakeBlobs {
    uint256 public counter;
    mapping(bytes32 => bytes32[4096]) public storedBlobData;
    mapping(bytes32 => bool) public tracked;

    function bitReverse(uint256 i) internal pure returns (uint256) {
        uint256 reversed = LibBit.reverseBits(i);
        reversed = (reversed >> 244);
        return reversed;
    }

    function storeAt(bytes32 root, uint256 index, bytes32 value) public {
        storedBlobData[root][index] = value;
    }

    function storeNew(bytes32[4096] memory data) public returns (bytes32) {
        bytes32 hashed = keccak256(abi.encodePacked(counter));
        counter++;
        for (uint256 i = 0; i < 4096; i++) {
            storedBlobData[hashed][bitReverse(i)] = data[i];
        }
        tracked[hashed] = true;
        return (hashed);
    }

    function store(bytes32[] memory data) public returns (bytes32[] memory ret) {
        uint256 blobs = data.length / 4096 + 1;
        ret = new bytes32[](blobs);
        for (uint256 i = 0; i < blobs; i++) {
            bytes32[4096] memory fakeBlob;
            for (uint256 j = 0; j < 4096; j++) {
                if (i * 4096 + j < data.length) {
                    fakeBlob[j] = data[i * 4096 + j];
                }
            }
            ret[i] = storeNew(fakeBlob);
        }
    }

    function access(bytes32 hashed, uint256 index) public view returns (bytes32) {
        require(tracked[hashed], "Not Tracked");
        require(index < 4096, "Invalid Index");
        return (storedBlobData[hashed][bitReverse(index)]);
    }
}
