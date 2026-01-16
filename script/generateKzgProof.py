#!/usr/bin/env python3
"""
FFI script to generate KZG proofs for blob data at specified indices.

Usage:
  python generateKzgProof.py <index> [index2 index3 ...]
  python generateKzgProof.py --blob <blob_file> <index> [index2 ...]
  python generateKzgProof.py --json <json_file> <index> [index2 ...]

Blob file format: One hex-encoded 32-byte field element per line (4096 lines total)
JSON file format: { "blobData": ["0x...", "0x...", ...] } with 4096 hex strings

Outputs ABI-encoded data to a temp file for FFI consumption via vm.readFileBinary.
Format: (bytes commitment, uint256[] indices, bytes32[] claims, bytes32 hash, bytes[] proofs)
"""

import sys
import os
import hashlib
import json
import ckzg
from eth_abi import encode

# Change to script directory so relative paths work
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

from blst_ctypes import object_as_kzg_settings, bytes_from_fr

def bytes_from_hex(hexstring):
    return bytes.fromhex(hexstring.replace("0x", ""))

def load_blob_from_txt(filepath):
    """Load blob data from a text file with one hex value per line."""
    blob = bytearray(b"")
    with open(filepath, "r") as file:
        for line in file:
            line = line.strip()
            if line:
                blob.extend(bytes_from_hex(line))
    return bytes(blob)

def load_blob_from_json(filepath):
    """Load blob data from a JSON file with blobData array."""
    with open(filepath, "r") as file:
        data = json.load(file)

    blob_data = data.get("blobData", [])
    blob = bytearray(b"")

    for element in blob_data:
        # Each element should be a 32-byte hex string
        blob.extend(bytes_from_hex(element))

    # Pad to 4096 elements (4096 * 32 = 131072 bytes) if needed
    required_size = 4096 * 32
    if len(blob) < required_size:
        blob.extend(b'\x00' * (required_size - len(blob)))

    return bytes(blob)

def main():
    if len(sys.argv) < 2:
        print("Usage: python generateKzgProof.py [--blob <file> | --json <file>] <index> [index2 ...]", file=sys.stderr)
        sys.exit(1)

    # Parse arguments
    args = sys.argv[1:]
    blob_file = None
    json_file = None
    indices = []

    i = 0
    while i < len(args):
        if args[i] == "--blob" and i + 1 < len(args):
            blob_file = args[i + 1]
            i += 2
        elif args[i] == "--json" and i + 1 < len(args):
            json_file = args[i + 1]
            i += 2
        else:
            indices.append(int(args[i]))
            i += 1

    if not indices:
        print("ERROR: No indices provided", file=sys.stderr)
        sys.exit(1)

    # Load trusted setup
    ts = ckzg.load_trusted_setup("trusted_setup.txt", 0)

    # Load blob data from appropriate source
    if json_file:
        blob = load_blob_from_json(json_file)
    elif blob_file:
        blob = load_blob_from_txt(blob_file)
    else:
        blob = load_blob_from_txt("blob.txt")

    # Compute KZG commitment
    commitment = ckzg.blob_to_kzg_commitment(blob, ts)

    # Compute blob versioned hash
    sha256_hash = hashlib.sha256(commitment).digest()
    version_byte = b'\x01'
    blob_versioned_hash = version_byte + sha256_hash[1:]

    # Get roots of unity
    roots_of_unity = object_as_kzg_settings(ts).roots_of_unity

    # Generate proofs for each index
    claims = []
    proofs = []

    for index in indices:
        (proof, y) = ckzg.compute_kzg_proof(blob, bytes_from_fr(roots_of_unity[index]), ts)

        # Verify the proof
        valid = ckzg.verify_kzg_proof(commitment, bytes_from_fr(roots_of_unity[index]), y, proof, ts)
        if not valid:
            print(f"ERROR: Invalid proof at index {index}", file=sys.stderr)
            sys.exit(1)

        claims.append(y)
        proofs.append(proof)

    # Always use array format for consistency with Solidity KzgProofData struct
    # Format: (bytes commitment, uint256[] indices, bytes32[] claims, bytes32 hash, bytes[] proofs)
    encoded = encode(
        ['(bytes,uint256[],bytes32[],bytes32,bytes[])'],
        [(commitment, indices, claims, blob_versioned_hash, proofs)]
    )

    # Write to temp file and output the path (for FFI to read with vm.readFileBinary)
    import tempfile
    import uuid
    # Use a deterministic path based on indices and blob source for caching
    indices_str = "_".join(str(i) for i in indices)
    # Include hash of blob source in path to avoid cache collisions
    blob_hash = hashlib.sha256(blob).hexdigest()[:8]
    # Add UUID to prevent race conditions when tests run in parallel
    unique_id = uuid.uuid4().hex[:8]
    temp_path = f"/tmp/kzg_proof_{blob_hash}_{indices_str}_{unique_id}.bin"
    with open(temp_path, "wb") as f:
        f.write(encoded)

    # Output just the file path (UTF-8 compatible)
    print(temp_path, end="")

if __name__ == "__main__":
    main()
