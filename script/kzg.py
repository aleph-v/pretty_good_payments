import ckzg
import hashlib

from blst_ctypes import object_as_kzg_settings, bytes_from_fr
from eth_abi import encode

def bytes_from_hex(hexstring):
    return bytes.fromhex(hexstring.replace("0x", ""))

if __name__ == "__main__":
    ts = ckzg.load_trusted_setup("trusted_setup.txt", 0)

    blob = bytearray(b"")
    with open("blob.txt", "r") as file:
        for line in file:
            blob.extend(bytes_from_hex(line.strip()))
    blob = bytes(blob)
    # Compute KZG commitment
    commitment = ckzg.blob_to_kzg_commitment(blob, ts)

    # Print the commitment in hexadecimal format
    print("KZG Commitment:", commitment.hex())

    roots_of_unity = object_as_kzg_settings(ts).roots_of_unity
    print("Root:", bytes_from_fr(roots_of_unity[1]).hex())
    index = 1

    (proof, y) = ckzg.compute_kzg_proof(blob, bytes_from_fr(roots_of_unity[index]), ts)
    print(y.hex())
    print(proof.hex())

    valid = ckzg.verify_kzg_proof(commitment, bytes_from_fr(roots_of_unity[index]), y, proof, ts)
    assert valid, "Invalid Proof"

    # Compute the SHA-256 hash of the KZG commitment
    sha256_hash = hashlib.sha256(commitment).digest()
    # Prepend the version byte (0x01) to the last 31 bytes of the SHA-256 hash
    version_byte = b'\x01'
    blob_versioned_hash = version_byte + sha256_hash[1:]
    print(f"Blob versioned hash: 0x{blob_versioned_hash.hex()}")

    ## Encode the (blob, commitment, index, claim, proof)
    encoded = encode(['(bytes,bytes,uint256,bytes32,bytes32,bytes)'], [(blob, commitment, index, y, blob_versioned_hash, proof)])
    with open("./testVector.bin", "wb") as file:
        file.write(encoded)