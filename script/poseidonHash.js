#!/usr/bin/env node
/**
 * FFI script to compute Poseidon hash using circomlibjs
 * Usage: node poseidonHash.js <input0> <input1> [<input2> <input3>]
 * Supports 2 inputs (T3) or 4 inputs (T5)
 * Inputs are hex strings (with or without 0x prefix)
 * Output is hex string (with 0x prefix)
 */

const { buildPoseidon } = require("circomlibjs");

async function main() {
    const args = process.argv.slice(2);

    if (args.length !== 2 && args.length !== 4) {
        console.error("Usage: node poseidonHash.js <input0> <input1> [<input2> <input3>]");
        process.exit(1);
    }

    // Parse inputs as BigInts
    const inputs = args.map(arg => {
        const hex = arg.startsWith("0x") ? arg : "0x" + arg;
        return BigInt(hex);
    });

    // Build Poseidon hasher
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Compute hash (circomlibjs auto-selects t based on input count)
    const hash = poseidon(inputs);

    // Convert to hex string with 0x prefix, padded to 64 chars
    const hashBigInt = F.toObject(hash);
    const hashHex = "0x" + hashBigInt.toString(16).padStart(64, "0");

    // Output the hash (this is what FFI will read)
    process.stdout.write(hashHex);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
