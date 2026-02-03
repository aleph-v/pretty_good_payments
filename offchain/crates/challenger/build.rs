//! Build script for the challenger crate.
//!
//! This script uses rust-witness to compile the predictableUpdate circuit WASM
//! into native Rust code for fast witness generation.

use std::path::Path;

fn main() {
    // Path to the directory containing the circuit WASM file
    // rust-witness expects a directory path, not a file path
    let wasm_dir = Path::new("../../../circuits/outputs/predictableUpdate/predictableUpdate_js");
    let wasm_file = wasm_dir.join("predictableUpdate.wasm");

    // Check if the WASM file exists
    if wasm_file.exists() {
        // rust-witness generates witness calculation code from WASM files in the directory
        // The generated code is available via the rust_witness::witness! macro
        rust_witness::transpile::transpile_wasm(wasm_dir.to_str().unwrap().to_string());

        println!("cargo:rerun-if-changed={}", wasm_file.display());
    } else {
        // Print a warning but don't fail the build
        // This allows the crate to be built without the circuit files for development
        println!("cargo:warning=Circuit WASM not found at {wasm_file:?}. Build circuits first with `make circuits`.");
    }

    // Rerun build script if these change
    println!("cargo:rerun-if-changed=build.rs");
}
