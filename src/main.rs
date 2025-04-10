#![feature(proc_macro_hygiene)] // If using bitcoin_script macro

use bitcoin::PublicKey;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin_script::script;
use bitcoin_script_dsl::treepp::*;
use bitcoin_scriptexec::execute_script;
use std::error::Error;

// --- Configuration ---
#[derive(Debug, Clone)]
pub struct ColliderVmConfig {
    pub l: usize, // e.g., 4 => D size = 16
    pub b: usize, // e.g., 8 => check first byte of hash
    pub k: usize, // Fixed to 2 for MVP
                  // hash_function implied as SHA256 for MVP
}

// --- Data Types ---
// Using Vec<u8> for simplicity in MVP
pub type InputX = Vec<u8>;
pub type NonceR = Vec<u8>;
pub type FlowIdD = Vec<u8>; // Should have length L/8
pub type Signature = Vec<u8>; // Dummy signature for MVP

// --- Parties ---
// Simplified for MVP - only need signer's pubkey
pub struct SignerInfo {
    pub pubkey: PublicKey,
    // In a real scenario, the signer would have the private key
}

// --- MVP Toy Function ---
// f(x) = f1(x) AND f2(x)
// Example: f(x) is true if x (as u32 LE) is > 100 AND < 200
const F1_THRESHOLD: u32 = 100;
const F2_THRESHOLD: u32 = 200;
const SIMPLE_HASH_CONSTANT: u32 = 12345; // Constant for our simple hash

// --- Simple Custom Hash (MVP) ---

/// Rust implementation of the simple hash: H(x) = x + CONSTANT
/// x is treated as a u32 Little Endian.
fn collider_hash(x_bytes: &[u8]) -> u32 {
    if x_bytes.len() != 4 {
        eprintln!(
            "ERROR: collider_hash expects 4 bytes, got {}",
            x_bytes.len()
        );
        return 0; // Return a default value or handle error
    }
    // Correct way to convert slice to fixed array
    let array: Result<[u8; 4], _> = x_bytes.try_into();
    match array {
        Ok(arr) => {
            let x_val = u32::from_le_bytes(arr);
            x_val.wrapping_add(SIMPLE_HASH_CONSTANT)
        }
        Err(_) => {
            eprintln!(
                "ERROR: Failed to convert slice to [u8; 4] in collider_hash. Len: {}",
                x_bytes.len()
            );
            0 // Return default on error
        }
    }
}

/// Generates Bitcoin Script for the simple hash: H(x) = x + CONSTANT
/// Assumes x (4 bytes LE) is on top of the stack. Leaves H(x) (4 bytes LE) on stack.
fn script_collider_hash() -> ScriptBuf {
    script! {
        <SIMPLE_HASH_CONSTANT> // Push the constant
        OP_ADD                 // Add x + CONSTANT (Script handles numbers appropriately)
                               // Result H(x) is left on stack
    }
}

// --- Script Generation ---

/// Generates the scriptPubKey for a ColliderVM transaction (MVP simplified).
/// Checks: 1. Signer Sig, 2. Hash Puzzle (H(x) mod 2^B = d_val), 3. Subfunction Fi
fn generate_script_pubkey(
    config: &ColliderVmConfig,
    signer_pubkey: &PublicKey,
    d_val: u32, // Target value for the hash puzzle
    sub_function_script: &ScriptBuf,
) -> ScriptBuf {
    // Witness stack expected by this script: [signer_sig, r, x] (x at top initially)
    // MVP Simplification: 'r' is ignored for the hash puzzle.

    let modulus: u32 = 1 << config.b; // Calculate 2^B

    script! {
        // Stack: [signer_sig, r, x]

        // 1. Verify Hash Puzzle H(x) mod 2^B = d_val
        // x is at the top, r is below it. We need x for the hash.
        OP_DUP       // Stack: [signer_sig, r, x, x]
        // Apply the custom hash function H(x)
        { script_collider_hash().clone() } // Clone ScriptBuf
        // Stack: [signer_sig, r, x, H(x)]

        // Perform the modulo operation
        <modulus>    // Stack: [signer_sig, r, x, H(x), 2^B]
        OP_MOD       // Stack: [signer_sig, r, x, H(x) mod 2^B] - Check if OP_MOD is available/correctly implemented

        // Compare with the target value d_val
        <d_val>      // Stack: [signer_sig, r, x, H(x) mod 2^B, d_val]
        OP_EQUALVERIFY // Stack: [signer_sig, r, x] - Fails if H(x) mod 2^B != d_val

        // 2. Verify Subfunction Fi(x)
        // x is on top. Append the subfunction's script logic.
        { sub_function_script.clone() } // Clone ScriptBuf (already cloning, ensure it's correct)

        // Stack: [signer_sig, r]
        OP_DROP      // Stack: [signer_sig] - Drop r (since it wasn't used in the hash)

        // 3. Verify Signer's Signature
        <signer_pubkey.to_bytes()> // Stack: [signer_sig, signer_pubkey]
        OP_CHECKSIGVERIFY // Fails if signature is invalid for this tx context

        // Script succeeds if it reaches here without VERIFY failing
        OP_TRUE // Leave TRUE on stack for success
    }
}

// --- Simulation Logic ---

/// Simulates the operator finding a valid x for a target d_val and config B.
/// Uses the MVP puzzle H(x) mod 2^B = d_val. 'r' is not used.
fn find_b_pair_simplified(
    config: &ColliderVmConfig,
    target_d_val: u32,
    // Note: In a real search, we'd iterate through many 'x' values.
    // Here, we just test a candidate 'x'.
    candidate_x: &InputX,
) -> Option<NonceR> {
    let hash_result = collider_hash(candidate_x);
    let modulus = 1 << config.b;
    let hash_mod_result = hash_result % modulus; // Use standard modulo

    // Safely get u32 value for printing
    let x_val_for_print = match candidate_x.as_slice().try_into() {
        Ok(arr) => u32::from_le_bytes(arr),
        Err(_) => 0, // Default for printing if conversion fails
    };

    println!(
        "find_b_pair_simplified: Testing x = {} ({}), H(x) = {}, H(x) mod 2^{} ({}) = {}",
        x_val_for_print,
        hex::encode(candidate_x),
        hash_result,
        config.b,
        modulus,
        hash_mod_result
    );

    if hash_mod_result == target_d_val {
        println!("  -> Match found for target d_val = {}", target_d_val);
        // Return a dummy nonce as 'r' isn't used in the hash check
        Some(vec![0u8; 8])
    } else {
        println!("  -> No match for target d_val = {}", target_d_val);
        None
    }
}

// --- Main Simulation ---
fn run_mvp_simulation() -> Result<(), Box<dyn Error>> {
    println!("--- ColliderVM MVP Simulation (Simple Hash) ---");

    // 1. Config
    let config = ColliderVmConfig { l: 4, b: 8, k: 2 }; // B=8 bits => modulus 2^8 = 256
    println!("Config: L={}, B={}, k={}", config.l, config.b, config.k);
    let modulus: u32 = 1 << config.b;
    println!("Derived Modulus (2^B): {}", modulus);

    // 2. Parties
    // Generate dummy signer key for MVP
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (_privkey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
    let signer_info = SignerInfo {
        pubkey: bitcoin::PublicKey::new(pubkey),
    };
    println!("Signer PubKey: {}", signer_info.pubkey);

    // 3. Choose Target Flow 'd' value
    // For B=8, d_val should be < 256. Let's target d_val = 171 (0xAB)
    let target_d_val: u32 = 0xAB;
    println!(
        "Target Flow Value (d_val): {} (0x{:X})",
        target_d_val, target_d_val
    );

    // 4. Find a suitable input 'x' that satisfies the puzzle and functions
    // We need x such that:
    // a) F1(x) is true (x > 100)
    // b) F2(x) is true (x < 200)
    // c) H(x) mod 256 == 171 (where H(x) = x + 12345)
    let mut valid_x_bytes: Option<Vec<u8>> = None;
    let mut found_x_val: u32 = 0;

    println!(
        "Searching for valid x (100 < x < 200) such that (x + {}) mod {} == {}...",
        SIMPLE_HASH_CONSTANT, modulus, target_d_val
    );

    for x_val in (F1_THRESHOLD + 1)..F2_THRESHOLD {
        let x_bytes = x_val.to_le_bytes().to_vec();
        let hash_val = collider_hash(&x_bytes);
        if hash_val % modulus == target_d_val {
            println!("Found valid x = {} (0x{:X})", x_val, x_val);
            println!("  - H({}) = {}", x_val, hash_val);
            println!("  - H(x) mod {} = {}", modulus, hash_val % modulus);
            valid_x_bytes = Some(x_bytes);
            found_x_val = x_val;
            break;
        }
    }

    let operator_x = match valid_x_bytes {
        Some(bytes) => bytes,
        None => {
            println!(
                "ERROR: Could not find a valid 'x' satisfying puzzle and function constraints."
            );
            return Ok(());
        }
    };
    println!(
        "Chosen Operator x: {} ({})",
        found_x_val,
        hex::encode(&operator_x)
    );

    // 5. Generate Scripts for the chosen flow 'd_val'
    let f1_script = script_f1();
    let f2_script = script_f2();

    // Pass d_val directly to the script generation
    let script_pubkey_1 =
        generate_script_pubkey(&config, &signer_info.pubkey, target_d_val, &f1_script);
    let script_pubkey_2 =
        generate_script_pubkey(&config, &signer_info.pubkey, target_d_val, &f2_script);

    // Debug: Print generated scripts
    println!("\nGenerated ScriptPubKey 1 (f1):");
    // script_debug(&script_pubkey_1); // Requires bitcoin_scriptexec feature or similar
    println!("{}", script_pubkey_1);
    println!("\nGenerated ScriptPubKey 2 (f2):");
    // script_debug(&script_pubkey_2);
    println!("{}", script_pubkey_2);

    // 6. Operator "Finds" Nonce (using the found x)
    // Since we pre-found x, this should succeed.
    let operator_r = match find_b_pair_simplified(&config, target_d_val, &operator_x) {
        Some(r) => {
            println!("Operator confirmed valid x matches target d_val.");
            r
        }
        None => {
            // This shouldn't happen if our search logic in step 4 was correct
            println!(
                "ERROR: Operator failed to *confirm* valid x for target d_val (logic mismatch?)."
            );
            return Ok(());
        }
    };

    // 7. Operator Builds Witnesses (ScriptSigs) - Use dummy signature
    let dummy_sig = vec![0u8; 71]; // Realistic dummy DER signature size
    // Witness format: [sig, r, x]
    let script_sig_1 = script! {
        { dummy_sig.clone() }
        { operator_r.clone() }
        { operator_x.clone() }
    };
    let script_sig_2 = script_sig_1.clone();

    println!("\nWitness for Tx1/Tx2 (bottom to top): [sig, r, x]");
    println!("  x: {}", hex::encode(&operator_x));
    println!("  r: {} (dummy nonce)", hex::encode(&operator_r));
    println!("sig: {}... (dummy)", hex::encode(&dummy_sig[..4]));

    // 8. Simulate Execution
    println!("\n--- Simulating Execution ---");

    let exec_result_1 = execute_script(script_sig_1.clone());
    if exec_result_1.success {
        println!("Tx1 Succeeded (simulated).");
        println!("Tx1 Result: {:?}", exec_result_1);
    } else {
        println!("Tx1 FAILED execution!");
        return Err("Tx1 FAILED execution!".into());
    }

    println!("\nExecuting Tx2 (f2)...");
    let exec_result_2 = execute_script(script_sig_2.clone());
    if exec_result_2.success {
        println!("Tx2 Succeeded (simulated).");
        println!("Tx2 Result: {:?}", exec_result_2);
    } else {
        println!("Tx2 FAILED execution!");
        return Err("Tx2 FAILED execution!".into());
    }

    println!("\n--- Simulation Complete ---");

    Ok(())
}

// Translates f1(x): x > F1_THRESHOLD into Bitcoin Script
// Assumes x is on top of the stack (as a 4-byte LE integer)
fn script_f1() -> ScriptBuf {
    script! {
        <F1_THRESHOLD> // Push threshold
        // OP_LESSTHAN OP_NOT for >=. Need >. Use OP_SWAP OP_GREATERTHAN
        OP_SWAP
        OP_GREATERTHAN // Is x > F1_THRESHOLD ?
        OP_VERIFY      // Fail script if not true
    }
}

// Translates f2(x): x < F2_THRESHOLD into Bitcoin Script
// Assumes x is on top of the stack (as a 4-byte LE integer)
fn script_f2() -> ScriptBuf {
    script! {
        <F2_THRESHOLD> // Push threshold
        OP_LESSTHAN    // Is x < F2_THRESHOLD ?
        OP_VERIFY      // Fail script if not true
    }
}

fn main() {
    if let Err(e) = run_mvp_simulation() {
        eprintln!("Simulation Error: {}", e);
    }
}
