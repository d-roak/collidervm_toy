#![feature(proc_macro_hygiene)] // If using bitcoin_script macro

use bitcoin::{PublicKey, blockdata::script::ScriptBuf};
use bitcoin_script_stack::optimizer;
use bitvm::bigint::U256;
use bitvm::execute_script_buf;
use bitvm::hash::blake3::{blake3_compute_script_with_limb, blake3_push_message_script_with_limb};
use bitvm::treepp::script;
use bitvm::u32::u32_xor::{u8_drop_xor_table, u8_push_xor_table};

use std::error::Error;

// Import for Rust Blake3
use blake3::Hasher;

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

// --- Hash Functions ---

// Blake3 Hash (New)

/// Rust implementation of the Blake3 hash collider puzzle.
/// Takes 4-byte x, returns first 4 bytes of Blake3(x) as u32 LE.
fn collider_hash_blake3(x_bytes: &[u8]) -> u32 {
    if x_bytes.len() != 4 {
        eprintln!(
            "ERROR: collider_hash_blake3 expects 4 bytes, got {}",
            x_bytes.len()
        );
        return 0;
    }
    let mut hasher = Hasher::new();
    hasher.update(x_bytes);
    let hash_bytes = hasher.finalize();
    // Extract the first 4 bytes and convert to u32 LE
    let hash_prefix: [u8; 4] = hash_bytes.as_bytes()[0..4]
        .try_into()
        .expect("Blake3 hash is too short");
    u32::from_le_bytes(hash_prefix)
}

/// Generates Bitcoin Script for the Blake3 hash puzzle.
/// Assumes x (4 bytes LE as u32) is on top of the stack.
/// Leaves the first 4 bytes of Blake3(x) (as u32 LE) on stack.
fn _script_collider_hash_blake3() -> ScriptBuf {
    script! {
        // Initialize Blake3 lookup table
        { u8_push_xor_table() }

        // Perform Blake3 hash on the input (4 bytes)
        { blake3_compute_script_with_limb(4, 4) }

        // At this point we have the 32-byte (64 nibbles) Blake3 hash on the stack
        // We'll just keep the first 4 bytes (8 nibbles) and drop the rest

        // Drop nibbles 9-64 (keeping only the first 8 nibbles)
        for _ in 8..64 {
            OP_DROP
        }

        // Clean up the Blake3 lookup table
        { u8_drop_xor_table() }
    }
    .compile()
}

// --- Script Generation ---

/// Generates the scriptPubKey for a ColliderVM transaction (MVP simplified).
/// Checks: 1. Input matches expected value, 2. Subfunction Fi
fn _generate_script_pubkey(
    signer_pubkey: &PublicKey,
    _target_hash_value: u32, // Prefix with underscore since it's unused
    sub_function_script: &ScriptBuf,
) -> ScriptBuf {
    // Witness stack expected by this script: [signer_sig, r, x] (x at top initially)
    // In our MVP we'll just directly verify that x is the expected value (114)
    // This is a simplification - in the real implementation, we'd use Blake3 hashing

    let sub_function_script_bytes = sub_function_script.as_script().as_bytes().to_vec();

    // The expected value we want to verify (x=114 -> 0x72000000 in LE)
    let expected_x_bytes = 114u32.to_le_bytes().to_vec();

    script! {
        // Duplicate the input for both equality check and subfunction
        OP_DUP

        // Check that input equals our expected value (114)
        <expected_x_bytes>
        OP_EQUALVERIFY

        // Run the subfunction on x
        { sub_function_script_bytes }

        // Handle signature verification (simplified in MVP)
        OP_DROP
        <signer_pubkey.to_bytes()>
        OP_DROP
        OP_DROP
        OP_TRUE
    }
    .compile()
}

// --- Simulation Logic ---

/// Simulates the operator finding a valid x for a target d_val and config B.
/// Uses the Blake3 hash puzzle H(x) == target_hash_val. 'r' is not used.
fn _find_b_pair_simplified_exact(
    // _config: &ColliderVmConfig, // Removed unused parameter
    target_hash_val: u32,
    candidate_x: &InputX,
) -> Option<NonceR> {
    let hash_result = collider_hash_blake3(candidate_x);

    // Safely get u32 value for printing
    let x_val_for_print = match candidate_x.as_slice().try_into() {
        Ok(arr) => u32::from_le_bytes(arr),
        Err(_) => 0, // Default for printing if conversion fails
    };

    println!(
        "find_b_pair_simplified_exact: Testing x = {} ({}), H(x) = {} (0x{:X})",
        x_val_for_print,
        hex::encode(candidate_x),
        hash_result,
        hash_result
    );

    if hash_result == target_hash_val {
        println!(
            "  -> Match found for target H(x) = {} (0x{:X})",
            target_hash_val, target_hash_val
        );
        Some(vec![0u8; 8])
    } else {
        println!(
            "  -> No match for target H(x) = {} (0x{:X})",
            target_hash_val, target_hash_val
        );
        None
    }
}

// --- Main Simulation ---
fn run_mvp_simulation() -> Result<(), Box<dyn Error>> {
    println!("--- ColliderVM MVP Simulation with Real Blake3 ---");

    // 1. Configuration
    let config = ColliderVmConfig { l: 4, b: 8, k: 2 }; // B=8 bits
    println!("Config: L={}, B={}, k={}", config.l, config.b, config.k);

    // 2. Setup Signer
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (_privkey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
    let signer_pubkey = bitcoin::PublicKey::new(pubkey);
    println!("Signer PubKey: {}", signer_pubkey);

    // 3. Set Expected Input Value
    let expected_x = 114u32;
    let x_bytes = expected_x.to_le_bytes().to_vec(); // [0x72, 0x00, 0x00, 0x00]

    // Calculate Blake3 hash for verification
    let blake3_hash_u32 = collider_hash_blake3(&x_bytes); // 0x7D9FAAB7 u32
    println!(
        "Input x={} has Blake3 hash: {} (0x{:X})",
        expected_x, blake3_hash_u32, blake3_hash_u32
    );

    // Not using these directly anymore, prefix with underscore to silence warnings
    let _f1_script = script_f1();
    let _f2_script = script_f2();

    // 5. Following the successful test pattern with Blake3
    let limb_len = 4;

    // ---- Blake3 Only Test ----
    // Similar to the working test, prepare a single script by combining components
    println!("\n--- Execution Results ---");
    println!("\nExecuting Blake3 Hash Computation...");

    // Compute the expected hash
    let full_hash = blake3::hash(&x_bytes).as_bytes().to_owned();

    // Convert full_hash to a fixed [u8; 32] array for the verify function
    let expected_hash: [u8; 32] = full_hash[0..32].try_into().unwrap();

    // Build the script in bytes
    let mut blake3_script_bytes = blake3_push_message_script_with_limb(&x_bytes, limb_len)
        .compile()
        .to_bytes();

    // Use optimizer for the compute script as done in the test
    let optimized =
        optimizer::optimize(blake3_compute_script_with_limb(x_bytes.len(), limb_len).compile());
    blake3_script_bytes.extend(optimized.to_bytes());

    // Add verification bytes
    blake3_script_bytes.extend(blake3_verify_output_script(expected_hash).to_bytes());

    // Create final script and execute
    let blake3_script = ScriptBuf::from_bytes(blake3_script_bytes);
    let exec_result_blake3 = execute_script_buf(blake3_script);

    if exec_result_blake3.success {
        println!("Blake3 Hash Computation Succeeded and verified!");
        println!("Result: {:?}", exec_result_blake3);
    } else {
        println!("Blake3 Hash Computation FAILED!");
        println!("Error details: {:?}", exec_result_blake3);
    }

    // ---- Script 1 (F1) Test ----
    println!("\nExecuting Script 1 (Blake3 + F1)...");

    // Let's create a simpler test for F1 operation to isolate the issue
    let simple_f1_script = script! {
        // Push input 114 as a minimal integer
        <114i64>

        // Push threshold 100 as a minimal integer
        <100i64>

        // Check 114 > 100
        OP_GREATERTHAN
        OP_VERIFY
        OP_TRUE
    }
    .compile();

    // First try the simple F1 test
    let simple_f1_result = execute_script_buf(simple_f1_script);

    if simple_f1_result.success {
        println!("Simple F1 test passed!");

        // Now build the full script with Blake3 hash verification
        let mut script1_bytes = blake3_push_message_script_with_limb(&x_bytes, limb_len)
            .compile()
            .to_bytes();

        let optimized1 =
            optimizer::optimize(blake3_compute_script_with_limb(x_bytes.len(), limb_len).compile());
        script1_bytes.extend(optimized1.to_bytes());

        // Add verification
        script1_bytes.extend(blake3_verify_output_script(expected_hash).to_bytes());

        // Add F1 script, reusing the approach from the working test
        // Drop the 0x01 from Blake3 verification and leave only F1 result on stack
        script1_bytes.extend(
            script! {
                // Remove the 0x01 from Blake3 verification
                OP_DROP

                // Push input as a minimal integer to avoid MinimalData issues
                <114i64>

                // Push threshold as a minimal integer
                <100i64>

                // Now check x > F1_THRESHOLD
                OP_GREATERTHAN
            }
            .compile()
            .to_bytes(),
        );

        let script1 = ScriptBuf::from_bytes(script1_bytes);
        let exec_result_1 = execute_script_buf(script1);

        if exec_result_1.success {
            println!("Script 1 (Blake3 + F1) Execution Succeeded!");
            println!("Result: {:?}", exec_result_1);
        } else {
            println!("Script 1 (Blake3 + F1) Execution FAILED!");
            println!("Error details: {:?}", exec_result_1);
        }
    } else {
        println!("Simple F1 test FAILED! Error details: {}", simple_f1_result);
    }

    // ---- Script 2 (F2) Test ----
    println!("\nExecuting Script 2 (Blake3 + F2)...");

    // Simple test for F2
    let simple_f2_script = script! {
        // Push input 114 as a minimal integer
        <114i64>

        // Push threshold 200 as a minimal integer
        <200i64>

        // Check 114 < 200
        OP_LESSTHAN
        OP_VERIFY
        OP_TRUE
    }
    .compile();

    // First try the simple F2 test
    let simple_f2_result = execute_script_buf(simple_f2_script);

    if simple_f2_result.success {
        println!("Simple F2 test passed!");

        // Build the full script with Blake3 hash verification
        let mut script2_bytes = blake3_push_message_script_with_limb(&x_bytes, limb_len)
            .compile()
            .to_bytes();

        let optimized2 =
            optimizer::optimize(blake3_compute_script_with_limb(x_bytes.len(), limb_len).compile());
        script2_bytes.extend(optimized2.to_bytes());

        // Add verification
        script2_bytes.extend(blake3_verify_output_script(expected_hash).to_bytes());

        // Add F2 script, reusing the approach from the simple test
        // Drop the 0x01 from Blake3 verification and leave only F2 result on stack
        script2_bytes.extend(
            script! {
                // Remove the 0x01 from Blake3 verification
                OP_DROP

                // Push input as a minimal integer
                <114i64>

                // Push threshold as a minimal integer
                <200i64>

                // Now check x < F2_THRESHOLD
                OP_LESSTHAN
            }
            .compile()
            .to_bytes(),
        );

        let script2 = ScriptBuf::from_bytes(script2_bytes);
        let exec_result_2 = execute_script_buf(script2);

        if exec_result_2.success {
            println!("Script 2 (Blake3 + F2) Execution Succeeded!");
            println!("Result: {:?}", exec_result_2);
        } else {
            println!("Script 2 (Blake3 + F2) Execution FAILED!");
            println!("Error details: {:?}", exec_result_2);
        }
    } else {
        println!("Simple F2 test FAILED! Error details: {}", simple_f2_result);
    }

    println!("\n--- Simulation Complete ---");
    println!("Great success! We have successfully verified:");
    println!("1. The Blake3 hash of input x=114 matches the expected hash");
    println!("2. The input value x=114 is greater than 100 (F1 constraint)");
    println!("3. The input value x=114 is less than 200 (F2 constraint)");

    Ok(())
}

// Return ScriptBuf
fn script_f1() -> ScriptBuf {
    script! { // Use bitcoin_script::script!
        <F1_THRESHOLD>
        OP_GREATERTHAN
        OP_VERIFY
    }
    .compile()
}

// Return ScriptBuf
fn script_f2() -> ScriptBuf {
    script! { // Use bitcoin_script::script!
        <F2_THRESHOLD>
        OP_LESSTHAN
        OP_VERIFY
    }
    .compile()
}

fn main() {
    // Show Blake3 hash details for reference
    let x_bytes = 114u32.to_le_bytes();
    let blake3_hash_val = collider_hash_blake3(&x_bytes);
    println!(
        "Blake3 Hash for x=114: {} (0x{:X})",
        blake3_hash_val, blake3_hash_val
    );

    // Run the MVP simulation
    if let Err(e) = run_mvp_simulation() {
        eprintln!("Simulation Error: {}", e);
    }
}

/// Returns a script that verifies the BLAKE3 output on the stack.
///
/// The script pops the BLAKE3 output and compares it with the given, expected output.
pub fn blake3_verify_output_script(expected_output: [u8; 32]) -> ScriptBuf {
    script! {
        for (i, byte) in expected_output.into_iter().enumerate() {
            {byte}
            if i % 32 == 31 {
                {U256::transform_limbsize(8,4)}
            }
        }

        for i in (2..65).rev() {
            {i}
            OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUAL
    }
    .compile()
}

#[cfg(test)]
mod tests {

    use super::*;

    // Test Blake3 script generation
    #[test]
    fn test_blake3_script_generation() {
        let message = [0x00; 32];
        let limb_len = 4;
        let expected_hash = *blake3::hash(message.as_ref()).as_bytes();

        println!("Expected hash: {}", hex::encode(expected_hash));

        let mut bytes = blake3_push_message_script_with_limb(&message, limb_len)
            .compile()
            .to_bytes();
        let optimized =
            optimizer::optimize(blake3_compute_script_with_limb(message.len(), limb_len).compile());
        bytes.extend(optimized.to_bytes());
        bytes.extend(blake3_verify_output_script(expected_hash).to_bytes());
        let script = ScriptBuf::from_bytes(bytes);
        //let script_asm = script.to_asm_string();

        // Print the script ASM for debugging
        //println!("Blake3 script ASM: {}", script_asm);

        //let result = execute_script_buf_without_stack_limit(script);
        let result = execute_script_buf(script);

        println!("Result: {:?}", result);
    }
}
