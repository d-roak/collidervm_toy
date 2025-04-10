#![feature(proc_macro_hygiene)] // If using bitcoin_script macro

use bitcoin::{
    PublicKey, Transaction,
    blockdata::opcodes::all::*,
    blockdata::script::{Builder, Instruction, Script, ScriptBuf},
    locktime::absolute::LockTime,
    transaction::Version,
};
use bitcoin_script_stack::optimizer;
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use bitvm::bigint::U256;
use bitvm::hash::blake3::{blake3_compute_script_with_limb, blake3_push_message_script_with_limb};
use bitvm::treepp::script;
use bitvm::u32::u32_xor::{u8_drop_xor_table, u8_push_xor_table};
use bitvm::{execute_script_buf, execute_script_buf_without_stack_limit};

use bitvm::{ExecuteInfo, FmtStack};
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
fn script_collider_hash_blake3() -> ScriptBuf {
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
fn generate_script_pubkey(
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
fn find_b_pair_simplified_exact(
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

    // 4. Create sub-function scripts (remain the same)
    let f1_script = script_f1();
    let f2_script = script_f2();

    // 5. Get the script that computes Blake3 and leaves 8 hash nibbles
    let blake3_compute_script = script_collider_hash_blake3(); // Uses blake3_compute_script_with_limb(4, 4)
    let blake3_compute_script_bytes = blake3_compute_script.as_script().as_bytes().to_vec();

    // 6. Create script to prepare input x (embeds x as 8 nibbles)
    // Assuming limb_len=4 is used for the compute script
    let prepare_input_script = blake3_push_message_script_with_limb(&x_bytes, 4);
    let prepare_input_script_bytes = prepare_input_script.compile().to_bytes();

    // 7. Calculate expected hash nibbles for comparison
    let expected_hash_bytes = blake3_hash_u32.to_le_bytes(); // [0xB7, 0xAA, 0x9F, 0x7D]
    // Blake3 script leaves hash nibbles as [h7, h6, h5, h4, h3, h2, h1, h0] (top = h0)
    // For 0x7D9FAAB7 (LE bytes B7 AA 9F 7D), the nibbles are 7, D, 9, F, A, A, B, 7
    let expected_nibbles_stack_order: Vec<u8> = vec![7, 13, 9, 15, 10, 10, 11, 7]; // h7=7, h6=D, ..., h0=7

    // 8. Create the script fragment to verify the 8 hash nibbles
    let verify_nibbles_script = {
        let mut builder = Builder::new();
        // Push expected nibbles in reverse order to match stack
        for (i, &nibble) in expected_nibbles_stack_order.iter().rev().enumerate() {
            builder = builder.push_int(nibble as i64); // Push expected nibble
            builder = builder.push_opcode(OP_EQUALVERIFY); // Compare with actual nibble from stack
            // Note: Using EQUALVERIFY for all simplifies logic slightly compared to EQUAL on last
        }
        // If all EQUALVERIFY passed, the script continues. No final TRUE/FALSE needed here.
        builder.into_script()
    };
    let verify_nibbles_script_bytes = verify_nibbles_script.as_bytes().to_vec();

    // --- Rebuild the main execution scripts ---

    // Blake3 hash computation only script
    let blake3_only_script = script! {
        // Input x (4 bytes) is provided by witness.

        // Prepare input x by pushing its 8 nibbles
        { prepare_input_script_bytes.clone() }

        // Calculate Blake3 hash (consumes 8 input nibbles, pushes 8 hash nibbles)
        { blake3_compute_script_bytes.clone() }

        // Verify the resulting 8 hash nibbles against the expected ones
        { verify_nibbles_script_bytes.clone() }

        // If verification passed, push TRUE
        OP_TRUE
    }
    .compile();

    // Script 1 (Blake3 + F1)
    let f1_script_bytes = f1_script.as_script().as_bytes().to_vec();
    let script_1 = script! {
        // Input x (4 bytes) from witness

        OP_DUP // Duplicate input x [x, x]

        // Prepare input (push corresponding nibbles)
        // This script doesn't use stack input, it embeds the values based on x_bytes
        { prepare_input_script_bytes.clone() }

        // Calculate Blake3 hash (consumes the prepared nibbles, pushes 8 hash nibbles)
        { blake3_compute_script_bytes.clone() } // Stack: [x, x, h7..h0]

        // Verify the resulting 8 hash nibbles against the expected ones
        { verify_nibbles_script_bytes.clone() } // Consumes h7..h0, leaves [x, x] if verify passes

        // Execute F1(x) on one copy of the original input
        // Note: F1 uses OP_VERIFY, so it consumes the top x and leaves the other x if successful
        { f1_script_bytes } // Stack: [x] if successful

        // Drop the remaining copy of x and return TRUE
        OP_DROP
        OP_TRUE
    }
    .compile();

    // Script 2 (Blake3 + F2)
    let f2_script_bytes = f2_script.as_script().as_bytes().to_vec();
    let script_2 = script! {
        OP_DUP // Duplicate input x [x, x]

        // Prepare input
        { prepare_input_script_bytes.clone() }

        // Calculate Blake3 hash
        { blake3_compute_script_bytes.clone() } // Stack: [x, x, h7..h0]

        // Verify the hash nibbles
        { verify_nibbles_script_bytes.clone() } // Stack: [x, x] if verify passes

        // Execute F2(x) on one copy of the original input
        { f2_script_bytes } // Stack: [x] if successful

        // Drop the remaining copy of x and return TRUE
        OP_DROP
        OP_TRUE
    }
    .compile();

    // Print the scripts (optional, can be large)
    // println!("\n--- Scripts ---");
    // println!("Prepare Input Script: {}", prepare_input_script.compile().to_asm_string());
    // println!("Blake3 Compute Script: {}", blake3_compute_script.to_asm_string());
    // println!("Verify Nibbles Script: {}", verify_nibbles_script.to_asm_string());
    // println!("Blake3 Only Script: {}", blake3_only_script.to_asm_string());
    // println!("Script 1 (Blake3 + F1): {}", script_1.to_asm_string());
    // println!("Script 2 (Blake3 + F2): {}", script_2.to_asm_string());

    // Create witness with just the input x
    let witness_script = script! {
        <x_bytes> // Push the 4-byte value e.g., [0x72, 0x00, 0x00, 0x00]
    }
    .compile();

    // Convert to witness format
    let witness = convert_scriptbuf_to_witness(witness_script)?; // Should be vec![vec![0x72, 0, 0, 0]]

    // Execute the scripts
    let exec_options = Options {
        require_minimal: false,
        ..Default::default()
    };

    println!("\n--- Execution Results ---");

    // Try the Blake3 hash computation only first
    println!("\nExecuting Blake3 Hash Computation...");
    let exec_result_blake3 = execute_script_with_witness_custom_opts(
        blake3_only_script,
        witness.clone(),
        exec_options.clone(),
    );

    if exec_result_blake3.success {
        println!("Blake3 Hash Computation Succeeded and verified!");
        println!("Result: {}", exec_result_blake3);
    } else {
        println!("Blake3 Hash Computation FAILED!");
        println!("Error details: {}", exec_result_blake3);
    }

    // Try script 1 (F1)
    println!("\nExecuting Script 1 (Blake3 + F1)...");
    let exec_result_1 =
        execute_script_with_witness_custom_opts(script_1, witness.clone(), exec_options.clone());

    if exec_result_1.success {
        println!("Script 1 Execution Succeeded!");
        println!("Result: {}", exec_result_1);
    } else {
        println!("Script 1 Execution FAILED!");
        println!("Error details: {}", exec_result_1);
    }

    // Try script 2 (F2)
    println!("\nExecuting Script 2 (Blake3 + F2)...");
    let exec_result_2 = execute_script_with_witness_custom_opts(script_2, witness, exec_options);

    if exec_result_2.success {
        println!("Script 2 Execution Succeeded!");
        println!("Result: {}", exec_result_2);
    } else {
        println!("Script 2 Execution FAILED!");
        println!("Error details: {}", exec_result_2);
    }

    println!("\n--- Simulation Complete ---");
    println!("Note: Failures are expected for now, the MVP is still not working properly.");

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

// --- Copied/Modified from bitcoin_scriptexec ---
// Executor function that runs Bitcoin script with the provided witness data
fn execute_script_with_witness_custom_opts(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    options: Options,
) -> ExecuteInfo {
    // Create a transaction template for script execution
    let tx_template = TxTemplate {
        tx: Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        },
        prevouts: vec![],
        input_idx: 0,
        taproot_annex_scriptleaf: Some((bitcoin::hashes::Hash::all_zeros(), None)),
    };

    // Create an executor with the script and witness data
    let mut exec = Exec::new(ExecCtx::Tapscript, options, tx_template, script, witness)
        .expect("error creating exec");

    // Execute the script until completion or error
    loop {
        match exec.exec_next() {
            Ok(()) => {}
            Err(_) => {
                break;
            }
        }
    }

    // Get the execution result
    let res = exec.result().expect("Execution did not produce a result");

    // Return execution information
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
    }
}
// --- End Copied/Modified ---

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

// --- Helper function from bitcoin_scriptexec source ---
// Adapted slightly to avoid dependency on internal Error type
fn convert_scriptbuf_to_witness(
    script: ScriptBuf,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    // We need a static reference for instructions_minimal, boxing achieves this.
    // This is a bit of a workaround due to lifetime constraints.
    let script_ref = Box::leak(script.into_boxed_script()) as &'static bitcoin::Script;
    let instructions = script_ref.instructions_minimal();
    let mut stack = vec![];

    // Process each instruction in the script
    for instruction in instructions {
        let instruction =
            instruction.map_err(|e| format!("Invalid script instruction: {:?}", e))?;

        match instruction {
            // Push bytes onto the stack
            Instruction::PushBytes(p) => {
                stack.push(p.as_bytes().to_vec());
            }
            // Handle opcodes (limited support for witness)
            Instruction::Op(op) => {
                match op {
                    // Push negative one
                    OP_PUSHNUM_NEG1 => {
                        stack.push(vec![0x81]);
                    }
                    // Push small integers 1-16
                    OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4 | OP_PUSHNUM_5
                    | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9 | OP_PUSHNUM_10
                    | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14
                    | OP_PUSHNUM_15 | OP_PUSHNUM_16 => {
                        let n = op.to_u8() - (OP_PUSHNUM_1.to_u8() - 1);
                        stack.push(vec![n]);
                    }
                    // Any other opcode is invalid in a scriptSig used as witness
                    _ => return Err(format!("scriptSig contains invalid opcode: {:?}", op).into()),
                }
            }
        }
    }

    // Clean up the leaked script reference (important!)
    unsafe {
        let _ = Box::from_raw(script_ref as *const bitcoin::Script as *mut bitcoin::Script);
    }

    Ok(stack)
}
// --- End Helper ---

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
