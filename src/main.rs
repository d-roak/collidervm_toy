#![feature(proc_macro_hygiene)] // If using bitcoin_script macro

use bitcoin::{
    PublicKey, Transaction,
    blockdata::opcodes::all::*,
    blockdata::script::{Instruction, ScriptBuf},
    locktime::absolute::LockTime,
    transaction::Version,
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use bitvm::hash::blake3::blake3_compute_script_with_limb;
use bitvm::treepp::script;
use bitvm::u32::u32_std::u32_drop;
use bitvm::u32::u32_xor::{u8_drop_xor_table, u8_push_xor_table};

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
        { u8_push_xor_table() } // Still assuming these exist and are callable

        // Perform Blake3 hash
        { blake3_compute_script_with_limb(0, 4) }

        // Drop the top 7 chunks
        for _ in 0..7 {
            { u32_drop() }
        }

        // Clean up the Blake3 lookup table
        { u8_drop_xor_table() }
    }
    .compile()
}

// --- Script Generation ---

/// Generates the scriptPubKey for a ColliderVM transaction (MVP simplified).
/// Checks: 1. Signer Sig, 2. Hash Puzzle (H(x) == target_hash_value), 3. Subfunction Fi
fn generate_script_pubkey(
    // _config: &ColliderVmConfig, // Removed unused parameter
    signer_pubkey: &PublicKey,
    target_hash_value: u32,
    sub_function_script: &ScriptBuf,
) -> ScriptBuf {
    // Witness stack expected by this script: [signer_sig, r, x] (x at top initially)
    // MVP Simplification: 'r' is ignored for the hash puzzle.

    let script_collider_hash_blake3_script = script_collider_hash_blake3()
        .as_script()
        .as_bytes()
        .to_vec();

    let sub_function_script_bytes = sub_function_script.as_script().as_bytes().to_vec();

    script! {
        OP_DUP
        { script_collider_hash_blake3_script }
        <target_hash_value>
        OP_EQUALVERIFY
        { sub_function_script_bytes }
        OP_DROP
        <signer_pubkey.to_bytes()>
        // OP_CHECKSIGVERIFY
        OP_DROP
        OP_DROP
        OP_TRUE
    }
    .compile()
}

// --- Simulation Logic ---

/// Simulates the operator finding a valid x for a target d_val and config B.
/// Uses the MVP puzzle H(x) == target_hash_val. 'r' is not used.
fn find_b_pair_simplified_exact(
    // _config: &ColliderVmConfig, // Removed unused parameter
    target_hash_val: u32,
    candidate_x: &InputX,
) -> Option<NonceR> {
    let hash_result = collider_hash(candidate_x);

    // Safely get u32 value for printing
    let x_val_for_print = match candidate_x.as_slice().try_into() {
        Ok(arr) => u32::from_le_bytes(arr),
        Err(_) => 0, // Default for printing if conversion fails
    };

    println!(
        "find_b_pair_simplified_exact: Testing x = {} ({}), H(x) = {}",
        x_val_for_print,
        hex::encode(candidate_x),
        hash_result
    );

    if hash_result == target_hash_val {
        println!("  -> Match found for target H(x) = {}", target_hash_val);
        Some(vec![0u8; 8])
    } else {
        println!("  -> No match for target H(x) = {}", target_hash_val);
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

    // 3. Choose Target Hash Value
    // NEW: Target the full hash H(x) = x + CONSTANT
    // Example: Let's find an x such that H(x) is easily representable.
    // If x=114, H(x) = 114 + 12345 = 12459 (0x30AB)
    let target_hash_value: u32 = 12459;
    println!(
        "Target Full Hash Value: {} (0x{:X})",
        target_hash_value, target_hash_value
    );

    // 4. Find a suitable input 'x' that satisfies the puzzle and functions
    // We need x such that:
    // a) F1(x) is true (x > 100)
    // b) F2(x) is true (x < 200)
    // c) H(x) == target_hash_value (where H(x) = x + 12345)
    let mut valid_x_bytes: Option<Vec<u8>> = None;
    let mut found_x_val: u32 = 0;

    println!(
        "Searching for valid x (100 < x < 200) such that (x + {}) == {}...",
        SIMPLE_HASH_CONSTANT, target_hash_value
    );

    for x_val in (F1_THRESHOLD + 1)..F2_THRESHOLD {
        let x_bytes = x_val.to_le_bytes().to_vec();
        let hash_val = collider_hash(&x_bytes);
        // Check the full hash value
        if hash_val == target_hash_value {
            // Also check f1 and f2 conditions here for clarity
            if x_val > F1_THRESHOLD && x_val < F2_THRESHOLD {
                println!("Found valid x = {} (0x{:X})", x_val, x_val);
                println!("  - H({}) = {} (Matches target)", x_val, hash_val);
                println!("  - F1({}) = true", x_val);
                println!("  - F2({}) = true", x_val);
                valid_x_bytes = Some(x_bytes);
                found_x_val = x_val;
                break;
            } else {
                println!(
                    "Found x = {} with H(x) matching target, but F1/F2 failed.",
                    x_val
                );
            }
        }
    }

    let operator_x = match valid_x_bytes {
        Some(bytes) => bytes,
        None => {
            println!(
                "ERROR: Could not find a valid 'x' satisfying puzzle H(x)={} AND function constraints.",
                target_hash_value
            );
            // Explicitly check if the target itself is findable in the range
            if target_hash_value > SIMPLE_HASH_CONSTANT {
                let required_x = target_hash_value - SIMPLE_HASH_CONSTANT;
                if required_x <= F1_THRESHOLD || required_x >= F2_THRESHOLD {
                    println!(
                        "Note: The required x={} to hit the target hash is outside the F1/F2 range ({} < x < {}).",
                        required_x, F1_THRESHOLD, F2_THRESHOLD
                    );
                }
            } else {
                println!("Note: Target hash is not reachable with positive x.");
            }
            return Ok(()); // Exit gracefully if no valid x found
        }
    };
    println!(
        "Chosen Operator x: {} ({})",
        found_x_val,
        hex::encode(&operator_x)
    );

    // 5. Generate Scripts for the chosen flow target_hash_value
    let f1_script: ScriptBuf = script_f1(); // Returns ScriptBuf
    let f2_script: ScriptBuf = script_f2(); // Returns ScriptBuf

    // Pass relevant parameters only
    let script_pubkey_1: ScriptBuf = generate_script_pubkey(
        /*&config,*/ &signer_info.pubkey,
        target_hash_value,
        &f1_script, // Pass reference
    );
    let script_pubkey_2: ScriptBuf = generate_script_pubkey(
        /*&config,*/ &signer_info.pubkey,
        target_hash_value,
        &f2_script, // Pass reference
    );

    // Debug: Print generated scripts
    println!(
        "\nGenerated ScriptPubKey 1 (f1) for target H(x)={}:",
        target_hash_value
    );
    println!("{}", script_pubkey_1);
    println!(
        "\nGenerated ScriptPubKey 2 (f2) for target H(x)={}:",
        target_hash_value
    );
    println!("{}", script_pubkey_2);

    // 6. Operator "Finds" Nonce (using the found x)
    // Pass relevant parameters only
    let operator_r = match find_b_pair_simplified_exact(
        /*&config,*/ target_hash_value,
        &operator_x,
    ) {
        Some(r) => {
            println!(
                "Operator confirmed valid x matches target H(x)={}.",
                target_hash_value
            );
            r
        }
        None => {
            // This shouldn't happen if our search logic in step 4 was correct
            println!(
                "ERROR: Operator failed to *confirm* valid x for target H(x)={} (logic mismatch?).",
                target_hash_value
            );
            return Ok(());
        }
    };

    // 7. Operator Builds Witnesses (ScriptSigs) - Use bitcoin_script::script!
    let dummy_sig = vec![0u8; 71];
    let script_sig_1: ScriptBuf = script! { // Return ScriptBuf
        { dummy_sig.clone() }
        { operator_r.clone() }
        { operator_x.clone() }
    }
    .compile();
    let script_sig_2 = script_sig_1.clone();

    println!("\nWitness for Tx1/Tx2 (bottom to top): [sig, r, x]");
    println!("  x: {}", hex::encode(&operator_x));
    println!("  r: {} (dummy nonce)", hex::encode(&operator_r));
    println!("sig: {}... (dummy)", hex::encode(&dummy_sig[..4]));

    // 8. Simulate Execution
    // No compilation needed now
    let witness_1 = convert_scriptbuf_to_witness(script_sig_1)?;
    let witness_2 = convert_scriptbuf_to_witness(script_sig_2)?;

    let exec_options = Options {
        require_minimal: false,
        ..Default::default()
    };

    println!("\nExecuting Tx1 ...");
    let exec_result_1 = execute_script_with_witness_custom_opts(
        script_pubkey_1.clone(), // Pass ScriptBuf directly
        witness_1,
        exec_options.clone(),
    );
    if exec_result_1.success {
        println!("Tx1 Succeeded (simulated).");
        println!("Tx1 Result: {}", exec_result_1);
    } else {
        println!("Tx1 FAILED execution!");
        println!("Tx1 Error details: {}", exec_result_1);
        return Err("Tx1 FAILED execution!".into());
    }

    println!("\nExecuting Tx2 ...");
    let exec_result_2 = execute_script_with_witness_custom_opts(
        script_pubkey_2.clone(), // Pass ScriptBuf directly
        witness_2,
        exec_options,
    );
    if exec_result_2.success {
        println!("Tx2 Succeeded (simulated).");
        println!("Tx2 Result: {}", exec_result_2);
    } else {
        println!("Tx2 FAILED execution!");
        println!("Tx2 Error details: {}", exec_result_2);
        return Err("Tx2 FAILED execution!".into());
    }

    println!("\n--- Simulation Complete ---");

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
// Re-add the custom executor function
fn execute_script_with_witness_custom_opts(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    options: Options,
) -> ExecuteInfo {
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

    let mut exec = Exec::new(ExecCtx::Tapscript, options, tx_template, script, witness)
        .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().expect("Execution did not produce a result");

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
    let x_bytes = 114u32.to_le_bytes();
    let target_hash_val = collider_hash_blake3(&x_bytes);
    println!(
        "Temporary Target Blake3 Hash for x=114: {} (0x{:X})",
        target_hash_val, target_hash_val
    );

    // Comment out the actual simulation for now
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

    for instruction in instructions {
        let instruction =
            instruction.map_err(|e| format!("Invalid script instruction: {:?}", e))?;

        match instruction {
            Instruction::PushBytes(p) => {
                stack.push(p.as_bytes().to_vec());
            }
            Instruction::Op(op) => {
                match op {
                    // Push value
                    OP_PUSHNUM_NEG1 => {
                        stack.push(vec![0x81]);
                    }
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
