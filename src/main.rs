#![feature(proc_macro_hygiene)] // If using bitcoin_script macro

use bitcoin::PublicKey;
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::script::{Instruction, Instructions};
use bitcoin_script::script;
use bitcoin_script_dsl::treepp::*;
use bitcoin_scriptexec::{Exec, ExecCtx, ExecuteInfo, FmtStack, Options, TxTemplate};
use std::error::Error;

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
/// Checks: 1. Signer Sig, 2. Hash Puzzle (H(x) == target_hash_value), 3. Subfunction Fi
fn generate_script_pubkey(
    _config: &ColliderVmConfig, // Config not strictly needed for exact hash match puzzle
    signer_pubkey: &PublicKey,
    target_hash_value: u32, // Target value for the exact hash puzzle
    sub_function_script: &ScriptBuf,
) -> ScriptBuf {
    // Witness stack expected by this script: [signer_sig, r, x] (x at top initially)
    // MVP Simplification: 'r' is ignored for the hash puzzle.

    script! {
        // Stack: [signer_sig, r, x]

        // 1. Verify Hash Puzzle H(x) == target_hash_value
        // x is at the top, r is below it. We need x for the hash.
        OP_DUP       // Stack: [signer_sig, r, x, x]
        // Apply the custom hash function H(x)
        { script_collider_hash() } // Stack: [signer_sig, r, x, H(x)]

        // Compare H(x) with the target value target_hash_value
        <target_hash_value> // Stack: [signer_sig, r, x, H(x), target_hash_value]
        OP_EQUALVERIFY      // Stack: [signer_sig, r, x] - Fails if H(x) != target_hash_value

        // 2. Verify Subfunction Fi(x)
        // x is on top. Append the subfunction's script logic.
        { sub_function_script.clone() } // Stack: [signer_sig, r] (assuming subfunction consumes x and leaves nothing)

        // Clean up witness stack
        OP_DROP      // Stack: [signer_sig] - Drop r (since it wasn't used in the hash)

        // 3. Verify Signer's Signature (Commented out for MVP)
        <signer_pubkey.to_bytes()> // Stack: [signer_sig, signer_pubkey]
        // OP_CHECKSIGVERIFY // Fails if signature is invalid -- COMMENTED OUT

        // Clean up stack from bypassed signature check
        OP_DROP // Drop signer_pubkey, Stack: [signer_sig]
        OP_DROP // Drop signer_sig, Stack: []

        // Script succeeds if it reaches here without VERIFY failing
        OP_TRUE // Leave TRUE on stack for success
    }
}

// --- Simulation Logic ---

/// Simulates the operator finding a valid x for a target d_val and config B.
/// Uses the MVP puzzle H(x) == target_hash_val. 'r' is not used.
fn find_b_pair_simplified_exact(
    _config: &ColliderVmConfig, // Config not needed for exact hash match
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
        // Return a dummy nonce as 'r' isn't used in the hash check
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
    let f1_script = script_f1();
    let f2_script = script_f2();

    // Pass the full target_hash_value to the script generation
    let script_pubkey_1 =
        generate_script_pubkey(&config, &signer_info.pubkey, target_hash_value, &f1_script);
    let script_pubkey_2 =
        generate_script_pubkey(&config, &signer_info.pubkey, target_hash_value, &f2_script);

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
    // This function needs to be updated for the new puzzle H(x) == target
    let operator_r = match find_b_pair_simplified_exact(&config, target_hash_value, &operator_x) {
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

    // 8. Simulate Execution using bitcoin_scriptexec
    println!("\n--- Simulating Execution ---");

    // Convert scriptSig ScriptBuf to Vec<Vec<u8>> witness format
    let witness_1 = convert_scriptbuf_to_witness(script_sig_1)?;
    let witness_2 = convert_scriptbuf_to_witness(script_sig_2)?;

    // Create custom options with minimal checks disabled
    let mut exec_options = Options::default();
    exec_options.require_minimal = false;
    exec_options.verify_minimal_if = false; // Also disable minimal IF check just in case

    println!("\nExecuting Tx1 (scriptPubKey_1 + witness_1)...");
    // Use the custom execute function with modified options
    let exec_result_1 = execute_script_with_witness_custom_opts(
        script_pubkey_1.clone(),
        witness_1,
        exec_options.clone(),
    );
    if exec_result_1.success {
        println!("Tx1 Succeeded (simulated).");
        println!("Tx1 Result: {}", exec_result_1); // Display the full result struct
    } else {
        println!("Tx1 FAILED execution!");
        println!("Tx1 Error details: {}", exec_result_1);
        return Err("Tx1 FAILED execution!".into());
    }

    println!("\nExecuting Tx2 (scriptPubKey_2 + witness_2)...");
    // Use the custom execute function with modified options
    let exec_result_2 =
        execute_script_with_witness_custom_opts(script_pubkey_2.clone(), witness_2, exec_options);
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

// Translates f1(x): x > F1_THRESHOLD into Bitcoin Script
// Assumes x is on top of the stack (as a 4-byte LE integer)
fn script_f1() -> ScriptBuf {
    script! {
        // Stack: [..., x]
        <F1_THRESHOLD> // Stack: [..., x, 100]
        // OP_GREATERTHAN checks stack[-2] > stack[-1]. This checks x > 100.
        OP_GREATERTHAN // Stack: [..., 1] or [..., 0]
        OP_VERIFY      // Fail script if result is not true (1)
    }
}

// Translates f2(x): x < F2_THRESHOLD into Bitcoin Script
// Assumes x is on top of the stack (as a 4-byte LE integer)
fn script_f2() -> ScriptBuf {
    script! {
        // Stack: [..., x]
        <F2_THRESHOLD> // Stack: [..., x, 200]
        // OP_LESSTHAN checks stack[-2] < stack[-1]. This checks x < 200.
        OP_LESSTHAN    // Stack: [..., 1] or [..., 0]
        OP_VERIFY      // Fail script if result is not true (1)
    }
}

fn main() {
    if let Err(e) = run_mvp_simulation() {
        eprintln!("Simulation Error: {}", e);
    }
}

// --- Copied/Modified from bitcoin_scriptexec ---
// We need to modify the options used
use bitcoin::locktime::absolute::LockTime;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::{Transaction, Version};

fn execute_script_with_witness_custom_opts(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    options: Options, // Allow passing custom options
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
        // Use the generic Hash trait method for all-zero hash
        taproot_annex_scriptleaf: Some((bitcoin::hashes::Hash::all_zeros(), None)),
    };

    let mut exec = Exec::new(
        ExecCtx::Tapscript, // Assuming Tapscript context
        options,            // Use provided options
        tx_template,
        script,
        witness,
    )
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
        #[cfg(feature = "profiler")]
        profiler: res.profiler.clone().unwrap_or_default(), // Handle potential None profiler
    }
}
// --- End Copied/Modified ---
