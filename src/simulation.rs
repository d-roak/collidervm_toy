use std::error::Error;

use bitcoin::{
    PublicKey,
    secp256k1::{self, Secp256k1},
};
use bitcoin_script_stack::optimizer;
use bitvm::{
    execute_script_buf,
    hash::blake3::{blake3_compute_script_with_limb, blake3_push_message_script_with_limb},
};

use crate::collidervm_toy::{
    ColliderVmConfig, F1_THRESHOLD, F2_THRESHOLD, OperatorInfo, SignerInfo,
    blake3_verify_output_script, calculate_blake3_hash, script_f1, script_f2,
};

// --- Simulation Structures ---

pub struct SimulationResult {
    pub success: bool,
    pub f1_result: bool,
    pub f2_result: bool,
    pub message: String,
}

// --- Simulation Logic ---

/// Simulates the offline setup phase of ColliderVM
/// Generates n signers and m operators with keypairs
pub fn offline_setup(
    config: &ColliderVmConfig,
) -> Result<(Vec<SignerInfo>, Vec<OperatorInfo>), Box<dyn Error>> {
    println!("--- Offline Setup Phase ---");
    println!(
        "Generating {} signers and {} operators...",
        config.n, config.m
    );

    let secp = Secp256k1::new();
    let mut signers = Vec::with_capacity(config.n);
    let mut operators = Vec::with_capacity(config.m);

    // Generate signers
    for i in 0..config.n {
        let (_privkey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let signer = SignerInfo {
            id: i,
            pubkey: PublicKey::new(pubkey),
        };
        println!("Generated Signer {}: {}", i, signer.pubkey);
        signers.push(signer);
    }

    // Generate operators
    for i in 0..config.m {
        let (_privkey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let operator = OperatorInfo {
            id: i,
            pubkey: PublicKey::new(pubkey),
        };
        println!("Generated Operator {}: {}", i, operator.pubkey);
        operators.push(operator);
    }

    println!("Offline setup complete\n");
    Ok((signers, operators))
}

/// Executes the online phase of ColliderVM with a given input value
/// Returns the simulation result with success/failure status
pub fn online_execution(
    _signers: &[SignerInfo],
    _operators: &[OperatorInfo],
    config: &ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    println!("--- Online Execution Phase ---");
    println!(
        "Config: L={}, B={}, k={}, n={}, m={}",
        config.l, config.b, config.k, config.n, config.m
    );
    println!("Using input value: {}", input_value);

    // Convert input to bytes
    let x_bytes = input_value.to_le_bytes().to_vec(); // LE bytes representation

    // The limb length for Blake3 hash computation
    let limb_len = 4;

    // Compute the expected hash in advance
    let full_hash = calculate_blake3_hash(&x_bytes);
    println!("Blake3 hash of input: {}", hex::encode(&full_hash));

    // Results tracking
    let mut f1_result = false;
    let mut f2_result = false;

    // ---- Script 1 (Blake3 + F1) Test ----
    println!("\nExecuting Script 1 (Blake3 + F1)...");

    // Build the full script with Blake3 hash verification and F1 check
    let mut script1_bytes = blake3_push_message_script_with_limb(&x_bytes, limb_len)
        .compile()
        .to_bytes();

    let optimized1 =
        optimizer::optimize(blake3_compute_script_with_limb(x_bytes.len(), limb_len).compile());
    script1_bytes.extend(optimized1.to_bytes());

    // Add hash verification
    script1_bytes.extend(blake3_verify_output_script(full_hash).to_bytes());

    // Add F1 script which uses script_f1() from collidervm_toy
    script1_bytes.extend(
        bitcoin::blockdata::script::Builder::new()
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_DROP) // Remove 0x01 from Blake3 verification
            .push_int(input_value as i64) // Push input
            .push_int(F1_THRESHOLD as i64) // Push F1 threshold
            .into_script()
            .to_bytes(),
    );

    // Add the F1 check (is input > threshold?)
    script1_bytes.extend(script_f1().to_bytes());

    // Create and execute final script
    let script1 = bitcoin::blockdata::script::ScriptBuf::from_bytes(script1_bytes);
    let exec_result_1 = execute_script_buf(script1);

    if exec_result_1.success {
        println!("Script 1 (Blake3 + F1) Execution Succeeded!");
        println!("Result: {:?}", exec_result_1);
        f1_result = true;
    } else {
        println!("Script 1 (Blake3 + F1) Execution FAILED!");
        println!("Error details: {:?}", exec_result_1);
    }

    // ---- Script 2 (Blake3 + F2) Test ----
    println!("\nExecuting Script 2 (Blake3 + F2)...");

    // Build the full script with Blake3 hash verification and F2 check
    let mut script2_bytes = blake3_push_message_script_with_limb(&x_bytes, limb_len)
        .compile()
        .to_bytes();

    let optimized2 =
        optimizer::optimize(blake3_compute_script_with_limb(x_bytes.len(), limb_len).compile());
    script2_bytes.extend(optimized2.to_bytes());

    // Add hash verification
    script2_bytes.extend(blake3_verify_output_script(full_hash).to_bytes());

    // Add F2 script which uses script_f2() from collidervm_toy
    script2_bytes.extend(
        bitcoin::blockdata::script::Builder::new()
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_DROP) // Remove 0x01 from Blake3 verification
            .push_int(input_value as i64) // Push input
            .push_int(F2_THRESHOLD as i64) // Push F2 threshold
            .into_script()
            .to_bytes(),
    );

    // Add the F2 check (is input < threshold?)
    script2_bytes.extend(script_f2().to_bytes());

    // Create and execute final script
    let script2 = bitcoin::blockdata::script::ScriptBuf::from_bytes(script2_bytes);
    let exec_result_2 = execute_script_buf(script2);

    if exec_result_2.success {
        println!("Script 2 (Blake3 + F2) Execution Succeeded!");
        println!("Result: {:?}", exec_result_2);
        f2_result = true;
    } else {
        println!("Script 2 (Blake3 + F2) Execution FAILED!");
        println!("Error details: {:?}", exec_result_2);
    }

    // Determine overall simulation success
    let success = f1_result && f2_result;
    println!("\n--- Execution Complete ---");

    // Create and return the simulation result
    let result = SimulationResult {
        success,
        f1_result,
        f2_result,
        message: if success {
            format!(
                "Successfully verified input {} satisfies all conditions",
                input_value
            )
        } else {
            format!(
                "Input {} failed to satisfy conditions: F1({}>{})={}, F2({}<{})={}",
                input_value,
                input_value,
                F1_THRESHOLD,
                f1_result,
                input_value,
                F2_THRESHOLD,
                f2_result
            )
        },
    };

    Ok(result)
}

/// Orchestrates the complete ColliderVM simulation
pub fn run_simulation(
    config: ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    // Step 1: Offline Setup
    let (signers, operators) = offline_setup(&config)?;

    // Step 2: Online Execution
    let result = online_execution(&signers, &operators, &config, input_value)?;

    // Step 3: Report Results
    println!("\n--- Simulation Summary ---");
    println!("{}", result.message);

    Ok(result)
}
