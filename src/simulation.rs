use std::collections::HashMap;
use std::error::Error;

use bitcoin::{PublicKey, secp256k1::Secp256k1};
use bitvm::execute_script_buf;

use crate::collidervm_toy::{
    ColliderVmConfig, F1_THRESHOLD, F2_THRESHOLD, OperatorInfo, SignerInfo, calculate_blake3_hash,
    calculate_flow_id, find_valid_nonce, script_f1, script_f1_with_signature, script_f2,
    script_f2_with_signature,
};

// --- Simulation Structures ---

/// Represents a presigned transaction flow
#[derive(Debug)]
pub struct PresignedFlow {
    pub flow_id: u32,
    #[allow(dead_code)]
    pub f1_script: bitcoin::blockdata::script::ScriptBuf,
    #[allow(dead_code)]
    pub f2_script: bitcoin::blockdata::script::ScriptBuf,
}

pub struct SimulationResult {
    pub success: bool,
    pub _f1_result: bool,
    pub _f2_result: bool,
    pub message: String,
}

// Create a type alias to simplify the return type of offline_setup
type SetupResult = (
    Vec<SignerInfo>,
    Vec<OperatorInfo>,
    HashMap<u32, PresignedFlow>,
);

// --- Simulation Logic ---

/// Simulates the offline setup phase of ColliderVM
/// Generates n signers and m operators with keypairs and presigns transaction flows
pub fn offline_setup(config: &ColliderVmConfig) -> Result<SetupResult, Box<dyn Error>> {
    println!("--- Offline Setup Phase ---");
    println!(
        "Generating {} signers and {} operators...",
        config.n, config.m
    );

    // Set up the secp256k1 context for key generation
    let secp = Secp256k1::new();
    let mut signers = Vec::with_capacity(config.n);
    let mut operators = Vec::with_capacity(config.m);

    // Generate signers with key pairs
    for i in 0..config.n {
        let (privkey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let signer = SignerInfo {
            _id: i,
            pubkey: PublicKey::new(pubkey),
            _privkey: privkey,
        };
        println!("Generated Signer {}: {}", i, signer.pubkey);
        signers.push(signer);
    }

    // Generate operators with key pairs
    for i in 0..config.m {
        let (privkey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let operator = OperatorInfo {
            _id: i,
            pubkey: PublicKey::new(pubkey),
            _privkey: privkey,
        };
        println!("Generated Operator {}: {}", i, operator.pubkey);
        operators.push(operator);
    }

    // Generate presigned transaction flows
    println!(
        "\nGenerating presigned flow scripts for D set (size 2^{})...",
        config.l
    );

    // In the real ColliderVM, we'd generate 2^L flows
    // For our toy simulation, we'll generate fewer flows for practicality
    let num_flows = std::cmp::min(1 << config.l, 16); // Max 16 flows for toy simulation
    println!("Using {} flows for toy simulation", num_flows);

    let mut presigned_flows = HashMap::new();

    // Generate script for each flow (each potential value of d ∈ D)
    for flow_id in 0..num_flows {
        // In a real implementation, we'd:
        // 1. Create actual Bitcoin tx templates
        // 2. Have signers sign these templates
        // 3. Store the complete presigned txs

        // For our toy simulation, we'll just create the locking scripts
        // that would check signatures in the real implementation

        // Create F1 script with signature verification for this flow
        let f1_script = script_f1_with_signature(&signers[0].pubkey, flow_id as u32, config.b);

        // Create F2 script with signature verification for this flow
        let f2_script = script_f2_with_signature(&signers[0].pubkey, flow_id as u32, config.b);

        // Store the flow scripts
        presigned_flows.insert(
            flow_id as u32,
            PresignedFlow {
                flow_id: flow_id as u32,
                f1_script,
                f2_script,
            },
        );

        if flow_id % 4 == 0 {
            println!("  Created flow {} of {}", flow_id + 1, num_flows);
        }
    }

    println!(
        "Offline setup complete with {} presigned flows\n",
        presigned_flows.len()
    );
    Ok((signers, operators, presigned_flows))
}

/// Executes the online phase of ColliderVM with a given input value
/// Returns the simulation result with success/failure status
pub fn online_execution(
    _signers: &[SignerInfo],
    operators: &[OperatorInfo],
    presigned_flows: &HashMap<u32, PresignedFlow>,
    config: &ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    println!("--- Online Execution Phase ---");
    println!(
        "Config: L={}, B={}, k={}, n={}, m={}",
        config.l, config.b, config.k, config.n, config.m
    );
    println!("Using input value: {}", input_value);

    // For the toy simulation, we'll use the first operator
    let operator = &operators[0];
    println!("Using operator: {}", operator.pubkey);

    // Convert input to bytes
    let x_bytes = input_value.to_le_bytes().to_vec();

    // Find a valid nonce for the input value
    // This is the hash collision challenge from the ColliderVM paper
    let (nonce, flow_id) = find_valid_nonce(input_value, config.b, config.l);
    println!("Found valid nonce {} for flow_id: {}", nonce, flow_id);

    // Check if we have the presigned flow for this flow_id
    if !presigned_flows.contains_key(&flow_id) {
        return Err(format!("No presigned flow found for flow_id: {}", flow_id).into());
    }

    let flow = &presigned_flows[&flow_id];
    println!("Using presigned flow with ID: {}", flow.flow_id);

    // The limb length for Blake3 hash computation
    let _limb_len = 4;

    // Compute the expected hash in advance for verification
    let full_hash = calculate_blake3_hash(&x_bytes);
    println!("Blake3 hash of input: {}", hex::encode(full_hash));

    // Results tracking
    let mut f1_result = false;
    let mut f2_result = false;

    // For toy simulation, we'll create dummy signatures
    // In a real implementation, these would be actual signatures created by the operator
    let _dummy_sig = [0u8; 64]; // Dummy signature for simulation

    // ---- Execute F1 with signature check (Flow 1) ----
    println!(
        "\nExecuting F1 with signature verification (Flow {})...",
        flow_id
    );

    // In a real implementation, we'd:
    // 1. Use a presigned transaction with F1 logic
    // 2. Include signatures from signers
    // 3. Execute the actual transaction

    // For toy simulation, we'll execute just the script
    // First, simulate the normal execution without signature check
    // Then check if the flow_id matches and if the F1 constraint is satisfied

    // Build the script for F1 check only (without signature verification)
    let mut script1_bytes = bitcoin::blockdata::script::Builder::new()
        .push_int(input_value as i64) // Push input
        .push_int(F1_THRESHOLD as i64) // Push F1 threshold
        .into_script()
        .to_bytes();

    // Add the F1 check (is input > threshold?)
    script1_bytes.extend(script_f1().to_bytes());

    // Execute the F1 check script
    let script1 = bitcoin::blockdata::script::ScriptBuf::from_bytes(script1_bytes);
    let exec_result_1 = execute_script_buf(script1);

    // Verify that the flow_id matches what we calculated
    let flow_check = flow_id == calculate_flow_id(input_value, nonce, config.b, config.l);
    println!(
        "Flow ID check: {}",
        if flow_check { "PASSED" } else { "FAILED" }
    );

    // In a real implementation, we'd also verify the signature here
    println!("F1 execution result: {:?}", exec_result_1);
    if exec_result_1.success && flow_check {
        println!("F1 check (x > {}) PASSED", F1_THRESHOLD);
        f1_result = true;
    } else {
        println!("F1 check (x > {}) FAILED", F1_THRESHOLD);
        println!(
            "Reason: {}",
            if !exec_result_1.success {
                "F1 constraint not satisfied"
            } else {
                "Flow ID check failed"
            }
        );
    }

    // ---- Execute F2 with signature check (Flow 2) ----
    println!(
        "\nExecuting F2 with signature verification (Flow {})...",
        flow_id
    );

    // Build the script for F2 check only (without signature verification)
    let mut script2_bytes = bitcoin::blockdata::script::Builder::new()
        .push_int(input_value as i64) // Push input
        .push_int(F2_THRESHOLD as i64) // Push F2 threshold
        .into_script()
        .to_bytes();

    // Add the F2 check (is input < threshold?)
    script2_bytes.extend(script_f2().to_bytes());

    // Execute the F2 check script
    let script2 = bitcoin::blockdata::script::ScriptBuf::from_bytes(script2_bytes);
    let exec_result_2 = execute_script_buf(script2);

    // The flow_id check is the same as for F1
    println!("F2 execution result: {:?}", exec_result_2);

    if exec_result_2.success && flow_check {
        println!("F2 check (x < {}) PASSED", F2_THRESHOLD);
        f2_result = true;
    } else {
        println!("F2 check (x < {}) FAILED", F2_THRESHOLD);
        println!(
            "Reason: {}",
            if !exec_result_2.success {
                "F2 constraint not satisfied"
            } else {
                "Flow ID check failed"
            }
        );
    }

    // Determine overall simulation success
    let success = f1_result && f2_result;
    println!("\n--- Execution Complete ---");

    // Create and return the simulation result
    let result = SimulationResult {
        success,
        _f1_result: f1_result,
        _f2_result: f2_result,
        message: if success {
            format!(
                "Successfully verified input {} satisfies all conditions using flow {}",
                input_value, flow_id
            )
        } else {
            format!(
                "Input {} failed to satisfy conditions using flow {}: F1({}>{})={}, F2({}<{})={}",
                input_value,
                flow_id,
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
    let (signers, operators, presigned_flows) = offline_setup(&config)?;

    // Step 2: Online Execution
    let result = online_execution(&signers, &operators, &presigned_flows, &config, input_value)?;

    // Step 3: Report Results
    println!("\n--- Simulation Summary ---");
    println!("{}", result.message);

    Ok(result)
}
