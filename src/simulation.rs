use std::{collections::HashMap, error::Error};

use bitcoin::{
    Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    blockdata::script::ScriptBuf,
};
use secp256k1::{Keypair, Secp256k1}; // For signing/verification

use crate::collidervm_toy::{
    ColliderVmConfig, F1_THRESHOLD, F2_THRESHOLD, OperatorInfo, PresignedFlow, PresignedStep,
    SignerInfo, build_script_f1_locked, build_script_f2_locked, calculate_flow_id,
    create_toy_sighash_message, find_valid_nonce,
};

// --- Simulation Structures ---
pub struct SimulationResult {
    pub success: bool,
    pub _f1_result: bool, // Made public for clarity
    pub _f2_result: bool, // Made public for clarity
    pub message: String,
}

type SetupResult = (
    Vec<SignerInfo>,
    Vec<OperatorInfo>,
    HashMap<u32, PresignedFlow>,
);

// Helper to create a placeholder transaction for signing
fn create_placeholder_tx(
    locking_script: ScriptBuf,
    value: Amount,
    input_txid: Txid,
    input_vout: u32,
) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_txid,
                vout: input_vout,
            },
            script_sig: ScriptBuf::new(), // Empty for Taproot/SegWit signing
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, // Example sequence
            witness: Witness::new(),      // Empty witness during template creation
        }],
        output: vec![TxOut {
            value,
            script_pubkey: locking_script,
        }],
    }
}

// --- Simulation Logic ---

/// Simulates the offline setup phase of ColliderVM
/// Generates keys, creates transaction templates, calculates sighashes,
/// and collects signatures from all signers.
pub fn offline_setup(config: &ColliderVmConfig) -> Result<SetupResult, Box<dyn Error>> {
    println!("--- Offline Setup Phase ---");
    println!(
        "Generating {} signers and {} operators...",
        config.n, config.m
    );

    // Secp256k1 context for key generation and signing
    let secp = Secp256k1::new(); // Use Secp256k1::new() for signing context
    let mut signers = Vec::with_capacity(config.n);
    let mut operators = Vec::with_capacity(config.m);

    // Generate signers
    for i in 0..config.n {
        let (privkey, secp_pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &privkey);
        let (xonly, _parity) = keypair.x_only_public_key();
        let signer = SignerInfo {
            _id: i,
            pubkey: PublicKey::new(secp_pubkey),
            _privkey: privkey,
            keypair,
            xonly,
        };
        println!("  Generated Signer {}: {}", i, signer.pubkey);
        signers.push(signer);
    }

    // Generate operators
    for i in 0..config.m {
        let (privkey, secp_pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let operator = OperatorInfo {
            _id: i,
            pubkey: PublicKey::new(secp_pubkey),
            _privkey: privkey,
        };
        println!("  Generated Operator {}: {}", i, operator.pubkey);
        operators.push(operator);
    }

    println!("\nGenerating presigned flows (Transaction Templates + Signatures)...");
    let num_flows = std::cmp::min(1 << config.l, 16); // Limit flows for toy
    println!(
        "  Targeting {} flows (L={}, max 16 for toy)",
        num_flows, config.l
    );
    let mut presigned_flows_map = HashMap::new();

    // Placeholder funding transaction output (needed for the first step's input)
    const DUMMY_TXID: &str = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";

    let funding_txid = DUMMY_TXID.parse::<Txid>().unwrap();
    let funding_vout = 0;
    let funding_amount = Amount::from_sat(10000); // Example amount

    for flow_id in 0..num_flows as u32 {
        let mut steps = Vec::with_capacity(config.k);

        // --- Presign Step 1 (F1) ---
        // 1a. Create Locking Script for F1
        //    Use the public key of the *first* signer for the script construction (simplification)
        let script_f1 = build_script_f1_locked(&signers[0].pubkey, flow_id, config.b);

        // 1b. Create Placeholder Transaction Template for F1
        let tx_f1_template = create_placeholder_tx(
            script_f1.clone(),
            funding_amount, // Output value matches funding for simplicity
            funding_txid,
            funding_vout,
        );

        // 1c. Create Simplified Sighash Message for F1
        //     (Using toy function - real sighash depends on more tx details)
        let sighash_msg_f1 = create_toy_sighash_message(&script_f1, tx_f1_template.output[0].value);

        // 1d. Collect Signatures for F1 from ALL signers
        let mut signatures_f1 = HashMap::new();
        for signer in &signers {
            let signature = secp.sign_schnorr(&sighash_msg_f1, &signer.keypair);
            signatures_f1.insert(signer.pubkey.to_bytes(), signature);
        }

        // 1e. Create Presigned Step for F1
        steps.push(PresignedStep {
            _tx_template: tx_f1_template.clone(), // Store the template
            sighash_message: sighash_msg_f1,
            signatures: signatures_f1,
            _locking_script: script_f1,
        });

        // --- Presign Step 2 (F2) ---
        // (Similar process, but tx_f2 spends tx_f1)
        let script_f2 = build_script_f2_locked(&signers[0].pubkey, flow_id, config.b);
        let tx_f2_template = create_placeholder_tx(
            script_f2.clone(),
            funding_amount,                // Assuming value is conserved
            tx_f1_template.compute_txid(), // Input is output of F1 tx
            0,                             // Assuming F1 tx had one output at vout 0
        );
        let sighash_msg_f2 = create_toy_sighash_message(&script_f2, tx_f2_template.output[0].value);
        let mut signatures_f2 = HashMap::new();
        for signer in &signers {
            let signature = secp.sign_schnorr(&sighash_msg_f2, &signer.keypair);
            signatures_f2.insert(signer.pubkey.to_bytes(), signature);
        }
        steps.push(PresignedStep {
            _tx_template: tx_f2_template,
            sighash_message: sighash_msg_f2,
            signatures: signatures_f2,
            _locking_script: script_f2,
        });

        // Add the fully signed flow to the map
        presigned_flows_map.insert(
            flow_id,
            PresignedFlow {
                _flow_id: flow_id,
                steps,
            },
        );

        if flow_id % 4 == 3 || flow_id == num_flows as u32 - 1 {
            println!("  Created and presigned flow {}...", flow_id);
        }
    }

    println!(
        "Offline setup complete. {} flows presigned by {} signers.\n",
        presigned_flows_map.len(),
        config.n
    );
    Ok((signers, operators, presigned_flows_map))
}

/// Simulates the online execution phase of ColliderVM.
/// Finds nonce, selects flow, verifies signatures, checks hash prefix, executes logic.
pub fn online_execution(
    signers: &[SignerInfo],      // Needed to get the public key for verification
    _operators: &[OperatorInfo], // Not used directly in this simplified online phase
    presigned_flows_map: &HashMap<u32, PresignedFlow>,
    config: &ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    println!("--- Online Execution Phase ---");
    println!(
        "Config: L={}, B={}, k={}, n={}, m={}",
        config.l, config.b, config.k, config.n, config.m
    );
    println!("Input value: {}", input_value);

    // Operator finds a valid nonce and corresponding flow ID
    let (nonce, flow_id) = match find_valid_nonce(input_value, config.b, config.l) {
        Ok(result) => result,
        Err(e) => return Err(e.into()),
    };
    println!(
        "Operator found Nonce: {}, required Flow ID: {}",
        nonce, flow_id
    );

    // Retrieve the corresponding presigned flow
    let presigned_flow = presigned_flows_map.get(&flow_id).ok_or_else(|| {
        format!(
            "Critical Error: Presigned flow {} not found after nonce search!",
            flow_id
        )
    })?;
    println!("Retrieved presigned flow {}", flow_id);

    // Secp256k1 context for verification
    let secp = Secp256k1::verification_only(); // Use verification context

    // --- Simulate Step 1 (F1) Execution ---
    println!("\nSimulating Execution Step 1 (F1)...");
    let step_f1 = &presigned_flow.steps[0];

    // 1a. Verify Signature (Off-chain simulation)
    let signer0_pubkey = &signers[0].pubkey;
    let signer0_xonly = &signers[0].xonly;
    let signature_f1 = step_f1
        .signatures
        .get(&signer0_pubkey.to_bytes())
        .ok_or("Signature from signer 0 not found for step 1")?;
    let signature_f1_valid = secp
        .verify_schnorr(signature_f1, &step_f1.sighash_message, signer0_xonly)
        .is_ok();
    println!(
        "  Signature Check (Signer 0): {}",
        if signature_f1_valid {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        }
    );

    // 1b. Verify Hash Prefix (Off-chain simulation)
    // This checks if the (input, nonce) pair indeed produces the required flow_id
    let hash_prefix_valid =
        calculate_flow_id(input_value, nonce, config.b, config.l) == Ok(flow_id);
    println!(
        "  Hash Prefix Check (H(x,r)|B == d): {}",
        if hash_prefix_valid {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        }
    );

    // 1c. Verify Function Logic (Off-chain simulation)
    // The actual script execution is not simulated here anymore. We just check the condition.
    let logic_f1_valid = input_value > F1_THRESHOLD;
    println!(
        "  Function Logic Check (F1: x > {}): {}",
        F1_THRESHOLD,
        if logic_f1_valid {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        }
    );

    let f1_step_success = signature_f1_valid && hash_prefix_valid && logic_f1_valid;
    println!(
        "  Step 1 Overall: {}",
        if f1_step_success {
            "SUCCESS"
        } else {
            "FAILURE"
        }
    );

    // --- Simulate Step 2 (F2) Execution ---
    println!("\nSimulating Execution Step 2 (F2)...");
    let step_f2 = &presigned_flow.steps[1];

    // 2a. Verify Signature (Signer 0) (Off-chain simulation)
    let signature_f2 = step_f2
        .signatures
        .get(&signer0_pubkey.to_bytes())
        .ok_or("Signature from signer 0 not found for step 2")?;
    let signature_f2_valid = secp
        .verify_schnorr(signature_f2, &step_f2.sighash_message, signer0_xonly)
        .is_ok();
    println!(
        "  Signature Check (Signer 0): {}",
        if signature_f2_valid {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        }
    );

    // 2b. Verify Hash Prefix (remains the same check) (Off-chain simulation)
    println!(
        "  Hash Prefix Check (H(x,r)|B == d): {}",
        if hash_prefix_valid {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        }
    ); // Re-use previous check result

    // 2c. Verify Function Logic (F2) (Off-chain simulation)
    let logic_f2_valid = input_value < F2_THRESHOLD;
    println!(
        "  Function Logic Check (F2: x < {}): {}",
        F2_THRESHOLD,
        if logic_f2_valid {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        }
    );

    let f2_step_success = signature_f2_valid && hash_prefix_valid && logic_f2_valid;
    println!(
        "  Step 2 Overall: {}",
        if f2_step_success {
            "SUCCESS"
        } else {
            "FAILURE"
        }
    );

    // Determine overall simulation success
    let overall_success = f1_step_success && f2_step_success;
    println!("\n--- Execution Complete ---");

    // Create and return the simulation result
    let result_message = if overall_success {
        format!(
            "Successfully verified input {} satisfies all conditions (Sig, Hash Prefix, F1, F2) using flow {}",
            input_value, flow_id
        )
    } else {
        format!(
            "Input {} failed conditions for flow {}. F1 Step Success: {}, F2 Step Success: {}",
            input_value, flow_id, f1_step_success, f2_step_success
        )
    };

    Ok(SimulationResult {
        success: overall_success,
        _f1_result: f1_step_success,
        _f2_result: f2_step_success,
        message: result_message,
    })
}

/// Orchestrates the complete ColliderVM simulation (unchanged)
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
