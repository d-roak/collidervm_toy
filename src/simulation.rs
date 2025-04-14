use std::{collections::HashMap, error::Error};

use bitcoin::{
    Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    blockdata::script::{Builder, ScriptBuf},
    script::PushBytesBuf,
};
use bitvm::execute_script_buf;
use secp256k1::{self, Keypair, Secp256k1};

use crate::collidervm_toy::{
    ColliderVmConfig, OperatorInfo, PresignedFlow, PresignedStep, SignerInfo,
    build_script_f1_locked, build_script_f2_locked, calculate_flow_id, create_toy_sighash_message,
    find_valid_nonce,
};

// --- Simulation Structures ---
pub struct SimulationResult {
    pub success: bool,
    pub _f1_result: bool,
    pub _f2_result: bool,
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
        let script_f1 = build_script_f1_locked(&signers[0].pubkey, flow_id, config.b);
        let tx_f1_template = create_placeholder_tx(
            script_f1.clone(),
            funding_amount,
            funding_txid,
            funding_vout,
        );
        let sighash_msg_f1 = create_toy_sighash_message(&script_f1, tx_f1_template.output[0].value);
        let mut signatures_f1 = HashMap::new();
        for signer in &signers {
            let signature = secp.sign_schnorr(&sighash_msg_f1, &signer.keypair);
            signatures_f1.insert(signer.pubkey.to_bytes(), signature);
        }
        steps.push(PresignedStep {
            _tx_template: tx_f1_template.clone(),
            sighash_message: sighash_msg_f1,
            signatures: signatures_f1,
            locking_script: script_f1,
        });

        // --- Presign Step 2 (F2) ---
        let script_f2 = build_script_f2_locked(&signers[0].pubkey, flow_id, config.b);
        let tx_f2_template = create_placeholder_tx(
            script_f2.clone(),
            funding_amount,
            tx_f1_template.compute_txid(),
            0,
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
            locking_script: script_f2,
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
/// Finds nonce, selects flow, executes the full presigned locking scripts.
pub fn online_execution(
    signers: &[SignerInfo],
    _operators: &[OperatorInfo],
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

    // --- Off-chain checks (for logging/comparison only) ---
    let secp = Secp256k1::verification_only();
    let signer0_pubkey = &signers[0].pubkey;
    let signer0_xonly = &signers[0].xonly;

    // Off-chain Sig check F1
    let step_f1 = &presigned_flow.steps[0];
    let signature_f1 = step_f1
        .signatures
        .get(&signer0_pubkey.to_bytes())
        .ok_or("Signature from signer 0 not found for step 1")?;
    let offchain_sig_f1_valid = secp
        .verify_schnorr(signature_f1, &step_f1.sighash_message, signer0_xonly)
        .is_ok();

    // Off-chain Sig check F2
    let step_f2 = &presigned_flow.steps[1];
    let signature_f2 = step_f2
        .signatures
        .get(&signer0_pubkey.to_bytes())
        .ok_or("Signature from signer 0 not found for step 2")?;
    let offchain_sig_f2_valid = secp
        .verify_schnorr(signature_f2, &step_f2.sighash_message, signer0_xonly)
        .is_ok();

    // Off-chain Hash prefix check
    let offchain_hash_prefix_valid =
        calculate_flow_id(input_value, nonce, config.b, config.l) == Ok(flow_id);
    println!("\n--- Off-Chain Check Results (Informational) ---");
    println!(
        "  Signature F1 Valid (off-chain): {}",
        offchain_sig_f1_valid
    );
    println!(
        "  Signature F2 Valid (off-chain): {}",
        offchain_sig_f2_valid
    );
    println!(
        "  Hash Prefix Valid (off-chain): {}",
        offchain_hash_prefix_valid
    );
    println!("---------------------------------------------");

    // --- Execute Full Script Step 1 (F1) ---
    println!("\nExecuting Full Script Step 1 (F1 - Flow {})...", flow_id);
    // Build the witness script part: <signature> <hash_prefix> <input_x>
    let witness_script_f1 = {
        let mut builder = Builder::new();
        let sig_bytes = PushBytesBuf::try_from(signature_f1.as_ref().to_vec())
            .expect("Cannot convert signature to bytes");
        builder = builder.push_slice(sig_bytes);
        builder = builder.push_int(flow_id as i64); // Push hash_prefix (flow_id)
        builder = builder.push_int(input_value as i64); // Push input_x
        builder.into_script()
    };

    // Concatenate witness script bytes and locking script bytes
    let mut full_script_bytes_f1 = witness_script_f1.to_bytes();
    full_script_bytes_f1.extend(step_f1.locking_script.to_bytes());

    // Create the final executable script from combined bytes
    let full_script_f1 = ScriptBuf::from_bytes(full_script_bytes_f1);

    println!("Full Script F1: {}", full_script_f1);

    let exec_result_f1 = execute_script_buf(full_script_f1.clone());
    let script_f1_success = exec_result_f1.success;
    println!(
        "  => Full Script F1 Execution Result: {} (Result: {:?})",
        if script_f1_success {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        },
        exec_result_f1
    );
    if !script_f1_success {
        println!(
            "     (Note: Failure might be due to OP_CHECKSIGVERIFY with toy signature/sighash)"
        );
    }

    // --- Execute Full Script Step 2 (F2) ---
    println!("\nExecuting Full Script Step 2 (F2 - Flow {})...", flow_id);
    // Build the witness script part: <signature> <hash_prefix> <input_x>
    let witness_script_f2 = {
        let mut builder = Builder::new();
        let sig_bytes =
            PushBytesBuf::try_from(signature_f2.as_ref().to_vec()).expect("Signature is too long");
        builder = builder.push_slice(sig_bytes);
        builder = builder.push_int(flow_id as i64);
        builder = builder.push_int(input_value as i64);
        builder.into_script()
    };

    // Concatenate witness script bytes and locking script bytes
    let mut full_script_bytes_f2 = witness_script_f2.to_bytes();
    full_script_bytes_f2.extend(step_f2.locking_script.to_bytes());

    // Create the final executable script from combined bytes
    let full_script_f2 = ScriptBuf::from_bytes(full_script_bytes_f2);

    println!("Full Script F2: {}", full_script_f2);

    let exec_result_f2 = execute_script_buf(full_script_f2.clone());
    let script_f2_success = exec_result_f2.success;
    println!(
        "  => Full Script F2 Execution Result: {} (Result: {:?})",
        if script_f2_success {
            "PASSED ✅"
        } else {
            "FAILED ❌"
        },
        exec_result_f2
    );
    if !script_f2_success {
        println!(
            "     (Note: Failure might be due to OP_CHECKSIGVERIFY with toy signature/sighash)"
        );
    }

    // Determine overall simulation success based *only* on the full script executions
    let overall_success = script_f1_success && script_f2_success;
    println!("\n--- Execution Complete ---");

    // Create and return the simulation result
    let result_message = if overall_success {
        format!(
            "Successfully executed full F1 & F2 scripts for input {} using flow {}.",
            input_value, flow_id
        )
    } else {
        format!(
            "Execution of full scripts failed for input {} using flow {}. F1 Script Success: {}, F2 Script Success: {}",
            input_value, flow_id, script_f1_success, script_f2_success
        )
    };

    Ok(SimulationResult {
        success: overall_success,
        _f1_result: script_f1_success, // Store full script execution results
        _f2_result: script_f2_success,
        message: result_message,
    })
}

/// Orchestrates the complete ColliderVM simulation
pub fn run_simulation(
    config: ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    // Step 1: Offline Setup
    let (signers, operators, presigned_flows) = offline_setup(&config)?;

    // Step 2: Online Execution
    // Pass signers and operators even if not used in this simplified execution
    let result = online_execution(&signers, &operators, &presigned_flows, &config, input_value)?;

    // Step 3: Report Results
    println!("\n--- Simulation Summary ---");
    println!("{}", result.message);

    Ok(result)
}
