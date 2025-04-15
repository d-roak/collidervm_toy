use colored::*;
use std::{collections::HashMap, error::Error, thread, time::Duration}; // Import colored crate

use bitcoin::{
    Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    blockdata::script::{Builder, ScriptBuf},
    script::PushBytesBuf,
};
use bitvm::execute_script_buf;
use secp256k1::{Keypair, Secp256k1};

use crate::collidervm_toy::{
    ColliderVmConfig, OperatorInfo, PresignedFlow, PresignedStep, SignerInfo,
    build_script_f1_locked, build_script_f2_locked, calculate_flow_id, create_toy_sighash_message,
    find_valid_nonce,
};

/// Stores the results of a ColliderVM simulation run.
#[allow(dead_code)] // Fields might be unused depending on success
pub struct SimulationResult {
    /// Indicates whether the overall simulation (both F1 and F2 script executions) succeeded.
    pub success: bool,
    /// Result of the F1 full script execution.
    pub f1_result: bool,
    /// Result of the F2 full script execution.
    pub f2_result: bool,
    /// A summary message describing the outcome of the simulation.
    pub message: String,
}

/// A type alias for the results of the offline setup phase.
/// Contains the generated signer and operator information, and the map of presigned flows.
type SetupResult = (
    Vec<SignerInfo>,
    Vec<OperatorInfo>,
    HashMap<u32, PresignedFlow>,
);

/// Creates a placeholder Bitcoin transaction.
///
/// This is used during the offline setup phase to generate the transaction structures
/// for which sighashes and signatures will be created. It doesn't represent a final,
/// spendable transaction but rather a template.
///
/// # Arguments
/// * `locking_script` - The `scriptPubKey` for the output of this transaction.
/// * `value` - The value (`Amount`) for the output.
/// * `input_txid` - The `Txid` of the transaction output being spent by this transaction's input.
/// * `input_vout` - The vout (output index) of the transaction output being spent.
///
/// # Returns
/// A `Transaction` object representing the placeholder.
fn create_placeholder_tx(
    locking_script: ScriptBuf,
    value: Amount,
    input_txid: Txid,
    input_vout: u32,
) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO, // Standard version
        lock_time: bitcoin::absolute::LockTime::ZERO, // No lock time
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_txid,
                vout: input_vout,
            },
            script_sig: ScriptBuf::new(), // Empty for SegWit/Taproot signing
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, // Standard sequence
            witness: Witness::new(),      // Empty witness for template creation
        }],
        output: vec![TxOut {
            value,                         // The amount for the output
            script_pubkey: locking_script, // The script locking the output
        }],
    }
}

/// Simulates the offline setup phase of the ColliderVM protocol.
///
/// This phase involves:
/// 1. Generating keypairs for `n` Signers and `m` Operators.
/// 2. For each potential flow ID `d` in the set `D` (up to a limit for this toy simulation):
///    a. Creating placeholder transaction templates for F1 and F2.
///    b. Generating the (simplified) sighash messages for each template.
///    c. Collecting Schnorr signatures from all `n` signers for each step (F1, F2).
///    d. Storing the templates, sighashes, signatures, and locking scripts in `PresignedFlow` structs.
///
/// Refer to Section 2.1 and Figure 2 of the ColliderVM paper.
///
/// # Arguments
/// * `config` - The `ColliderVmConfig` specifying parameters like n, m, L, B, k.
/// * `auto` - Whether to run in auto mode (skipping sleeps and prompts).
///
/// # Returns
/// * `Ok(SetupResult)` - A tuple containing the generated signers, operators, and the map of presigned flows.
/// * `Err(Box<dyn Error>)` - An error if setup fails (e.g., key generation).
pub fn offline_setup(config: &ColliderVmConfig, auto: bool) -> Result<SetupResult, Box<dyn Error>> {
    if !auto {
        println!("\n{}", "---  PHASE 1: Offline Setup --- ".bold().yellow());
        println!(
            "{}",
            "(Signers generate keys and presign all transaction flows)".dimmed()
        );
        thread::sleep(Duration::from_millis(500)); // Small pause
    }

    if !auto {
        println!(
            "\nGenerating {} signers and {} operators...",
            config.n.to_string().cyan(),
            config.m.to_string().cyan()
        );
        thread::sleep(Duration::from_millis(200));
    }

    // Initialize Secp256k1 context for key operations
    let secp = Secp256k1::new();
    let mut signers = Vec::with_capacity(config.n);
    let mut operators = Vec::with_capacity(config.m);

    // 1. Generate Signer Info
    if !auto {
        println!("Generating Signer keys...");
    }
    for i in 0..config.n {
        let (privkey, secp_pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &privkey);
        let (xonly, _parity) = keypair.x_only_public_key(); // Parity needed if using MuSig etc.
        let signer = SignerInfo {
            id: i,
            pubkey: PublicKey::new(secp_pubkey),
            privkey, // Store private key for simulation
            keypair,
            xonly,
        };
        if !auto {
            println!(
                "  {} {}: {}",
                "Generated Signer".dimmed(),
                i,
                signer.pubkey.to_string().green()
            );
        }
        signers.push(signer);
        if !auto {
            thread::sleep(Duration::from_millis(50)); // Tiny pause per key
        }
    }

    // 1. Generate Operator Info
    if !auto {
        println!("\nGenerating Operator keys...");
    }
    for i in 0..config.m {
        let (privkey, secp_pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let operator = OperatorInfo {
            id: i,
            pubkey: PublicKey::new(secp_pubkey),
            privkey, // Store private key for simulation
        };
        if !auto {
            println!(
                "  {} {}: {}",
                "Generated Operator".dimmed(),
                i,
                operator.pubkey.to_string().blue()
            );
        }
        operators.push(operator);
        if !auto {
            thread::sleep(Duration::from_millis(50)); // Tiny pause per key
        }
    }

    if !auto {
        println!(
            "\n{} {} flows (Transaction Templates + Signatures)...",
            "Generating".yellow(),
            (1u64 << config.l).to_string().cyan()
        );
        thread::sleep(Duration::from_millis(300));
    }
    // Calculate the number of flows (|D| = 2^L), limited for the toy example.
    let num_flows = std::cmp::min(1u64 << config.l, 16u64) as u32;
    if !auto {
        println!(
            "  {}",
            format!(
                "(Targeting {} flows for this demo, L={}, max 16)",
                num_flows, config.l
            )
            .dimmed()
        );
    }
    let mut presigned_flows_map: HashMap<u32, PresignedFlow> = HashMap::new();

    // Define a dummy funding transaction output (needed for F1's input)
    const DUMMY_TXID_STR: &str = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
    let funding_txid = DUMMY_TXID_STR
        .parse::<Txid>()
        .expect("Failed to parse dummy TXID");
    let funding_vout = 0;
    let funding_amount = Amount::from_sat(10000); // Example funding amount

    // 2. Generate Presigned Flows for each potential flow ID `d`
    for flow_id in 0..num_flows {
        let mut steps = Vec::with_capacity(config.k); // k=2 for F1, F2

        // --- Presign Step F1 ---
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
            tx_template: tx_f1_template.clone(),
            sighash_message: sighash_msg_f1,
            signatures: signatures_f1,
            locking_script: script_f1,
        });

        // --- Presign Step F2 ---
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
            tx_template: tx_f2_template,
            sighash_message: sighash_msg_f2,
            signatures: signatures_f2,
            locking_script: script_f2,
        });

        presigned_flows_map.insert(flow_id, PresignedFlow { flow_id, steps });

        // Progress indicator
        if flow_id % (num_flows / 4).max(1) == (num_flows / 4).max(1) - 1
            || flow_id == num_flows - 1
        {
            if !auto {
                println!(
                    "  {} flow d={}...",
                    "Created and presigned".dimmed(),
                    flow_id
                );
            }
            if !auto {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if !auto {
        println!(
            "\n{} {} flows presigned by {} signers.",
            "Offline setup complete.".bold().green(),
            presigned_flows_map.len().to_string().cyan(),
            config.n.to_string().cyan()
        );
        println!(
            "{}",
            "-----------------------------------------------------".yellow()
        );
    }
    Ok((signers, operators, presigned_flows_map))
}

/// Simulates the online execution phase of the ColliderVM protocol.
///
/// This phase involves:
/// 1. An Operator, given an input `x`, finds a nonce `r` such that `H(x, r)|_B = d` for some `d` in the set `D`.
/// 2. The Operator retrieves the `PresignedFlow` corresponding to the found `flow_id` (`d`).
/// 3. The Operator constructs the full scripts (witness + locking script) for F1 and F2.
/// 4. The Operator (or in this simulation, the `bitvm` executor) executes these full scripts.
/// 5. The overall success depends on the successful execution of both F1 and F2 scripts.
///
/// Refer to Section 2.1 and Figure 2 of the ColliderVM paper.
///
/// The expected witness stack is: `<signature> <flow_id> <input_x>` (integers)
///
/// # Arguments
/// * `signers` - Slice of `SignerInfo` generated during setup.
/// * `_operators` - Slice of `OperatorInfo` (unused in this simplified online phase simulation).
/// * `presigned_flows_map` - The map of `PresignedFlow`s generated during setup.
/// * `config` - The `ColliderVmConfig`.
/// * `input_value` - The input `x` for the computation.
/// * `auto` - Whether to run in auto mode (skipping sleeps and prompts).
///
/// # Returns
/// * `Ok(SimulationResult)` - The result of the online execution simulation.
/// * `Err(Box<dyn Error>)` - An error if execution fails (e.g., nonce not found, flow missing).
pub fn online_execution(
    signers: &[SignerInfo],
    _operators: &[OperatorInfo], // Currently unused in this simulation logic
    presigned_flows_map: &HashMap<u32, PresignedFlow>,
    config: &ColliderVmConfig,
    input_value: u32,
    auto: bool,
) -> Result<SimulationResult, Box<dyn Error>> {
    if !auto {
        println!("\n{}", "--- PHASE 2: Online Execution --- ".bold().yellow());
        println!(
            "{}",
            "(Operator finds nonce, selects flow, executes scripts)".dimmed()
        );
        thread::sleep(Duration::from_millis(500));
    }

    if !auto {
        println!("\nConfiguration:");
        println!(
            "  L={}, B={}, k={}, n={}, m={}",
            config.l.to_string().cyan(),
            config.b.to_string().cyan(),
            config.k.to_string().cyan(),
            config.n.to_string().cyan(),
            config.m.to_string().cyan()
        );
        println!("Input value (x): {}", input_value.to_string().cyan());
        thread::sleep(Duration::from_millis(300));
    }

    // 1. Operator finds a valid nonce `r` and corresponding flow ID `d`
    if !auto {
        println!(
            "\n{}: Finding Nonce (r) and Flow ID (d) for input x={}...",
            "Operator Action".bold().blue(),
            input_value
        );
    }
    let (nonce, flow_id) = match find_valid_nonce(input_value, config.b, config.l) {
        Ok(result) => result,
        Err(e) => {
            return Err(format!("Failed to find a valid nonce: {}", e).into());
        }
    };
    if !auto {
        println!(
            "  {} Nonce (r): {}, Required Flow ID (d): {}",
            "Found!".bold().green(),
            nonce.to_string().cyan(),
            flow_id.to_string().cyan()
        );
        if !auto {
            thread::sleep(Duration::from_millis(300));
        }
    }

    // 2. Retrieve the PresignedFlow for the calculated flow ID `d`
    if !auto {
        println!(
            "\n{}: Retrieving presigned flow d={}...",
            "Operator Action".bold().blue(),
            flow_id
        );
    }
    let presigned_flow = presigned_flows_map.get(&flow_id).ok_or_else(|| {
        format!(
            "Critical Error: Presigned flow d={} not found after nonce search!",
            flow_id
        )
    })?;
    if !auto {
        println!(
            "  {} Retrieved presigned flow d={}",
            "Success:".green(),
            flow_id
        );
        if !auto {
            thread::sleep(Duration::from_millis(300));
        }
    }

    // --- Perform Off-Chain Checks (Informational Only) ---
    if !auto {
        println!(
            "\n{}",
            "--- Off-Chain Check Results (Informational) ---".dimmed()
        );
    }
    let secp = Secp256k1::verification_only();
    let signer0_pubkey = &signers[0].pubkey;
    let signer0_xonly = &signers[0].xonly;
    let step_f1 = &presigned_flow.steps[0];
    let signature_f1 = step_f1.signatures.get(&signer0_pubkey.to_bytes()).unwrap(); // Assume exists
    let offchain_sig_f1_valid = secp
        .verify_schnorr(signature_f1, &step_f1.sighash_message, signer0_xonly)
        .is_ok();
    let step_f2 = &presigned_flow.steps[1];
    let signature_f2 = step_f2.signatures.get(&signer0_pubkey.to_bytes()).unwrap(); // Assume exists
    let offchain_sig_f2_valid = secp
        .verify_schnorr(signature_f2, &step_f2.sighash_message, signer0_xonly)
        .is_ok();
    let offchain_hash_prefix_valid =
        calculate_flow_id(input_value, nonce, config.b, config.l) == Ok(flow_id);
    if !auto {
        println!(
            "  {} F1 Signature Valid (Signer 0): {}",
            "Check:".dimmed(),
            offchain_sig_f1_valid
                .to_string()
                .color(if offchain_sig_f1_valid {
                    Color::Green
                } else {
                    Color::Red
                })
        );
        println!(
            "  {} F2 Signature Valid (Signer 0): {}",
            "Check:".dimmed(),
            offchain_sig_f2_valid
                .to_string()
                .color(if offchain_sig_f2_valid {
                    Color::Green
                } else {
                    Color::Red
                })
        );
        println!(
            "  {} Hash Prefix Valid (H(x,r)|_B == d): {}",
            "Check:".dimmed(),
            offchain_hash_prefix_valid
                .to_string()
                .color(if offchain_hash_prefix_valid {
                    Color::Green
                } else {
                    Color::Red
                })
        );
        println!(
            "{}",
            "---------------------------------------------".dimmed()
        );
    }
    if !auto {
        thread::sleep(Duration::from_millis(500));
    }

    // --- Construct and Execute Full Script for Step F1 ---
    if !auto {
        println!(
            "\n{}: Executing Full Script Step F1 (Flow d={})...",
            "Operator Action".bold().blue(),
            flow_id
        );
        thread::sleep(Duration::from_millis(300));
    }

    let witness_script_f1 = {
        let mut builder = Builder::new();
        let sig_bytes =
            PushBytesBuf::try_from(signature_f1.as_ref().to_vec()).expect("Sig too long");
        builder = builder.push_slice(sig_bytes);
        builder = builder.push_int(flow_id as i64);
        builder = builder.push_int(input_value as i64);
        builder.into_script()
    };
    let mut full_script_bytes_f1 = witness_script_f1.to_bytes();
    full_script_bytes_f1.extend(step_f1.locking_script.to_bytes());
    let full_script_f1 = ScriptBuf::from_bytes(full_script_bytes_f1);
    if !auto {
        println!(
            "  {} Full Script F1: {}",
            "Info:".dimmed(),
            full_script_f1.to_asm_string().italic()
        );
    }

    let exec_result_f1 = execute_script_buf(full_script_f1.clone());
    let script_f1_success = exec_result_f1.success;
    if !auto {
        println!(
            "    => {}: {} (Log: {:?})",
            "Execution Result".bold(),
            if script_f1_success {
                "PASSED ✅".bold().green()
            } else {
                "FAILED ❌".bold().red()
            },
            exec_result_f1
        );
        if !script_f1_success {
            println!(
                "       {}",
                "(Toy Note: Failure might be due to OP_CHECKSIGVERIFY)".dimmed()
            );
        }
    }
    if !auto {
        thread::sleep(Duration::from_millis(500));
    }

    // --- Construct and Execute Full Script for Step F2 ---
    if !auto {
        println!(
            "\n{}: Executing Full Script Step F2 (Flow d={})...",
            "Operator Action".bold().blue(),
            flow_id
        );
        thread::sleep(Duration::from_millis(300));
    }

    let witness_script_f2 = {
        let mut builder = Builder::new();
        let sig_bytes =
            PushBytesBuf::try_from(signature_f2.as_ref().to_vec()).expect("Sig too long");
        builder = builder.push_slice(sig_bytes);
        builder = builder.push_int(flow_id as i64);
        builder = builder.push_int(input_value as i64);
        builder.into_script()
    };
    let mut full_script_bytes_f2 = witness_script_f2.to_bytes();
    full_script_bytes_f2.extend(step_f2.locking_script.to_bytes());
    let full_script_f2 = ScriptBuf::from_bytes(full_script_bytes_f2);
    if !auto {
        println!(
            "  {} Full Script F2: {}",
            "Info:".dimmed(),
            full_script_f2.to_asm_string().italic()
        );
    }

    let exec_result_f2 = execute_script_buf(full_script_f2.clone());
    let script_f2_success = exec_result_f2.success;
    if !auto {
        println!(
            "    => {}: {} (Log: {:?})",
            "Execution Result".bold(),
            if script_f2_success {
                "PASSED ✅".bold().green()
            } else {
                "FAILED ❌".bold().red()
            },
            exec_result_f2
        );
        if !script_f2_success {
            println!(
                "       {}",
                "(Toy Note: Failure might be due to OP_CHECKSIGVERIFY)".dimmed()
            );
        }
    }
    if !auto {
        thread::sleep(Duration::from_millis(500));
    }

    // Determine Overall Simulation Success
    let overall_success = script_f1_success && script_f2_success;
    if !auto {
        println!("\n{}", "--- Online Execution Complete ---".yellow());
    }

    // Create the final simulation result message
    let result_message = if overall_success {
        format!(
            "Successfully executed simplified F1 & F2 scripts for input x={} using flow d={}. (Hash check was simplified)",
            input_value, flow_id
        )
    } else {
        format!(
            "Execution failed for input x={} using flow d={}. F1 Script Success: {}, F2 Script Success: {} (Hash check was simplified)",
            input_value, flow_id, script_f1_success, script_f2_success
        )
    };

    Ok(SimulationResult {
        success: overall_success,
        f1_result: script_f1_success,
        f2_result: script_f2_success,
        message: result_message,
    })
}

/// Orchestrates the complete ColliderVM simulation: offline setup followed by online execution.
///
/// # Arguments
/// * `config` - The `ColliderVmConfig` parameters for the simulation.
/// * `input_value` - The input `x` to be used in the online phase.
/// * `auto` - Whether to run in auto mode (skipping sleeps and prompts).
///
/// # Returns
/// * `Ok(SimulationResult)` - The final result of the simulation.
/// * `Err(Box<dyn Error>)` - An error if either the setup or execution phase fails.
pub fn run_simulation(
    config: ColliderVmConfig,
    input_value: u32,
    auto: bool,
) -> Result<SimulationResult, Box<dyn Error>> {
    // --- Phase 1: Offline Setup ---
    let (signers, operators, presigned_flows) = offline_setup(&config, auto)?;

    // --- Phase 2: Online Execution ---
    let result = online_execution(
        &signers,
        &operators,
        &presigned_flows,
        &config,
        input_value,
        auto,
    )?;

    // --- Phase 3: Report Summary (in main.rs) ---
    // println!("\n--- Simulation Summary ---"); // Moved to main.rs
    // println!("{}", result.message);

    Ok(result)
}
