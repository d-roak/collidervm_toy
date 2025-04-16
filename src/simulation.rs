// src/simulation.rs

use colored::*;
use std::{collections::HashMap, error::Error, thread, time::Duration};

use bitcoin::{
    Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    blockdata::script::{Builder, ScriptBuf},
    script::PushBytesBuf,
};
use bitvm::execute_script_buf;
use secp256k1::{Keypair, Secp256k1};

use crate::collidervm_toy::{
    ColliderVmConfig, F1_THRESHOLD, F2_THRESHOLD, OperatorInfo, PresignedFlow, PresignedStep,
    SignerInfo, build_script_f1_blake3_locked, build_script_f2_blake3_locked,
    create_toy_sighash_message, find_valid_nonce, flow_id_to_prefix_bytes,
};

/// Stores the results of a ColliderVM simulation run.
#[allow(dead_code)]
pub struct SimulationResult {
    /// Did the entire simulation succeed (F1 & F2 both pass)?
    pub success: bool,
    /// F1 script outcome
    pub f1_result: bool,
    /// F2 script outcome
    pub f2_result: bool,
    /// Summary message
    pub message: String,
}

/// Type alias: the output of offline_setup => (signers, operators, map_of_flows)
type SetupResult = (
    Vec<SignerInfo>,
    Vec<OperatorInfo>,
    HashMap<u32, PresignedFlow>,
);

/// Creates a placeholder transaction for demonstration.
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
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: locking_script,
        }],
    }
}

/// Offline Setup: generate signers, operators, presigned flows, etc.
pub fn offline_setup(config: &ColliderVmConfig) -> Result<SetupResult, Box<dyn Error>> {
    println!("\n{}", "--- Phase 1: Offline Setup ---".bold().yellow());
    println!("{}", "(Signers generate keys and presign flows)".dimmed());
    thread::sleep(Duration::from_millis(500));

    println!(
        "Generating {} signers and {} operators...",
        config.n, config.m
    );
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

    let mut signers = Vec::with_capacity(config.n);
    let mut operators = Vec::with_capacity(config.m);

    // Generate signers
    for i in 0..config.n {
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        let si = SignerInfo {
            id: i,
            pubkey: PublicKey::new(pk),
            privkey: sk,
            keypair,
            xonly,
        };
        println!("  Signer{} => pubkey={}", i, si.pubkey);
        signers.push(si);
    }

    // Generate operators
    for j in 0..config.m {
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let op = OperatorInfo {
            id: j,
            pubkey: PublicKey::new(pk),
            privkey: sk,
        };
        println!("  Operator{} => pubkey={}", j, op.pubkey);
        operators.push(op);
    }

    // We'll create up to 2^L flows, but cap at 16 in this toy.
    let num_flows = std::cmp::min(1u64 << config.l, 16) as u32;
    println!(
        "\nCreating presigned flows for up to {} (2^{}) possible flow IDs (capped at 16).",
        num_flows, config.l
    );

    let mut flows_map = HashMap::new();

    // A dummy funding TXID
    let funding_txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        .parse::<Txid>()
        .unwrap();
    let funding_vout = 0;
    let funding_amount = Amount::from_sat(10_000);

    // We'll have just one signer sign everything (signer[0]) for simplicity
    let signer0 = &signers[0];
    let secp_sign = Secp256k1::signing_only();

    for flow_id in 0..num_flows {
        // Convert the flow_id to a prefix
        // b_bits must be <= 32, so we'll just slice out that many bits in bytes
        let prefix_bytes: Vec<u8> = flow_id_to_prefix_bytes(flow_id, config.b);

        // Build the F1 script
        let f1_script = build_script_f1_blake3_locked(&signer0.pubkey, &prefix_bytes, config.b);
        // Tx template
        let tx_f1 = create_placeholder_tx(
            f1_script.clone(),
            funding_amount,
            funding_txid,
            funding_vout,
        );
        // Create sighash
        let sighash_f1 = create_toy_sighash_message(&f1_script, tx_f1.output[0].value);
        // sign
        let mut sigs_f1 = HashMap::new();
        let sig_f1 = secp_sign.sign_schnorr(&sighash_f1, &signer0.keypair);
        sigs_f1.insert(signer0.pubkey.to_bytes(), sig_f1);

        let step_f1 = PresignedStep {
            tx_template: tx_f1.clone(),
            sighash_message: sighash_f1,
            signatures: sigs_f1,
            locking_script: f1_script,
        };

        // Build the F2 script
        let f2_script = build_script_f2_blake3_locked(&signer0.pubkey, &prefix_bytes, config.b);
        // Tx template F2 depends on TxF1
        let tx_f2 =
            create_placeholder_tx(f2_script.clone(), funding_amount, tx_f1.compute_txid(), 0);
        let sighash_f2 = create_toy_sighash_message(&f2_script, tx_f2.output[0].value);
        let mut sigs_f2 = HashMap::new();
        let sig_f2 = secp_sign.sign_schnorr(&sighash_f2, &signer0.keypair);
        sigs_f2.insert(signer0.pubkey.to_bytes(), sig_f2);

        let step_f2 = PresignedStep {
            tx_template: tx_f2,
            sighash_message: sighash_f2,
            signatures: sigs_f2,
            locking_script: f2_script,
        };

        flows_map.insert(
            flow_id,
            PresignedFlow {
                flow_id,
                steps: vec![step_f1, step_f2],
            },
        );
    }

    println!("Offline setup complete. Created {} flows.", flows_map.len());
    Ok((signers, operators, flows_map))
}

/// Online execution: Operator picks x, finds nonce, picks flow, builds script/witness, runs it.
pub fn online_execution(
    signers: &[SignerInfo],
    _operators: &[OperatorInfo],
    flows_map: &HashMap<u32, PresignedFlow>,
    config: &ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    println!("\n{}", "--- Phase 2: Online Execution ---".bold().yellow());
    println!("Input x={}", input_value);

    // 1) find a valid nonce => flow_id
    let (nonce, _hash, flow_id) = find_valid_nonce(input_value, config.b, config.l)?;
    println!("Found nonce={} => flow_id={}", nonce, flow_id);

    // retrieve that presigned flow
    let flow = flows_map
        .get(&flow_id)
        .ok_or_else(|| format!("No presigned flow for flow_id={}", flow_id))?;

    // We'll do a basic off-chain check of the signature from Signer0
    let secp_verify = Secp256k1::verification_only();
    let signer0 = &signers[0];

    let step_f1 = &flow.steps[0];
    let sig_f1 = step_f1
        .signatures
        .get(&signer0.pubkey.to_bytes())
        .ok_or_else(|| "Signer0 sig missing for F1")?;
    let step_f2 = &flow.steps[1];
    let sig_f2 = step_f2
        .signatures
        .get(&signer0.pubkey.to_bytes())
        .ok_or_else(|| "Signer0 sig missing for F2")?;

    let sig_ok_f1 = secp_verify
        .verify_schnorr(sig_f1, &step_f1.sighash_message, &signer0.xonly)
        .is_ok();
    let sig_ok_f2 = secp_verify
        .verify_schnorr(sig_f2, &step_f2.sighash_message, &signer0.xonly)
        .is_ok();

    println!(
        "Offchain check => F1 sig valid: {}, F2 sig valid: {}",
        sig_ok_f1, sig_ok_f2
    );

    // 2) Let's run the scripts with the actual witness.
    // Our script expects: [ signature, x_num, r_4b1, r_4b0, x_4b ]
    //   x_4b is the raw 4-bytes of input_value
    //   r_4b0, r_4b1 => the 8 bytes of the nonce in 4-byte lumps
    let x_le_4 = input_value.to_le_bytes();
    let r_le_8 = nonce.to_le_bytes();
    let r_4b0 = &r_le_8[0..4];
    let r_4b1 = &r_le_8[4..8];

    // Print debugging info about the data
    println!("Debug: r_4b0 = {:?}", r_4b0);
    println!("Debug: r_4b1 = {:?}", r_4b1);
    println!("Debug: x_le_4 = {:?}", x_le_4);

    // Create PushBytesBuf for all raw bytes for F1
    let sig_f1_buf =
        PushBytesBuf::try_from(sig_f1.as_ref().to_vec()).expect("sig_f1 conversion failed");
    let r_4b1_buf_f1 = PushBytesBuf::try_from(r_4b1.to_vec()).expect("r_4b1 conversion failed");
    let r_4b0_buf_f1 = PushBytesBuf::try_from(r_4b0.to_vec()).expect("r_4b0 conversion failed");
    let x_le_4_buf_f1 = PushBytesBuf::try_from(x_le_4.to_vec()).expect("x_le_4 conversion failed");

    // -- Step F1 script
    let witness_f1 = {
        let mut b = Builder::new();
        b = b.push_slice(sig_f1_buf); // Signature
        b = b.push_slice(r_4b1_buf_f1); // Nonce part 1
        b = b.push_slice(r_4b0_buf_f1); // Nonce part 0
        b = b.push_slice(x_le_4_buf_f1); // x as 4 bytes (for hashing)
        b = b.push_int(input_value as i64); // x as number (minimal, for comparison)
        b.into_script()
    };

    // Debug the witness script
    println!("Debug - F1 witness: {}", witness_f1);

    // Debug the locking script
    println!("Debug - F1 locking: {}", step_f1.locking_script);

    let mut full_f1 = witness_f1.to_bytes();
    full_f1.extend(step_f1.locking_script.to_bytes());
    let exec_f1_script = ScriptBuf::from_bytes(full_f1);

    // Debug the full script
    println!("Debug - F1 full script: {}", exec_f1_script);

    let f1_res = execute_script_buf(exec_f1_script);
    println!("F1 => success={}  log={:?}", f1_res.success, f1_res);

    // Create PushBytesBuf for F2 values - new instances
    let sig_f2_buf =
        PushBytesBuf::try_from(sig_f2.as_ref().to_vec()).expect("sig_f2 conversion failed");
    let r_4b1_buf_f2 =
        PushBytesBuf::try_from(r_4b1.to_vec()).expect("r_4b1 conversion failed for F2");
    let r_4b0_buf_f2 =
        PushBytesBuf::try_from(r_4b0.to_vec()).expect("r_4b0 conversion failed for F2");
    let x_le_4_buf_f2 =
        PushBytesBuf::try_from(x_le_4.to_vec()).expect("x_le_4 conversion failed for F2");

    // -- Step F2 script
    let witness_f2 = {
        let mut b = Builder::new();
        b = b.push_slice(sig_f2_buf); // Signature
        b = b.push_slice(r_4b1_buf_f2); // Nonce part 1
        b = b.push_slice(r_4b0_buf_f2); // Nonce part 0
        b = b.push_slice(x_le_4_buf_f2); // x as 4 bytes (for hashing)
        b = b.push_int(input_value as i64); // x as number (minimal, for comparison)
        b.into_script()
    };
    let mut full_f2 = witness_f2.to_bytes();
    full_f2.extend(step_f2.locking_script.to_bytes());
    let exec_f2_script = ScriptBuf::from_bytes(full_f2);

    let f2_res = execute_script_buf(exec_f2_script);
    println!("F2 => success={}  log={:?}", f2_res.success, f2_res);

    let overall = f1_res.success && f2_res.success;
    let msg = if overall {
        format!(
            "Success: Both F1(x>{}) and F2(x<{}) checks + BLAKE3 prefix match (flow_id={})",
            F1_THRESHOLD, F2_THRESHOLD, flow_id
        )
    } else {
        format!(
            "FAIL: F1={}, F2={} for x={} flow_id={}",
            f1_res.success, f2_res.success, input_value, flow_id
        )
    };

    Ok(SimulationResult {
        success: overall,
        f1_result: f1_res.success,
        f2_result: f2_res.success,
        message: msg,
    })
}

/// Orchestrates both offline setup + online execution.
pub fn run_simulation(
    config: ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    let (signers, operators, flows_map) = offline_setup(&config)?;
    let res = online_execution(&signers, &operators, &flows_map, &config, input_value)?;
    Ok(res)
}
