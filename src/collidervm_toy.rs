use bitcoin::{
    Amount, PublicKey, Transaction, XOnlyPublicKey,
    blockdata::script::{Builder, ScriptBuf},
    opcodes::{self, OP_TRUE, all},
    script::PushBytesBuf,
};
use bitcoin_hashes::{HashEngine, sha256};
use bitcoin_script_stack::optimizer;
use bitvm::hash::blake3::{blake3_compute_script_with_limb, blake3_push_message_script_with_limb};
use blake3::Hasher;
use indicatif::{ProgressBar, ProgressStyle};
use secp256k1::{Keypair, Message, SecretKey, schnorr::Signature};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// F1 threshold: x must be > 100
pub const F1_THRESHOLD: u32 = 100;
/// F2 threshold: x must be < 200
pub const F2_THRESHOLD: u32 = 200;

/// ColliderVM parameters
#[derive(Debug, Clone)]
pub struct ColliderVmConfig {
    pub n: usize,
    pub m: usize,
    pub l: usize,
    pub b: usize, // must be <= 32
    pub k: usize,
}

/// Info for one Signer
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SignerInfo {
    pub id: usize,
    pub pubkey: PublicKey,
    pub keypair: Keypair,
    pub xonly: XOnlyPublicKey,
    pub privkey: SecretKey,
}

/// Info for one Operator
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OperatorInfo {
    pub id: usize,
    pub pubkey: PublicKey,
    pub privkey: SecretKey,
}

/// A single step in the protocol
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PresignedStep {
    pub tx_template: Transaction,
    pub sighash_message: Message,
    pub signatures: HashMap<Vec<u8>, Signature>,
    pub locking_script: ScriptBuf,
}

/// A flow for a specific flow_id
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PresignedFlow {
    pub flow_id: u32,
    pub steps: Vec<PresignedStep>,
}

/// Create a minimal sighash for demonstration
pub fn create_toy_sighash_message(locking_script: &ScriptBuf, value: Amount) -> Message {
    let mut engine = sha256::HashEngine::default();
    engine.input(&locking_script.to_bytes());
    engine.input(&value.to_sat().to_le_bytes());
    let digest = sha256::Hash::from_engine(engine);
    Message::from_digest(digest.to_byte_array())
}

/// Calculate H(x||nonce)|_B => flow_id
pub fn calculate_flow_id(
    input: u32,
    nonce: u64,
    b_bits: usize,
    l_bits: usize,
) -> Result<u32, String> {
    let mut hasher = Hasher::new();
    hasher.update(&input.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    let hash = hasher.finalize();

    let mut fourb = [0u8; 4];
    fourb.copy_from_slice(&hash.as_bytes()[0..4]);
    let hash_u32 = u32::from_le_bytes(fourb);

    let mask_b = if b_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << b_bits) - 1
    };
    let prefix_b = hash_u32 & mask_b;

    let max_flow_id = (1u64 << l_bits) as u32;
    if prefix_b < max_flow_id {
        Ok(prefix_b)
    } else {
        Err(format!(
            "Hash prefix {} (from H={}) >= {} (out of range)",
            prefix_b, hash, max_flow_id
        ))
    }
}

/// Offchain search for a valid nonce
pub fn find_valid_nonce(input: u32, b_bits: usize, l_bits: usize) -> Result<(u64, u32), String> {
    let expected_attempts = 1u64
        .checked_shl((b_bits.saturating_sub(l_bits)) as u32)
        .unwrap_or(u64::MAX);

    println!(
        "find_valid_nonce => expected ~2^{} = {} tries",
        b_bits.saturating_sub(l_bits),
        expected_attempts
    );

    let start = Instant::now();
    let mut nonce = 0u64;
    loop {
        match calculate_flow_id(input, nonce, b_bits, l_bits) {
            Ok(flow_id) => {
                let dt = start.elapsed().as_secs_f64();
                let rate = if dt > 0.0 { nonce as f64 / dt } else { 0.0 };
                println!(
                    "Found flow_id={} at nonce={}, ~{:.2} H/s",
                    flow_id, nonce, rate
                );
                return Ok((nonce, flow_id));
            }
            Err(_) => {
                nonce = nonce.checked_add(1).ok_or("nonce overflow!")?;
                if nonce > expected_attempts.saturating_mul(100) {
                    return Err("Could not find valid flow_id within 100x expected".to_owned());
                }
            }
        }
    }
}

/// Convert flow_id => little-endian prefix of length B/8
pub fn flow_id_to_prefix_bytes(flow_id: u32, b_bits: usize) -> Vec<u8> {
    assert!(b_bits <= 32);
    assert_eq!(b_bits % 8, 0, "b_bits must be multiple of 8");
    let prefix_len = b_bits / 8;
    let le4 = flow_id.to_le_bytes();
    le4[..prefix_len].to_vec()
}

/// Helper: combine scripts (by just concatenating the raw bytes).
fn combine_scripts(fragments: &[ScriptBuf]) -> ScriptBuf {
    let mut combined = Vec::new();
    for frag in fragments {
        combined.extend(frag.to_bytes());
    }
    ScriptBuf::from_bytes(combined)
}

/// A small helper script that pushes `prefix_data` and does OP_EQUALVERIFY
fn build_prefix_equalverify(prefix_data: &[u8]) -> ScriptBuf {
    let mut b = Builder::new();
    // Check if the prefix_data represents a small integer (0-16)
    if prefix_data.len() == 1 {
        let val = prefix_data[0] as i64;
        if val == 0 {
            b = b.push_opcode(opcodes::OP_0); // OP_0 is special
        } else if val >= 1 && val <= 16 {
            // Use push_int for 1-16 to ensure minimal push (OP_1 to OP_16)
            b = b.push_int(val);
        } else {
            // Use standard push for other single-byte values (-1, or 17+)
            let prefix_push =
                PushBytesBuf::try_from(prefix_data.to_vec()).expect("prefix too large for push");
            b = b.push_slice(prefix_push);
        }
    } else {
        // For multi-byte prefixes, always use standard push
        let prefix_push =
            PushBytesBuf::try_from(prefix_data.to_vec()).expect("prefix too large for push");
        b = b.push_slice(prefix_push);
    }

    b.push_opcode(opcodes::all::OP_EQUALVERIFY).into_script()
}

/// Build an F1 script with onchain BLAKE3, checking x>F1_THRESHOLD and the top (b_bits/8) bytes match flow_id_prefix.
pub fn build_script_f1_blake3_locked(
    signer_pubkey: &PublicKey,
    flow_id_prefix: &[u8],
    _b_bits: usize,
) -> ScriptBuf {
    let prefix_len = flow_id_prefix.len();
    let total_msg_len = 12; // x_4b + r_4b0 + r_4b1
    let limb_len = 4;

    // 1) Script to check signature
    let sig_check = {
        let mut b = Builder::new();
        b = b.push_key(signer_pubkey);
        b.push_opcode(opcodes::all::OP_CHECKSIGVERIFY).into_script()
    };

    // 2) Bring x_num to top, check x_num > 100
    let x_greater_check = Builder::new()
        .push_opcode(opcodes::all::OP_DUP)
        .push_int(F1_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_GREATERTHAN)
        .push_opcode(opcodes::all::OP_VERIFY)
        .into_script();

    // 3) Drop x_num and reorder for BLAKE3
    let reorder_for_blake = Builder::new()
        .push_opcode(opcodes::all::OP_DROP)
        .into_script();

    // 4) BLAKE3 compute snippet - OPTIMIZED
    let push_compiled = blake3_push_message_script_with_limb(&[], limb_len).compile();
    let push_script = ScriptBuf::from_bytes(push_compiled.to_bytes());

    let compute_compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
    let compute_optimized = optimizer::optimize(compute_compiled);
    let compute_script = ScriptBuf::from_bytes(compute_optimized.to_bytes());

    // 5) drop limbs we don't need for prefix check
    let needed_limbs = (prefix_len + 3) / 4; // how many 4-byte limbs for prefix
    let to_drop = 8usize.saturating_sub(needed_limbs);
    let drop_script = {
        let mut b = Builder::new();
        for _ in 0..to_drop {
            b = b.push_opcode(opcodes::all::OP_DROP);
        }
        b.into_script()
    };

    // 6) compare prefix => OP_EQUALVERIFY
    let prefix_script = build_prefix_equalverify(flow_id_prefix);

    // 7) push OP_TRUE
    let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

    // Combine the locking script parts
    let f1_locking_script = combine_scripts(&[
        sig_check,
        x_greater_check,
        reorder_for_blake,
        push_script,
        compute_script,
        drop_script,
        prefix_script,
        success_script,
    ]);

    f1_locking_script
}

/// Build an F2 script with onchain BLAKE3, checking x<F2_THRESHOLD and prefix
pub fn build_script_f2_blake3_locked(
    signer_pubkey: &PublicKey,
    flow_id_prefix: &[u8],
    _b_bits: usize,
) -> ScriptBuf {
    let prefix_len = flow_id_prefix.len();
    let total_msg_len = 12;
    let limb_len = 4;

    // 1) signature
    let sig_check = Builder::new()
        .push_key(signer_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .into_script();

    // 2) Bring x_num to top, check x_num < 200
    let x_less_check = Builder::new()
        .push_opcode(opcodes::all::OP_DUP)
        .push_int(F2_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_LESSTHAN)
        .push_opcode(opcodes::all::OP_VERIFY)
        .into_script();

    // 3) Drop x_num and reorder for BLAKE3
    let reorder_for_blake = Builder::new()
        .push_opcode(opcodes::all::OP_DROP)
        .into_script();

    let push_script = {
        let compiled = blake3_push_message_script_with_limb(&[], limb_len).compile();
        ScriptBuf::from_bytes(compiled.to_bytes())
    };
    let compute_script = {
        let compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
        // Important: Optimize the compute script
        let optimized = optimizer::optimize(compiled);
        ScriptBuf::from_bytes(optimized.to_bytes())
    };

    let needed_limbs = (prefix_len + 3) / 4;
    let to_drop = 8usize.saturating_sub(needed_limbs);
    let drop_script = {
        let mut b = Builder::new();
        for _ in 0..to_drop {
            b = b.push_opcode(opcodes::all::OP_DROP);
        }
        b.into_script()
    };

    let prefix_script = build_prefix_equalverify(flow_id_prefix);
    let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

    combine_scripts(&[
        sig_check,
        x_less_check,
        reorder_for_blake,
        push_script,
        compute_script,
        drop_script,
        prefix_script,
        success_script,
    ])
}

/// A basic "hash rate" calibration
pub fn benchmark_hash_rate(duration_secs: u64) -> u64 {
    println!("Calibrating for {} seconds...", duration_secs);
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner} [{elapsed_precise}] [{bar:40.green/black}] {percent}% {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    let start = Instant::now();
    let end = start + Duration::from_secs(duration_secs);

    let mut count = 0u64;
    let mut nonce = 0u64;
    let input = 123u32;

    while Instant::now() < end {
        let mut hasher = Hasher::new();
        hasher.update(&input.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.finalize();
        nonce += 1;
        count += 1;
    }

    let dt = start.elapsed().as_secs_f64();
    let rate = if dt > 0.0 { count as f64 / dt } else { 0.0 };
    pb.finish_with_message(format!("~{:.2} H/s", rate));
    rate as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::opcodes::all::{OP_ADD, OP_DROP, OP_EQUALVERIFY, OP_GREATERTHAN};
    use bitcoin_script::script;
    // use bitcoin_script_stack::{evaluate::EvalResult, optimize, script_executor::ExecOptions};
    use bitvm::{execute_script_buf, hash::blake3::blake3_verify_output_script};
    use secp256k1::Secp256k1;

    #[test]
    fn test_blake3_script_generation() {
        let message = [0u8; 32];
        let limb_len = 4;
        let expected_hash = *blake3::hash(message.as_ref()).as_bytes();

        println!("Expected hash: {}", hex::encode(expected_hash));

        // Test push message script generation (requires message argument)
        let push_bytes = blake3_push_message_script_with_limb(&message, limb_len)
            .compile()
            .to_bytes();

        // Test compute script generation
        let optimized_compute =
            optimizer::optimize(blake3_compute_script_with_limb(message.len(), limb_len).compile());

        // Test verify output script generation
        let verify_bytes = blake3_verify_output_script(expected_hash)
            .compile()
            .to_bytes();

        // Combine scripts for execution (assuming message is pushed first)
        let mut combined_script_bytes = push_bytes;
        combined_script_bytes.extend(optimized_compute.to_bytes());
        combined_script_bytes.extend(verify_bytes);

        let script = ScriptBuf::from_bytes(combined_script_bytes);

        let result = execute_script_buf(script);

        println!("Result: {:?}", result);
        assert!(result.success, "Blake3 script execution failed");

        // Create an invalid hash by copying the expected hash and modifying one byte
        let mut invalid_hash = expected_hash.clone();
        invalid_hash[0] ^= 0x01; // Change one byte to create an invalid hash

        // Test push message script generation (requires message argument)
        let push_bytes = blake3_push_message_script_with_limb(&message, limb_len)
            .compile()
            .to_bytes();

        // Test compute script generation
        let optimized_compute =
            optimizer::optimize(blake3_compute_script_with_limb(message.len(), limb_len).compile());

        // Test verify output script generation
        let verify_bytes = blake3_verify_output_script(invalid_hash)
            .compile()
            .to_bytes();

        // Combine scripts for execution (assuming message is pushed first)
        let mut combined_script_bytes = push_bytes;
        combined_script_bytes.extend(optimized_compute.to_bytes());
        combined_script_bytes.extend(verify_bytes);

        let script = ScriptBuf::from_bytes(combined_script_bytes);

        let result = execute_script_buf(script);

        println!("Result: {:?}", result);
        assert!(!result.success, "Blake3 script execution failed");
    }

    #[test]
    fn test_prefix_flow() {
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let signer_keypair = Keypair::from_secret_key(&secp, &sk);

        let signer_pubkey = PublicKey::new(pk);

        // ColliderVM parameters
        let b = 32;
        let l = 4;
        let input_value = 123u32;
        let (nonce, flow_id) = find_valid_nonce(input_value, b, l).unwrap();

        let flow_id_prefix: Vec<u8> = flow_id_to_prefix_bytes(flow_id, b);
        println!("flow_id: {}", flow_id);
        println!(
            "flow_id_prefix bytes: {}",
            hex::encode(flow_id_prefix.clone())
        );
        println!("nonce: {}", nonce);

        // Create a dummy transaction signature
        let sighash_f1 = create_dummy_sighash_message(&flow_id_prefix.clone());
        let sig_f1 = secp.sign_schnorr(&sighash_f1, &signer_keypair);

        let prefix_len = flow_id_prefix.len();
        let total_msg_len = 12; // x_4b + r_4b0 + r_4b1
        let limb_len = 4;

        // 1) Script to check signature
        let sig_check = {
            let mut b = Builder::new();
            b = b.push_key(&signer_pubkey);
            b.push_opcode(opcodes::all::OP_CHECKSIGVERIFY).into_script()
        };

        // 2) Bring x_num to top, check x_num > 100
        let x_greater_check = Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_int(F1_THRESHOLD as i64)
            .push_opcode(opcodes::all::OP_GREATERTHAN)
            .push_opcode(opcodes::all::OP_VERIFY)
            .into_script();

        // 3) Drop x_num and reorder for BLAKE3
        let reorder_for_blake = Builder::new()
            .push_opcode(opcodes::all::OP_DROP)
            .into_script();

        // 4) BLAKE3 compute snippet - OPTIMIZED
        let push_compiled = blake3_push_message_script_with_limb(&[], limb_len).compile();
        let push_script = ScriptBuf::from_bytes(push_compiled.to_bytes());

        let compute_compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
        let compute_optimized = optimizer::optimize(compute_compiled);
        let compute_script = ScriptBuf::from_bytes(compute_optimized.to_bytes());

        // 5) drop limbs we don't need for prefix check
        let needed_limbs = (prefix_len + 3) / 4; // how many 4-byte limbs for prefix
        let to_drop = 8usize.saturating_sub(needed_limbs);
        let drop_script = {
            let mut b = Builder::new();
            for _ in 0..to_drop {
                b = b.push_opcode(opcodes::all::OP_DROP);
            }
            b.into_script()
        };

        // 6) compare prefix => OP_EQUALVERIFY
        let prefix_script = build_prefix_equalverify(&flow_id_prefix);

        // 7) push OP_TRUE
        let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

        // Combine the locking script parts
        let f1_locking_script = combine_scripts(&[
            sig_check,
            //x_greater_check,
            //reorder_for_blake,
            //push_script,
            //compute_script,
            //drop_script,
            //prefix_script,
            script! {OP_DROP OP_DROP OP_DROP OP_DROP}.compile(),
            success_script,
        ]);

        // Construct the witness

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
        let x_le_4_buf_f1 =
            PushBytesBuf::try_from(x_le_4.to_vec()).expect("x_le_4 conversion failed");

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

        let mut full_f1 = witness_f1.to_bytes();
        full_f1.extend(f1_locking_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);

        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        //println!("F1 => log={:?}", f1_res);
    }

    pub fn create_dummy_sighash_message(seed_bytes: &[u8]) -> Message {
        let mut engine = sha256::HashEngine::default();
        engine.input(seed_bytes);
        let digest = sha256::Hash::from_engine(engine);
        Message::from_digest(digest.to_byte_array())
    }
}
