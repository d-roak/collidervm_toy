use bitcoin::{
    Amount, PublicKey, Transaction, XOnlyPublicKey,
    blockdata::script::{Builder, ScriptBuf},
    opcodes::{self, OP_TRUE},
};
use bitcoin_hashes::{HashEngine, sha256};
use bitcoin_script_stack::optimizer;
use bitvm::hash::blake3::blake3_compute_script_with_limb;
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
) -> Result<(u32, [u8; 32]), String> {
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
        Ok((prefix_b, hash.as_bytes()[0..32].try_into().unwrap()))
    } else {
        Err(format!(
            "Hash prefix {prefix_b} (from H={hash}) >= {max_flow_id} (out of range)"
        ))
    }
}

/// Finds a valid nonce `r` for a given input `x` such that `H(x, r)|_B` falls within the set `D`. (Off-chain logic)
///
/// This simulates the work performed by an Operator during the online phase.
/// The expected number of hash attempts is `2^(B-L)`.
///
/// # Arguments
/// * `input` - The input value `x`.
/// * `b_bits` - The hash prefix length `B`.
/// * `l_bits` - The parameter `L` defining the size of set `D`.
///
/// # Returns
/// * `Ok((u64, u32))` - A tuple containing the found nonce `r` and the corresponding flow ID `d`.
/// * `Err(String)` - An error if a nonce cannot be found (e.g., due to overflow or excessive attempts).
pub fn find_valid_nonce(
    input: u32,
    b_bits: usize,
    l_bits: usize,
) -> Result<(u64, u32, [u8; 32]), String> {
    let mut nonce: u64 = 0;

    // Calculate expected number of attempts (2^(B-L)) for progress reporting
    let expected_attempts: u64 = 1u64
        .checked_shl((b_bits.saturating_sub(l_bits)) as u32) // Calculate 2^(B-L)
        .unwrap_or(u64::MAX);

    println!(
        "Finding valid nonce (L={}, B={})... (Expected work: ~2^{} = {} hashes)",
        l_bits,
        b_bits,
        b_bits.saturating_sub(l_bits),
        expected_attempts
    );

    // Create a progress bar with expected attempts
    let progress_bar = if expected_attempts > 100 {
        let pb = ProgressBar::new(expected_attempts);

        // More attractive and informative template
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:50.cyan/blue}] {pos}/{len} ({percent}%) [{per_sec}] {msg}")
                .unwrap()
                .progress_chars("■□·")
        );

        pb.set_message("Finding nonce for valid flow...");
        pb.enable_steady_tick(Duration::from_millis(100)); // Update the spinner every 100ms to show activity
        Some(pb)
    } else {
        None
    };

    // Variables for hash rate calculation
    let start_time = Instant::now();
    let report_interval = 50_000; // Update progress every 50K hashes
    let mut last_update = 0;
    let mut hash_rates = Vec::with_capacity(10); // Store last 10 hash rates for averaging

    loop {
        // Check if the current nonce yields a valid flow ID
        match calculate_flow_id(input, nonce, b_bits, l_bits) {
            Ok((flow_id, hash)) => {
                // Found a nonce `r` such that H(x, r)|_B = d ∈ D
                if let Some(pb) = &progress_bar {
                    pb.finish_with_message(format!(
                        "Found flow_id {} after {} hashes!",
                        flow_id,
                        nonce + 1
                    ));
                } else {
                    println!(
                        "  Found valid nonce {} -> flow_id {} after {} hashes.",
                        nonce,
                        flow_id,
                        nonce + 1 // nonce starts at 0
                    );
                }

                // Calculate and display the final hash rate
                let elapsed = start_time.elapsed();
                let hash_rate = if elapsed.as_secs() > 0 {
                    nonce as f64 / elapsed.as_secs_f64()
                } else {
                    nonce as f64 // avoid division by zero
                };

                println!("  Average hash rate: {hash_rate:.2} hashes/sec");

                return Ok((nonce, flow_id, hash));
            }
            Err(_) => {
                // Hash prefix was outside the valid range [0, 2^L - 1], try next nonce
                if nonce > last_update + report_interval {
                    // Calculate current hash rate
                    let elapsed = start_time.elapsed();
                    let hash_rate = if elapsed.as_secs() > 0 {
                        nonce as f64 / elapsed.as_secs_f64()
                    } else {
                        nonce as f64 // avoid division by zero
                    };

                    // Keep track of hash rates for averaging
                    hash_rates.push(hash_rate);
                    if hash_rates.len() > 10 {
                        hash_rates.remove(0);
                    }
                    let avg_hash_rate: f64 =
                        hash_rates.iter().sum::<f64>() / hash_rates.len() as f64;

                    // Update progress bar with current rate and ETA
                    if let Some(pb) = &progress_bar {
                        pb.set_position(nonce);

                        // More detailed progress message
                        let eta_secs = if nonce >= expected_attempts {
                            0.0
                        } else {
                            (expected_attempts - nonce) as f64 / avg_hash_rate
                        };

                        let eta_str = if eta_secs < 60.0 {
                            format!("{eta_secs:.1}s")
                        } else if eta_secs < 3600.0 {
                            format!("{:.1}m {:.0}s", eta_secs / 60.0, eta_secs % 60.0)
                        } else {
                            format!(
                                "{:.1}h {:.0}m",
                                eta_secs / 3600.0,
                                (eta_secs % 3600.0) / 60.0
                            )
                        };

                        pb.set_message(format!(
                            "ETA: {} @ {:.2} KH/s, {:.1}% done",
                            eta_str,
                            avg_hash_rate / 1000.0,
                            (nonce as f64 / expected_attempts as f64) * 100.0
                        ));
                    } else {
                        println!("  Tried {nonce} hashes... ({avg_hash_rate:.2} hash/s)");
                    }

                    last_update = nonce;
                }

                // Update progress bar more frequently (without recalculating hash rate)
                if let Some(pb) = &progress_bar {
                    // Update the progress bar more frequently for high workloads
                    let update_frequency = if expected_attempts > 1_000_000 {
                        5_000 // Every 5K hashes for large workloads
                    } else if expected_attempts > 100_000 {
                        1_000 // Every 1K hashes for medium workloads
                    } else {
                        100 // Every 100 hashes for small workloads
                    };

                    if nonce % update_frequency == 0 {
                        pb.set_position(nonce);
                    }
                }

                // Increment nonce, checking for overflow
                nonce = nonce
                    .checked_add(1)
                    .ok_or_else(|| "Nonce overflowed u64::MAX while searching".to_string())?;

                // Safety break after excessive attempts (e.g., 100x expected work)
                // This prevents infinite loops in case of configuration errors.
                if nonce > expected_attempts.saturating_mul(100) {
                    if let Some(pb) = &progress_bar {
                        pb.finish_with_message("Exceeded maximum attempts");
                    }
                    return Err(format!(
                        "Could not find a valid nonce after {nonce} attempts (expected ~{expected_attempts})"
                    ));
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
    let flow_id_prefix_bytes = le4[..prefix_len].to_vec();
    // Transform to nibbles
    // For example: [0x12, 0x34] => [0x1, 0x2, 0x3, 0x4]
    // Or: [0x0d, 0x00] => [0x0, 0xd, 0x0, 0x0]
    let mut nibbles = Vec::with_capacity(flow_id_prefix_bytes.len() * 2);
    for &byte in &flow_id_prefix_bytes {
        // Extract high nibble (first 4 bits)
        nibbles.push((byte >> 4) & 0x0F);
        // Extract low nibble (last 4 bits)
        nibbles.push(byte & 0x0F);
    }
    nibbles
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
/// This is used to check if the top of the stack matches the prefix
/// For example, if the content of the stack is:
/// [0x00, 0x0d, 0x00, 0x00]
/// Then the script needs to check equality of each byte.
/// We need to take care of the fact that the prefix is now in nibbles.
/// Also the ordering of elements on the stack.
/// We need to push the prefix in reverse order to the stack.
fn build_prefix_equalverify(prefix_data: &[u8]) -> ScriptBuf {
    let mut b = Builder::new();

    // Check each nibble individually, pushing in reverse order to match stack evaluation
    for &nibble in prefix_data.iter().rev() {
        // For the nibble value, use push_int for accurate stack comparison
        b = b.push_int(nibble as i64);
        b = b.push_opcode(opcodes::all::OP_EQUALVERIFY);
    }

    b.into_script()
}

/// Build an F1 script with onchain BLAKE3, checking x>F1_THRESHOLD and the top (b_bits/8) bytes match flow_id_prefix.
/// For now we cheat and use the provided input and nonce to construct the message for the BLAKE3 hash.
/// TODO: Reconstruct the message from the witness elements.
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
    // TODO: Reconstruct the message from the witness elements.
    let compute_compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
    let compute_optimized = optimizer::optimize(compute_compiled);
    let compute_script = ScriptBuf::from_bytes(compute_optimized.to_bytes());

    // 5) drop limbs we don't need for prefix check
    // Needed nibbles: prefix_len (because now represented as nibbles) or B / 4
    let needed_nibbles = prefix_len;
    let blake3_script_hash_len_nibbles = 64;
    let to_drop = blake3_script_hash_len_nibbles - needed_nibbles;
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
    combine_scripts(&[
        sig_check,
        x_greater_check,
        reorder_for_blake,
        compute_script,
        drop_script,
        prefix_script,
        success_script,
    ])
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

    // 4) BLAKE3 compute snippet - OPTIMIZED
    let compute_script = {
        let compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
        // Important: Optimize the compute script
        let optimized = optimizer::optimize(compiled);
        ScriptBuf::from_bytes(optimized.to_bytes())
    };

    // Needed nibbles: prefix_len (because now represented as nibbles) or B / 4
    let needed_nibbles = prefix_len;
    let blake3_script_hash_len_nibbles = 64;
    let to_drop = blake3_script_hash_len_nibbles - needed_nibbles;
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
        compute_script,
        drop_script,
        prefix_script,
        success_script,
    ])
}

/// A basic "hash rate" calibration
pub fn benchmark_hash_rate(duration_secs: u64) -> u64 {
    println!("Calibrating for {duration_secs} seconds...");
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
    pb.finish_with_message(format!("~{rate:.2} H/s"));
    rate as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::script::PushBytesBuf;
    use bitcoin_script::script;
    use bitvm::{
        execute_script_buf,
        hash::blake3::{blake3_push_message_script_with_limb, blake3_verify_output_script},
    };
    use secp256k1::Secp256k1;

    // commented fields are never read
    pub struct ColliderVmTestCase {
        // pub b: usize,
        // pub l: usize,
        // pub input_value: u32,
        pub signer_pubkey: PublicKey,
        // pub signer_keypair: Keypair,
        pub flow_id_prefix: Vec<u8>,
        // pub sig_f1: Signature,
        // pub f1_script: ScriptBuf,
        // pub message: Vec<u8>,
        pub msg_push_script_f1: ScriptBuf,
        pub sig_script_f1: ScriptBuf,
    }

    pub fn create_test_case(b: usize, l: usize, input_value: u32) -> ColliderVmTestCase {
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let signer_keypair = Keypair::from_secret_key(&secp, &sk);
        let signer_pubkey = PublicKey::new(pk);

        let (nonce, flow_id, _hash) = find_valid_nonce(input_value, b, l).unwrap();
        let flow_id_prefix: Vec<u8> = flow_id_to_prefix_bytes(flow_id, b);

        let sighash_f1 = create_dummy_sighash_message(&flow_id_prefix.clone());
        let sig_f1 = secp.sign_schnorr(&sighash_f1, &signer_keypair);

        // let f1_script = build_script_f1_blake3_locked(&signer_pubkey, &flow_id_prefix, b);

        let message = [
            input_value.to_le_bytes(),
            nonce.to_le_bytes()[0..4].try_into().unwrap(),
            nonce.to_le_bytes()[4..8].try_into().unwrap(),
        ]
        .concat();
        let msg_push_script_f1 = blake3_push_message_script_with_limb(&message, 4).compile();

        // Create PushBytesBuf for all raw bytes for F1
        let sig_f1_buf =
            PushBytesBuf::try_from(sig_f1.as_ref().to_vec()).expect("sig_f1 conversion failed");

        let sig_script_f1 = {
            let mut b = Builder::new();
            b = b.push_slice(sig_f1_buf);
            b.into_script()
        };

        ColliderVmTestCase {
            // b,
            // l,
            // input_value,
            signer_pubkey,
            // signer_keypair,
            flow_id_prefix,
            // sig_f1,
            // f1_script,
            // message,
            msg_push_script_f1,
            sig_script_f1,
        }
    }

    #[test]
    fn test_f1_e2e() {
        let test_case = create_test_case(16, 4, 123);

        // ******************************************************
        // CONSTRUCT A DEBUGGING SCRIPT
        // ******************************************************

        let total_msg_len = 12;
        let limb_len = 4;

        // 0)  signature
        let sig_check = Builder::new()
            .push_key(&test_case.signer_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .into_script();

        // 1)  reconstruct x  (keeps message)
        let recon_x = script_reconstruct_x_from_first_8_nibbles();

        // 2)  x > 100 (non-destructive)
        Builder::new()
            .push_opcode(opcodes::all::OP_FROMALTSTACK)
            .push_opcode(opcodes::all::OP_DUP)
            .push_int(F1_THRESHOLD as i64)
            .push_opcode(opcodes::all::OP_GREATERTHAN)
            .push_opcode(opcodes::all::OP_VERIFY)
            .push_opcode(opcodes::all::OP_TOALTSTACK)
            .into_script();

        // 3)  BLAKE-3(message)
        {
            let compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
            let optim = optimizer::optimize(compiled);
            ScriptBuf::from_bytes(optim.to_bytes())
        };

        // 4)  drop the 64-needed-nibbles minus prefix_len
        let mut drop = Builder::new();
        for _ in 0..(64 - test_case.flow_id_prefix.len()) {
            drop = drop.push_opcode(opcodes::all::OP_DROP);
        }
        drop.into_script();

        // 5)  compare prefix & succeed
        build_prefix_equalverify(&test_case.flow_id_prefix);
        Builder::new().push_opcode(OP_TRUE).into_script();

        let debug_script = combine_scripts(&[
            sig_check,
            recon_x,
            Builder::new()
                .push_opcode(opcodes::all::OP_FROMALTSTACK)
                .into_script(),
            //compute,
            //x_test,
            //drop_excess,
            //prefix_cmp,
            //success,
        ]);

        // ******************************************************
        // EXECUTE THE DEBUGGING SCRIPT
        // ******************************************************
        let mut full_f1 = Vec::new();
        full_f1.extend(test_case.msg_push_script_f1.to_bytes());
        full_f1.extend(test_case.sig_script_f1.to_bytes());
        //full_f1.extend(test_case.f1_script.to_bytes());
        full_f1.extend(debug_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);

        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
    }

    /// duplicates (keeps) the first 8 nibbles, accumulates them into `x`,
    /// leaves `x` on the *altstack*, original 24 nibbles untouched.
    fn script_reconstruct_x_from_first_8_nibbles() -> ScriptBuf {
        const TOTAL_NIBBLES: i64 = 24; // 12 bytes ×2
        let mut b = Builder::new()
            .push_int(0) // acc = 0
            .push_opcode(opcodes::all::OP_TOALTSTACK);

        for i in 0..8 {
            let idx = TOTAL_NIBBLES - 1 - i; // 23,22,…,16
            b = b
                .push_int(idx) // depth index
                .push_opcode(opcodes::all::OP_PICK) // copy nib
                .push_opcode(opcodes::all::OP_FROMALTSTACK); // nib acc

            // acc *= 16
            for _ in 0..4 {
                b = b
                    .push_opcode(opcodes::all::OP_DUP)
                    .push_opcode(opcodes::all::OP_ADD);
            }
            // acc += nib
            b = b
                .push_opcode(opcodes::all::OP_SWAP) // acc nib  → nib acc
                .push_opcode(opcodes::all::OP_ADD) // consume nib copy
                .push_opcode(opcodes::all::OP_TOALTSTACK); // store new acc
        }
        // leave the finished x on altstack
        b.into_script()
    }

    #[test]
    fn test_f1_witness_script() {
        // Create an input value that will fill the 4 bytes
        let input_value = u32::from_be_bytes([0x12, 0x34, 0x56, 0x78]);
        let nonce = u64::from_be_bytes([0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x21, 0x43]);
        let limb_len: u8 = 4;

        let message = [
            input_value.to_le_bytes(),
            nonce.to_le_bytes()[0..4].try_into().unwrap(),
            nonce.to_le_bytes()[4..8].try_into().unwrap(),
        ]
        .concat();
        println!("input_value: {input_value}");
        println!("nonce: {nonce}");
        println!("message: {}", hex::encode(message.clone()));
        let msg_push_script_f1 = blake3_push_message_script_with_limb(&message, limb_len).compile();
        //println!("msg_push_script_f1: {}", msg_push_script_f1);

        let witness_script = ScriptBuf::from_bytes(msg_push_script_f1.to_bytes());
        let f1_res = execute_script_buf(witness_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
    }

    #[test]
    fn test_blake3_script_generation() {
        let message = [0u8; 32];
        let limb_len: u8 = 4;
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

        println!("Result: {result:?}");
        assert!(result.success, "Blake3 script execution failed");

        // Create an invalid hash by copying the expected hash and modifying one byte
        let mut invalid_hash = expected_hash;
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

        println!("Result: {result:?}");
        assert!(!result.success, "Blake3 script execution failed");
    }

    #[test]
    fn test_prefix_flow() {
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let signer_keypair = Keypair::from_secret_key(&secp, &sk);

        let signer_pubkey = PublicKey::new(pk);

        // ColliderVM parameters
        let b = 16;
        let l = 4;
        let input_value = 123u32;
        let (nonce, flow_id, _hash) = find_valid_nonce(input_value, b, l).unwrap();

        let flow_id_prefix: Vec<u8> = flow_id_to_prefix_bytes(flow_id, b);

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
        let compute_compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
        let compute_optimized = optimizer::optimize(compute_compiled);
        let compute_script = ScriptBuf::from_bytes(compute_optimized.to_bytes());

        // 5) drop limbs we don't need for prefix check
        // Needed nibbles: prefix_len (because now represented as nibbles) or B / 4
        let needed_nibbles = prefix_len;
        let blake3_script_hash_len_nibbles = 64;
        let to_drop = blake3_script_hash_len_nibbles - needed_nibbles;
        let drop_script = {
            let mut b = Builder::new();
            for _ in 0..to_drop {
                b = b.push_opcode(opcodes::all::OP_DROP);
            }
            b.into_script()
        };

        // 6) compare prefix => OP_EQUALVERIFY
        let prefix_script = build_prefix_equalverify(&flow_id_prefix);

        println!("prefix_script: {prefix_script}");

        // 7) push OP_TRUE
        let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

        // Combine the locking script parts
        let f1_locking_script = combine_scripts(&[
            sig_check,
            x_greater_check,
            reorder_for_blake,
            compute_script,
            drop_script,
            prefix_script,
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
        println!("r_4b0 = {}", hex::encode(r_4b0));
        println!("r_4b1 = {}", hex::encode(r_4b1));
        println!("x_le_4 = {}", hex::encode(x_le_4));

        // Create PushBytesBuf for all raw bytes for F1
        let sig_f1_buf =
            PushBytesBuf::try_from(sig_f1.as_ref().to_vec()).expect("sig_f1 conversion failed");
        let _r_4b1_buf_f1 =
            PushBytesBuf::try_from(r_4b1.to_vec()).expect("r_4b1 conversion failed");
        let _r_4b0_buf_f1 =
            PushBytesBuf::try_from(r_4b0.to_vec()).expect("r_4b0 conversion failed");
        let _x_le_4_buf_f1 =
            PushBytesBuf::try_from(x_le_4.to_vec()).expect("x_le_4 conversion failed");

        // -- Step F1 script
        let x_sig_script = {
            let mut b = Builder::new();
            b = b.push_int(input_value as i64);
            b = b.push_slice(sig_f1_buf);
            b.into_script()
        };

        let mut full_f1 = x_sig_script.to_bytes();
        full_f1.extend(f1_locking_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);

        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        //assert!(f1_res.success);
    }

    #[test]
    fn test_encoding() {
        let x_sig_script = {
            let mut b = Builder::new();
            b = b.push_int(0x00_i64);
            b = b.push_int(0x0d_i64);
            b = b.push_int(0x00_i64);
            b = b.push_int(0x00_i64);
            b.into_script()
        };
        println!("x_sig_script: {x_sig_script}");

        // flow id prefix: 000d0000
        let flow_id_prefix = vec![0x00, 0x0d, 0x00, 0x00];
        let script_part_1 = build_prefix_equalverify(&flow_id_prefix);

        let locking_script = combine_scripts(&[script_part_1, script! {OP_TRUE}.compile()]);

        let mut full_f1 = x_sig_script.to_bytes();
        full_f1.extend(locking_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);
        println!("exec_f1_script: {exec_f1_script}");

        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        assert!(f1_res.success);
    }

    #[test]
    fn test_blake3_input_from_witness() {
        let message = [
            0x7b, 0x00, 0x00, 0x00, 0xd9, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let msg_push_script = blake3_push_message_script_with_limb(&message, 4).compile();
        let push_script = ScriptBuf::from_bytes(msg_push_script.to_bytes());

        let total_msg_len = 12;
        let limb_len = 4;
        let compute_compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
        let compute_optimized = optimizer::optimize(compute_compiled);
        let compute_script = ScriptBuf::from_bytes(compute_optimized.to_bytes());

        let locking_script = combine_scripts(&[compute_script]);

        let witness = push_script;

        let mut full_f1 = witness.to_bytes();
        full_f1.extend(locking_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);
        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        //assert!(f1_res.success);
    }

    #[test]
    fn test_prefix_flow_input_from_witness() {
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let signer_keypair = Keypair::from_secret_key(&secp, &sk);

        let signer_pubkey = PublicKey::new(pk);

        // ColliderVM parameters
        let b = 16;
        let l = 4;
        let input_value = 123u32;
        let (nonce, flow_id, _hash) = find_valid_nonce(input_value, b, l).unwrap();

        let flow_id_prefix: Vec<u8> = flow_id_to_prefix_bytes(flow_id, b);

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
        let compute_compiled = blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
        let compute_optimized = optimizer::optimize(compute_compiled);
        let compute_script = ScriptBuf::from_bytes(compute_optimized.to_bytes());

        // 5) drop limbs we don't need for prefix check
        // Needed nibbles: prefix_len (because now represented as nibbles) or B / 4
        let needed_nibbles = prefix_len;
        let blake3_script_hash_len_nibbles = 64;
        let to_drop = blake3_script_hash_len_nibbles - needed_nibbles;
        let drop_script = {
            let mut b = Builder::new();
            for _ in 0..to_drop {
                b = b.push_opcode(opcodes::all::OP_DROP);
            }
            b.into_script()
        };

        // 6) compare prefix => OP_EQUALVERIFY
        let prefix_script = build_prefix_equalverify(&flow_id_prefix);

        println!("prefix_script: {prefix_script}");

        // 7) push OP_TRUE
        let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

        // Combine the locking script parts
        let f1_locking_script = combine_scripts(&[
            sig_check,
            x_greater_check,
            reorder_for_blake,
            compute_script,
            drop_script,
            prefix_script,
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
        println!("r_4b0 = {}", hex::encode(r_4b0));
        println!("r_4b1 = {}", hex::encode(r_4b1));
        println!("x_le_4 = {}", hex::encode(x_le_4));

        // Create PushBytesBuf for all raw bytes for F1
        let sig_f1_buf =
            PushBytesBuf::try_from(sig_f1.as_ref().to_vec()).expect("sig_f1 conversion failed");
        let _r_4b1_buf_f1 =
            PushBytesBuf::try_from(r_4b1.to_vec()).expect("r_4b1 conversion failed");
        let _r_4b0_buf_f1 =
            PushBytesBuf::try_from(r_4b0.to_vec()).expect("r_4b0 conversion failed");
        let _x_le_4_buf_f1 =
            PushBytesBuf::try_from(x_le_4.to_vec()).expect("x_le_4 conversion failed");

        let message = [
            0x7b, 0x00, 0x00, 0x00, 0xd9, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let msg_push_script = blake3_push_message_script_with_limb(&message, 4).compile();
        let push_script = ScriptBuf::from_bytes(msg_push_script.to_bytes());

        // -- Step F1 script
        let x_sig_script = {
            let mut b = Builder::new();
            b = b.push_int(input_value as i64);
            b = b.push_slice(sig_f1_buf);
            b.into_script()
        };

        let mut full_f1 = push_script.to_bytes();
        full_f1.extend(x_sig_script.to_bytes());
        full_f1.extend(f1_locking_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);

        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        //assert!(f1_res.success);
    }

    pub fn create_dummy_sighash_message(seed_bytes: &[u8]) -> Message {
        let mut engine = sha256::HashEngine::default();
        engine.input(seed_bytes);
        let digest = sha256::Hash::from_engine(engine);
        Message::from_digest(digest.to_byte_array())
    }
}
#[cfg(test)]
mod debug_reconstruct {
    use bitcoin::blockdata::script::{Builder, ScriptBuf};
    use bitcoin::opcodes;
    use bitvm::{execute_script_buf, hash::blake3::blake3_push_message_script_with_limb};

    //------------------------------------------------------------//
    // Constants & helpers
    //------------------------------------------------------------//
    const X_BE: u32 = 0x12_34_56_78;
    const NONCE: u64 = 0x56_78_9a_bc_de_f0_21_43;
    const LIMB: u8 = 4;

    fn message() -> Vec<u8> {
        [
            X_BE.to_le_bytes(),
            NONCE.to_le_bytes()[0..4].try_into().unwrap(),
            NONCE.to_le_bytes()[4..8].try_into().unwrap(),
        ]
        .concat()
    }

    fn witness_script() -> ScriptBuf {
        blake3_push_message_script_with_limb(&message(), LIMB).compile()
    }

    // ------------------------------------------------------------ //
    //  The test
    // ------------------------------------------------------------ //
    #[test]
    fn dbg_reconstruct_x_and_verify() {
        // 1) witness pushes every nibble of the 12‑byte message
        let witness = witness_script();

        // 2) locking script
        let mut b: Builder = Builder::new();

        // -- initialise accumulator
        b = b.push_int(0).push_opcode(opcodes::all::OP_TOALTSTACK);

        // -- eight rounds: build x from bottom up
        for _ in 0..8 {
            b = b
                .push_opcode(opcodes::all::OP_DEPTH)
                .push_opcode(opcodes::all::OP_1SUB)
                .push_opcode(opcodes::all::OP_ROLL) // nib
                .push_opcode(opcodes::all::OP_FROMALTSTACK); // nib acc

            // acc *= 16
            for _ in 0..4 {
                b = b
                    .push_opcode(opcodes::all::OP_DUP)
                    .push_opcode(opcodes::all::OP_ADD);
            }
            // acc += nib
            b = b
                .push_opcode(opcodes::all::OP_ADD)
                .push_opcode(opcodes::all::OP_TOALTSTACK);
        }

        // -- drop the 16 nonce nibbles
        for _ in 0..16 {
            b = b
                .push_opcode(opcodes::all::OP_DEPTH)
                .push_opcode(opcodes::all::OP_1SUB)
                .push_opcode(opcodes::all::OP_ROLL)
                .push_opcode(opcodes::all::OP_DROP);
        }

        // -- pull x back, run equality & range checks
        b = b
            .push_opcode(opcodes::all::OP_FROMALTSTACK) // x
            .push_opcode(opcodes::all::OP_DUP) // x x
            .push_int(X_BE as i64)
            .push_opcode(opcodes::all::OP_EQUALVERIFY) // x
            .push_int(100)
            .push_opcode(opcodes::all::OP_GREATERTHAN)
            .push_opcode(opcodes::all::OP_VERIFY); // (stack empty)

        // Cleanup loop:
        //   - always removes the depth word we just pushed
        //   - removes one real stack item *only* when DEPTH > 0
        //   - never leaves falsey `[]` leftovers.
        // 128 iterations are plenty – > than any stack we create.
        // TODO: investigate if we can have a more efficient way to do this
        for _ in 0..128 {
            // any upper bound ≥ max stack size
            b = b
                .push_opcode(opcodes::all::OP_DEPTH)
                .push_opcode(opcodes::all::OP_0NOTEQUAL) // depth != 0 ?
                .push_opcode(opcodes::all::OP_IF)
                .push_opcode(opcodes::all::OP_DROP) // drop depth word
                .push_opcode(opcodes::all::OP_DROP) // drop one payload item
                .push_opcode(opcodes::all::OP_ENDIF);
        }

        // -- push TRUE
        b = b.push_int(1);

        let locking: ScriptBuf = b.into_script();

        // 3) execute
        let full_script = {
            let mut bytes = witness.to_bytes();
            bytes.extend(locking.to_bytes());
            ScriptBuf::from_bytes(bytes)
        };

        let info = execute_script_buf(full_script);
        println!("\n===== dbg_reconstruct_x_and_verify =====");
        println!("{info:#?}");

        assert!(
            info.success,
            "Script failed – final stack: {:?}",
            info.final_stack
        );
    }
}
