use bitcoin::{
    Amount, PublicKey, Transaction, XOnlyPublicKey,
    blockdata::script::{Builder, ScriptBuf},
    opcodes,
};
use bitcoin_hashes::{HashEngine, sha256};
use blake3::Hasher;
use secp256k1::{Keypair, Message, SecretKey, schnorr::Signature};
use std::collections::HashMap;

/// Threshold value for the F1 subfunction logic check.
/// In this toy simulation, F1 succeeds if the input `x` is greater than this value.
const F1_THRESHOLD: u32 = 100;
/// Threshold value for the F2 subfunction logic check.
/// In this toy simulation, F2 succeeds if the input `x` is less than this value.
const F2_THRESHOLD: u32 = 200;

/// Configuration parameters for the ColliderVM simulation.
/// These parameters define the security assumptions and computational requirements.
#[derive(Debug, Clone)]
pub struct ColliderVmConfig {
    /// Number of signers (`n`). Security requires 1-of-n honest signers.
    pub n: usize,
    /// Number of operators (`m`). Liveness requires 1-of-m honest operators.
    pub m: usize,
    /// Logarithm base 2 of the size of the set `D` of valid flow IDs (`L`). |D| = 2^L.
    pub l: usize,
    /// Length of the hash prefix in bits (`B`) used in the collision challenge.
    pub b: usize,
    /// Number of sub-functions (`k`) the main function is split into. Fixed to 2 (F1, F2) for this toy simulation.
    pub k: usize,
}

/// Represents a Signer in the ColliderVM protocol.
/// Signers participate in the offline setup phase to create and sign transaction templates.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields might be unused in the toy version
pub struct SignerInfo {
    /// Unique identifier for the signer.
    pub id: usize,
    /// The signer's public key.
    pub pubkey: PublicKey,
    /// The signer's secp256k1 keypair (includes private key).
    pub keypair: Keypair,
    /// The signer's x-only public key, used for Schnorr signatures.
    pub xonly: XOnlyPublicKey,
    /// The signer's private key (kept for simulation purposes, should be deleted in a real scenario).
    pub privkey: SecretKey,
}

/// Represents an Operator in the ColliderVM protocol.
/// Operators participate in the online execution phase, providing inputs, finding nonces,
/// and broadcasting transactions.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields might be unused in the toy version
pub struct OperatorInfo {
    /// Unique identifier for the operator.
    pub id: usize,
    /// The operator's public key.
    pub pubkey: PublicKey,
    /// The operator's private key (kept for simulation purposes).
    pub privkey: SecretKey,
}

/// Represents a single step (e.g., F1 or F2 execution) within a presigned flow.
/// Contains the transaction template, sighash, signatures, and locking script for that step.
#[derive(Clone, Debug)]
#[allow(dead_code)] // Fields might be unused in the toy version
pub struct PresignedStep {
    /// The presigned Bitcoin transaction template for this step.
    pub tx_template: Transaction,
    /// The message hash that was signed by the signers (simplified in this toy simulation).
    pub sighash_message: Message,
    /// A map from signer public key (bytes) to their Schnorr signature for this step.
    pub signatures: HashMap<Vec<u8>, Signature>,
    /// The locking script (`scriptPubKey`) for the output created by this step's transaction.
    pub locking_script: ScriptBuf,
}

/// Represents a complete presigned flow for a specific flow ID (`d`).
/// A flow consists of a sequence of steps (transactions) designed to execute the sub-functions.
#[derive(Clone, Debug)]
#[allow(dead_code)] // Fields might be unused in the toy version
pub struct PresignedFlow {
    /// The unique identifier (`d`) for this flow, belonging to the set `D`.
    pub flow_id: u32,
    /// The sequence of presigned steps (e.g., [step_f1, step_f2]) constituting this flow.
    pub steps: Vec<PresignedStep>,
}

/// Creates a simplified message digest to be signed, representing the core commitment.
///
/// In a real Bitcoin transaction, the sighash message is constructed according to complex rules
/// (see BIP-341 for Taproot). This function provides a placeholder by hashing the locking script
/// and the output value, simulating the commitment to the transaction's essential parts.
///
/// # Arguments
/// * `locking_script` - The scriptPubKey of the output being spent.
/// * `value` - The value of the output being spent.
///
/// # Returns
/// A `secp256k1::Message` suitable for Schnorr signing.
pub fn create_toy_sighash_message(locking_script: &ScriptBuf, value: Amount) -> Message {
    let mut engine = sha256::HashEngine::default();
    engine.input(&locking_script.to_bytes());
    engine.input(&value.to_sat().to_le_bytes());
    let hash = sha256::Hash::from_engine(engine);
    Message::from_digest(hash.to_byte_array())
}

/// Calculates the flow ID (`d`) from an input (`x`) and nonce (`r`). (Off-chain logic)
///
/// This simulates the core hash collision challenge `H(x, r)|_B = d`, where `H` is Blake3.
/// It checks if the `B`-bit prefix of the hash falls within the valid range `[0, 2^L - 1]`, which defines the set `D`.
///
/// # Arguments
/// * `input` - The input value `x` for the computation.
/// * `nonce` - The nonce `r` found by the operator.
/// * `b_bits` - The number of bits (`B`) in the hash prefix.
/// * `l_bits` - The number of bits (`L`) defining the size of the set `D` (2^L).
///
/// # Returns
/// * `Ok(u32)` - The calculated flow ID `d` if the hash prefix is within the valid range `D`.
/// * `Err(String)` - An error message if the hash prefix is outside the valid range.
pub fn calculate_flow_id(
    input: u32,
    nonce: u64,
    b_bits: usize,
    l_bits: usize,
) -> Result<u32, String> {
    // Compute H(input || nonce) using Blake3
    let mut hasher = Hasher::new();
    hasher.update(&input.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    let hash = hasher.finalize();

    // Extract the first 4 bytes of the hash as a u32
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash.as_bytes()[0..4]);
    let hash_u32 = u32::from_le_bytes(bytes);

    // Create a bitmask for the first B bits
    let mask_b = if b_bits >= 32 {
        u32::MAX // Avoid overflow if b_bits >= 32
    } else {
        (1u32 << b_bits).saturating_sub(1) // Generates 0b11...1 (B times)
    };

    // Extract the B-bit prefix
    let prefix_b = hash_u32 & mask_b;

    // Calculate the maximum valid flow ID (size of set D = 2^L)
    let max_flow_id = (1u64 << l_bits) as u32;

    // Check if the prefix falls within the valid set D = [0, 2^L - 1]
    if prefix_b < max_flow_id {
        Ok(prefix_b) // This is a valid flow ID `d`
    } else {
        Err(format!(
            "Hash prefix {} (from hash {}) is outside the valid flow ID range [0, {})",
            prefix_b, hash, max_flow_id
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
pub fn find_valid_nonce(input: u32, b_bits: usize, l_bits: usize) -> Result<(u64, u32), String> {
    let mut nonce: u64 = 0;

    // Calculate expected number of attempts (2^(B-L)) for progress reporting
    let expected_attempts: u64 = 1u64
        .checked_shl((b_bits.saturating_sub(l_bits)) as u32) // Calculate 2^(B-L)
        .unwrap_or(u64::MAX);
    let report_interval = (expected_attempts / 10).max(100_000); // Report progress periodically or every 100k hashes

    println!(
        "Finding valid nonce (L={}, B={})... (Expected work: ~2^{} = {} hashes)",
        l_bits,
        b_bits,
        b_bits.saturating_sub(l_bits),
        expected_attempts
    );

    loop {
        // Check if the current nonce yields a valid flow ID
        match calculate_flow_id(input, nonce, b_bits, l_bits) {
            Ok(flow_id) => {
                // Found a nonce `r` such that H(x, r)|_B = d ∈ D
                println!(
                    "  Found valid nonce {} -> flow_id {} after {} hashes.",
                    nonce,
                    flow_id,
                    nonce.saturating_add(1) // nonce starts at 0
                );
                return Ok((nonce, flow_id));
            }
            Err(_) => {
                // Hash prefix was outside the valid range [0, 2^L - 1], try next nonce
                if nonce > 0 && nonce % report_interval == 0 {
                    println!("  Tried {} hashes...", nonce);
                }

                // Increment nonce, checking for overflow
                nonce = nonce
                    .checked_add(1)
                    .ok_or_else(|| "Nonce overflowed u64::MAX while searching".to_string())?;

                // Safety break after excessive attempts (e.g., 100x expected work)
                // This prevents infinite loops in case of configuration errors.
                if nonce > expected_attempts.saturating_mul(100) {
                    return Err(format!(
                        "Could not find a valid nonce after {} attempts (expected ~{})",
                        nonce, expected_attempts
                    ));
                }
            }
        }
    }
}

/// Builds the complete locking script for the F1 sub-function.
///
/// This script enforces three conditions when being spent:
/// 1.  **Signature Check:** Verifies a signature from the designated signer.
/// 2.  **Hash Prefix Check:** Verifies that the flow ID provided in the witness matches the `flow_id` hardcoded in this script.
/// 3.  **Logic Check:** Verifies that the input `x` satisfies the F1 condition (`x > F1_THRESHOLD`).
///
/// The expected witness stack is: `<signature> <flow_id> <input_x>`
///
/// # Arguments
/// * `signer_pubkey` - The public key of the signer whose signature is required.
/// * `flow_id` - The specific flow ID (`d`) associated with this script.
/// * `_b_bits` - The hash prefix length `B` (parameter kept for consistency, but the hash check logic is simplified here).
///
/// # Returns
/// A `ScriptBuf` representing the locking script for the F1 transaction output.
pub fn build_script_f1_locked(
    signer_pubkey: &PublicKey,
    flow_id: u32,
    _b_bits: usize, // Parameter kept for consistency, but logic is simplified here
) -> ScriptBuf {
    Builder::new()
        // Stack: <sig> <flow_id> <input_x> --- Initial witness stack
        // 3. F1 Logic Check: input_x > F1_THRESHOLD?
        .push_int(F1_THRESHOLD as i64) // Push the threshold value
        .push_opcode(opcodes::all::OP_GREATERTHAN) // Check if <input_x> > <F1_THRESHOLD>
        .push_opcode(opcodes::all::OP_VERIFY) // Fail script if check is false
        // Stack: <sig> <flow_id> --- Input `x` is consumed
        // 2. Hash Prefix Check: flow_id == hardcoded_flow_id?
        // This simulates checking `H(x, r)|_B = d` by directly comparing the flow_id `d`.
        .push_int(flow_id as i64) // Push the hardcoded flow_id for this script
        .push_opcode(opcodes::all::OP_EQUALVERIFY) // Check if <witness_flow_id> == <hardcoded_flow_id>
        // Stack: <sig> --- Flow ID is consumed
        // 1. Signature Check: Is the signature valid for this transaction?
        .push_key(signer_pubkey) // Push the signer's public key
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY) // Verify the signature against the pubkey and tx data
        // Stack: <empty> --- Signature is consumed
        // 4. Success: If all VERIFY ops passed, the script is valid.
        .push_opcode(opcodes::OP_TRUE)
        .into_script()
}

/// Builds the complete locking script for the F2 sub-function.
///
/// Similar to `build_script_f1_locked`, this enforces:
/// 1.  Signature check.
/// 2.  Hash prefix check (matching the hardcoded `flow_id`).
/// 3.  F2 logic check (`x < F2_THRESHOLD`).
///
/// The expected witness stack is: `<signature> <flow_id> <input_x>`
///
/// # Arguments
/// * `signer_pubkey` - The public key of the signer whose signature is required.
/// * `flow_id` - The specific flow ID (`d`) associated with this script.
/// * `_b_bits` - The hash prefix length `B` (parameter kept for consistency, but the hash check logic is simplified here).
///
/// # Returns
/// A `ScriptBuf` representing the locking script for the F2 transaction output.
pub fn build_script_f2_locked(
    signer_pubkey: &PublicKey,
    flow_id: u32,
    _b_bits: usize, // Parameter kept for consistency, but logic is simplified here
) -> ScriptBuf {
    Builder::new()
        // Stack: <sig> <flow_id> <input_x> --- Initial witness stack
        // 3. F2 Logic Check: input_x < F2_THRESHOLD?
        .push_int(F2_THRESHOLD as i64) // Push the threshold value
        .push_opcode(opcodes::all::OP_LESSTHAN) // Check if <input_x> < <F2_THRESHOLD>
        .push_opcode(opcodes::all::OP_VERIFY) // Fail script if check is false
        // Stack: <sig> <flow_id> --- Input `x` is consumed
        // 2. Hash Prefix Check: flow_id == hardcoded_flow_id?
        // This simulates checking `H(x, r)|_B = d` by directly comparing the flow_id `d`.
        .push_int(flow_id as i64) // Push the hardcoded flow_id for this script
        .push_opcode(opcodes::all::OP_EQUALVERIFY) // Check if <witness_flow_id> == <hardcoded_flow_id>
        // Stack: <sig> --- Flow ID is consumed
        // 1. Signature Check: Is the signature valid for this transaction?
        .push_key(signer_pubkey) // Push the signer's public key
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY) // Verify the signature against the pubkey and tx data
        // Stack: <empty> --- Signature is consumed
        // 4. Success: If all VERIFY ops passed, the script is valid.
        .push_opcode(opcodes::OP_TRUE)
        .into_script()
}
