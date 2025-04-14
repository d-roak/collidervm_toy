use bitcoin::{
    Amount,
    PublicKey,
    Transaction,
    XOnlyPublicKey,
    blockdata::script::{Builder, ScriptBuf},
    opcodes,
    // Remove unused imports: Sequence, TxIn, TxOut, Witness
    // Remove unused sighash imports: self, SighashCache, TapSighashType
};
// Add HashEngine trait import
use bitcoin_hashes::{Hash as BitcoinHashTrait, HashEngine, sha256};
// Remove unused bitvm imports
// Remove unused Secp256k1 import
use blake3::Hasher;
use secp256k1::{Keypair, Message, SecretKey, schnorr::Signature}; // Keep necessary secp types
use std::collections::HashMap;

// --- Configuration ---
#[derive(Debug, Clone)]
pub struct ColliderVmConfig {
    pub n: usize, // Number of signers
    pub m: usize, // Number of operators
    pub l: usize, // D size = 2^L
    pub b: usize, // Hash prefix length in bits
    pub k: usize, // Number of sub-functions (fixed to 2 for MVP)
}

// --- Data Types ---
pub type _InputX = Vec<u8>; // Keeping alias for potential future use
pub type _NonceR = Vec<u8>; // Keeping alias for potential future use

// --- Actors ---
#[derive(Debug, Clone)] // Added Clone
pub struct SignerInfo {
    pub id: usize,
    // Use bitcoin::PublicKey for compatibility with script generation
    pub pubkey: PublicKey,
    // Store the secp256k1::SecretKey for signing
    pub privkey: SecretKey,
    pub keypair: Keypair,
    pub xonly: XOnlyPublicKey,
}

#[derive(Debug, Clone)] // Added Clone
pub struct OperatorInfo {
    pub id: usize,
    pub pubkey: PublicKey,
    pub privkey: SecretKey,
}

// --- New Data Structures for Presigned Flows ---

/// Represents a single step in a presigned flow (e.g., F1 or F2 execution)
#[derive(Clone, Debug)]
pub struct PresignedStep {
    /// Placeholder for the transaction structure committed to during signing.
    /// For the toy, this might be simplified.
    pub tx_template: Transaction,
    /// The actual sighash message that was signed by the signers.
    pub sighash_message: Message,
    /// Map from Signer's PublicKey (as bytes for HashMap key) to their Schnorr signature.
    pub signatures: HashMap<Vec<u8>, Signature>,
    /// The scriptPubKey that enforces the logic (sig check, hash check, function check).
    /// This is embedded in tx_template.output[.].script_pubkey.
    pub locking_script: ScriptBuf,
}

/// Represents a complete presigned flow for a specific flow_id 'd'
#[derive(Clone, Debug)]
pub struct PresignedFlow {
    pub flow_id: u32,
    /// Sequence of steps, e.g., [step_f1, step_f2]
    pub steps: Vec<PresignedStep>,
}

// --- Toy Function Constants ---
pub const F1_THRESHOLD: u32 = 100;
pub const F2_THRESHOLD: u32 = 200;

// --- Hash Functions ---

/// Rust implementation of the Blake3 hash. Used for off-chain calculations.
/// Takes arbitrary bytes, returns the 32-byte Blake3 hash.
pub fn calculate_blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

// --- Simplified Sighash Message Generation for Toy ---
/// Creates a simplified message to be signed, representing the core commitment.
/// In a real system, this uses the complex Bitcoin sighash rules.
/// Here, we hash the locking script and output value as a proxy.
pub fn create_toy_sighash_message(locking_script: &ScriptBuf, value: Amount) -> Message {
    let mut engine = sha256::HashEngine::default();
    engine.input(&locking_script.to_bytes()); // Now compiles due to HashEngine trait
    engine.input(&value.to_sat().to_le_bytes()); // Now compiles
    let hash = sha256::Hash::from_engine(engine);
    Message::from_digest(hash.to_byte_array())
}

// --- Script Generation Helpers ---

/// Generates the script for F1(x): checks if x > F1_THRESHOLD.
/// Assumes input x is pushed onto the stack before this script segment.
pub fn script_f1_logic() -> ScriptBuf {
    Builder::new()
        .push_int(F1_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_GREATERTHAN) // Check x > threshold
        .push_opcode(opcodes::all::OP_VERIFY) // Fail if false
        .into_script()
}

/// Generates the script for F2(x): checks if x < F2_THRESHOLD.
/// Assumes input x is pushed onto the stack before this script segment.
pub fn script_f2_logic() -> ScriptBuf {
    Builder::new()
        .push_int(F2_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_LESSTHAN) // Check x < threshold
        .push_opcode(opcodes::all::OP_VERIFY) // Fail if false
        .into_script()
}

/// Calculate flow ID from input and nonce (Off-chain logic)
/// Simulates H(x,r)|B to find which flow to use.
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

    // Extract first 4 bytes and convert to u32
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash.as_bytes()[0..4]);
    let hash_u32 = u32::from_le_bytes(bytes);

    // Create a mask for the first B bits
    let mask_b = if b_bits >= 32 {
        0xFFFFFFFF
    } else {
        (1 << b_bits) - 1
    };
    // Apply the mask to get the B-bit prefix
    let prefix_b = hash_u32 & mask_b;

    // Check if the B-bit prefix is within the allowed range [0, 2^L - 1]
    let max_flow_id = (1u64 << l_bits) as u32; // Calculate 2^L
    if prefix_b < max_flow_id {
        Ok(prefix_b)
    } else {
        // Indicate that this hash doesn't map to a valid flow ID in D
        Err(format!(
            "Hash prefix {} is outside range [0, {})",
            prefix_b, max_flow_id
        ))
    }
}

/// Find a valid nonce for a given input that produces a flow ID in D (Off-chain logic)
/// Simulates the operator finding a nonce r such that H(x,r)|B ∈ D.
pub fn find_valid_nonce(input: u32, b_bits: usize, l_bits: usize) -> Result<(u64, u32), String> {
    let mut nonce: u64 = 0;
    // Calculate expected number of attempts (2^(B-L)) for progress reporting
    let expected_attempts: u64 = 1u64
        .checked_shl((b_bits - l_bits) as u32)
        .unwrap_or(u64::MAX);
    let report_interval = (expected_attempts / 10).max(100_000); // Report progress periodically

    println!(
        "Finding valid nonce (L={}, B={})... (Expected work: ~2^{} = {} hashes)",
        l_bits,
        b_bits,
        b_bits - l_bits,
        expected_attempts
    );

    loop {
        match calculate_flow_id(input, nonce, b_bits, l_bits) {
            Ok(flow_id) => {
                // Found a nonce that maps to a valid flow ID
                println!(
                    "  Found valid nonce {} -> flow_id {} after {} hashes.",
                    nonce,
                    flow_id,
                    nonce + 1 // nonce starts at 0
                );
                return Ok((nonce, flow_id));
            }
            Err(_) => {
                // Hash prefix was outside the valid range, continue searching
                if nonce % report_interval == 0 && nonce > 0 {
                    println!("  Tried {} hashes...", nonce);
                }
                nonce = nonce
                    .checked_add(1)
                    .ok_or_else(|| "Nonce overflowed".to_string())?;
                // Optional: Add a safety break after an excessive number of attempts
                if nonce > expected_attempts.saturating_mul(100) {
                    // e.g., 100x expected work
                    return Err(format!(
                        "Could not find a valid nonce after {} attempts (expected ~{})",
                        nonce, expected_attempts
                    ));
                }
            }
        }
    }
}

/// Generates the *complete locking script* for F1 including signature verification.
/// Structure: Check Sig -> Check Hash Prefix -> Check F1 Logic
/// Returns the ScriptBuf.
pub fn build_script_f1_locked(
    signer_pubkey: &PublicKey, // Use bitcoin::PublicKey
    flow_id: u32,
    _b_bits: usize, // _b_bits is unused in this simplified version
) -> ScriptBuf {
    // --- Witness stack expected: <signature> <hash_prefix> <input_x> ---
    Builder::new()
        // 1. Verify signature
        .push_key(signer_pubkey) // Push the public key
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY) // Check sig (consumes sig & key)
        // Stack: <hash_prefix> <input_x>
        // 2. Verify hash prefix (Simulated check - inline logic)
        .push_int(flow_id as i64) // Push the expected flow_id
        .push_opcode(opcodes::all::OP_EQUALVERIFY) // Check equality with pushed <hash_prefix>
        // Stack: <input_x>
        // 3. Check F1 logic: x > F1_THRESHOLD (inline logic)
        .push_int(F1_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_GREATERTHAN) // Check x > threshold
        .push_opcode(opcodes::all::OP_VERIFY) // Fail if false
        // Stack: empty (if successful)
        // 4. Final success opcode
        .push_opcode(opcodes::OP_TRUE)
        .into_script()
}

/// Generates the *complete locking script* for F2 including signature verification.
/// Structure: Check Sig -> Check Hash Prefix -> Check F2 Logic
/// Returns the ScriptBuf.
pub fn build_script_f2_locked(
    signer_pubkey: &PublicKey,
    flow_id: u32,
    _b_bits: usize, // _b_bits is unused in this simplified version
) -> ScriptBuf {
    // --- Witness stack expected: <signature> <hash_prefix> <input_x> ---
    Builder::new()
        // 1. Verify signature
        .push_key(signer_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        // Stack: <hash_prefix> <input_x>
        // 2. Verify hash prefix (Simulated check - inline logic)
        .push_int(flow_id as i64) // Push the expected flow_id
        .push_opcode(opcodes::all::OP_EQUALVERIFY) // Check equality with pushed <hash_prefix>
        // Stack: <input_x>
        // 3. Check F2 logic: x < F2_THRESHOLD (inline logic)
        .push_int(F2_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_LESSTHAN) // Check x < threshold
        .push_opcode(opcodes::all::OP_VERIFY) // Fail if false
        // Stack: empty (if successful)
        // 4. Final success opcode
        .push_opcode(opcodes::OP_TRUE)
        .into_script()
}
