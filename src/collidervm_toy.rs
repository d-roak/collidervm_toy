use bitcoin::{PublicKey, blockdata::script::ScriptBuf};
use bitvm::{bigint::U256, treepp::script};
use blake3::Hasher;

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
pub type _InputX = Vec<u8>;
pub type _NonceR = Vec<u8>;

// --- Actors ---
#[derive(Debug)]
pub struct SignerInfo {
    pub _id: usize,
    pub pubkey: PublicKey,
    pub _privkey: secp256k1::SecretKey,
}

#[derive(Debug)]
pub struct OperatorInfo {
    pub _id: usize,
    pub pubkey: PublicKey,
    pub _privkey: secp256k1::SecretKey,
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

/// Alternate implementation that returns first 4 bytes as u32 (used for debugging)
pub fn _collider_hash_blake3(x_bytes: &[u8]) -> u32 {
    if x_bytes.len() != 4 {
        eprintln!(
            "ERROR: collider_hash_blake3 expects 4 bytes, got {}",
            x_bytes.len()
        );
        return 0;
    }
    let mut hasher = Hasher::new();
    hasher.update(x_bytes);
    let hash_bytes = hasher.finalize();
    // Extract the first 4 bytes and convert to u32 LE
    let hash_prefix: [u8; 4] = hash_bytes.as_bytes()[0..4]
        .try_into()
        .expect("Blake3 hash is too short");
    u32::from_le_bytes(hash_prefix)
}

// --- Script Generation Helpers ---

/// Generates the script for F1(x): checks if x > F1_THRESHOLD.
/// Assumes the stack top has: <F1_THRESHOLD> <x>
/// Leaves 0x01 on stack if true, fails otherwise.
pub fn script_f1() -> ScriptBuf {
    script! {
        OP_GREATERTHAN
        // OP_VERIFY // We might not need VERIFY if execute_script_buf handles the final boolean
    }
    .compile()
}

/// Generates the script for F2(x): checks if x < F2_THRESHOLD.
/// Assumes the stack top has: <F2_THRESHOLD> <x>
/// Leaves 0x01 on stack if true, fails otherwise.
pub fn script_f2() -> ScriptBuf {
    script! {
        OP_LESSTHAN
        // OP_VERIFY // We might not need VERIFY
    }
    .compile()
}

/// Returns a script that verifies the full 32-byte BLAKE3 output on the stack.
/// Assumes the stack top contains the 64 limbs (nibbles) of the computed hash.
/// Pops the 64 limbs and compares them with the provided `expected_output`.
/// Leaves OP_TRUE (0x01) if verification succeeds.
pub fn blake3_verify_output_script(expected_output: [u8; 32]) -> ScriptBuf {
    script! {
        // Push the expected hash bytes (converted to limbs/nibbles)
        for (i, byte) in expected_output.into_iter().enumerate() {
            {byte} // Push the full byte
            if i % 32 == 31 { // After every 32 bytes
                {U256::transform_limbsize(8,4)} // Transform to nibbles
            }
        }
        // Now the stack has: <computed_limbs> <expected_limbs>

        // Verify all 64 limbs
        for i in (2..65).rev() {
            {i}
            OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUAL
    }
    .compile()
}
