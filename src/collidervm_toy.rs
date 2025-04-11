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
/// Leaves 0x01 on stack if true, 0x00 otherwise.
pub fn script_f1() -> ScriptBuf {
    script! {
        OP_GREATERTHAN
        // No OP_VERIFY here, just return the boolean result
    }
    .compile()
}

/// Generates the script for F2(x): checks if x < F2_THRESHOLD.
/// Assumes the stack top has: <F2_THRESHOLD> <x>
/// Leaves 0x01 on stack if true, 0x00 otherwise.
pub fn script_f2() -> ScriptBuf {
    script! {
        OP_LESSTHAN
        // No OP_VERIFY here, just return the boolean result
    }
    .compile()
}

/// Returns a script that verifies the full 32-byte BLAKE3 output on the stack.
/// Assumes the stack top contains the 64 limbs (nibbles) of the computed hash.
/// Pops the 64 limbs and compares them with the provided `expected_output`.
/// Leaves OP_TRUE (0x01) if verification succeeds.
#[allow(dead_code)]
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

/// Generates a script that verifies a signature against a public key.
/// Assumes the stack has: <signature> <pubkey>
/// Leaves 0x01 on stack if verification succeeds, fails otherwise.
#[allow(dead_code)]
pub fn script_check_signature() -> ScriptBuf {
    script! {
        OP_CHECKSIG
    }
    .compile()
}

/// Generates a Bitcoin script to check H(x,r)|B = d
/// This is the flow selection mechanism from the ColliderVM paper
/// Returns a script that checks if the first B bits of H(x,r) match d
#[allow(dead_code)]
pub fn script_check_hash_prefix(flow_id: u32, _b_bits: usize) -> ScriptBuf {
    // In a real implementation, this would check if the first b_bits of H(x,r) equal flow_id
    // For simplicity in our toy implementation, we'll just do a direct comparison
    // assuming x and r are on the stack

    script! {
        // The full H(x,r) calculation would go here
        // In a real implementation, we'd compute the hash and check if B bits match flow_id

        // For toy simulation, since we're not actually implementing the hash calculation in script,
        // we'll just push a constant and check against flow_id
        <flow_id>
        OP_EQUALVERIFY
    }
    .compile()
}

/// Generates the complete F1 script with signature verification
/// Takes a signer public key and the flow ID to generate a script that:
/// 1. Verifies the signature against the signer's public key
/// 2. Verifies that the input hash matches the flow ID
/// 3. Checks if x > F1_THRESHOLD
pub fn script_f1_with_signature(
    signer_pubkey: &PublicKey,
    flow_id: u32,
    _b_bits: usize,
) -> ScriptBuf {
    let signer_pubkey_bytes = signer_pubkey.to_bytes();

    script! {
        // Stack: <signature> <x> <r> ...

        // 1. Verify signature (signature is at the top of the stack)
        <signer_pubkey_bytes>
        OP_CHECKSIGVERIFY

        // 2. Verify hash prefix (check that H(x,r)|B = flow_id)
        // In a real implementation, we'd duplicate x and r, compute H(x,r)|B and check against flow_id
        <flow_id>
        OP_EQUALVERIFY

        // 3. Check F1: x > F1_THRESHOLD
        // Stack: <x> ...
        <F1_THRESHOLD>
        OP_GREATERTHAN
        // Result left on stack: 0x01 if x > F1_THRESHOLD, 0x00 otherwise
    }
    .compile()
}

/// Generates the complete F2 script with signature verification
/// Takes a signer public key and the flow ID to generate a script that:
/// 1. Verifies the signature against the signer's public key
/// 2. Verifies that the input hash matches the flow ID
/// 3. Checks if x < F2_THRESHOLD
pub fn script_f2_with_signature(
    signer_pubkey: &PublicKey,
    flow_id: u32,
    _b_bits: usize,
) -> ScriptBuf {
    let signer_pubkey_bytes = signer_pubkey.to_bytes();

    script! {
        // Stack: <signature> <x> <r> ...

        // 1. Verify signature (signature is at the top of the stack)
        <signer_pubkey_bytes>
        OP_CHECKSIGVERIFY

        // 2. Verify hash prefix (check that H(x,r)|B = flow_id)
        // In a real implementation, we'd duplicate x and r, compute H(x,r)|B and check against flow_id
        <flow_id>
        OP_EQUALVERIFY

        // 3. Check F2: x < F2_THRESHOLD
        // Stack: <x> ...
        <F2_THRESHOLD>
        OP_LESSTHAN
        // Result left on stack: 0x01 if x < F2_THRESHOLD, 0x00 otherwise
    }
    .compile()
}

/// Calculate flow ID from input and nonce
/// This simulates H(x,r)|B to find which flow to use
pub fn calculate_flow_id(input: u32, nonce: u64, b_bits: usize, l_bits: usize) -> u32 {
    // In a real implementation, this would calculate H(x,r) and return the first B bits
    // Also check if the result is in the set D (size 2^L)

    // For the toy implementation, we'll use a simplified approach:
    // Calculate a hash of input and nonce, take the first b_bits,
    // and ensure it's in range [0, 2^l_bits - 1]

    let mut hasher = Hasher::new();
    hasher.update(&input.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    let hash = hasher.finalize();

    // Extract first 4 bytes and convert to u32
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash.as_bytes()[0..4]);
    let hash_u32 = u32::from_le_bytes(bytes);

    // Take only b_bits and ensure it's in range [0, 2^l_bits - 1]
    let mask_b = if b_bits >= 32 {
        0xFFFFFFFF
    } else {
        (1 << b_bits) - 1
    };
    let mask_l = if l_bits >= 32 {
        0xFFFFFFFF
    } else {
        (1 << l_bits) - 1
    };

    (hash_u32 & mask_b) & mask_l
}

/// Find a valid nonce for a given input that produces a valid flow ID
/// This simulates the operator finding a nonce r such that H(x,r)|B ∈ D
pub fn find_valid_nonce(input: u32, b_bits: usize, l_bits: usize) -> (u64, u32) {
    // Start with nonce 0 and increment until we find a valid flow ID
    let mut nonce: u64 = 0;
    let max_attempts = if (b_bits - l_bits) < 30 {
        1 << (b_bits - l_bits)
    } else {
        1_000_000
    };

    println!(
        "Finding valid nonce (expected work: 2^{} = {} hashes)...",
        b_bits - l_bits,
        max_attempts
    );

    for i in 0..max_attempts {
        let flow_id = calculate_flow_id(input, nonce, b_bits, l_bits);
        if i % 100_000 == 0 {
            println!("  Tried {} hashes...", i);
        }

        // In real implementation, we'd check if flow_id ∈ D
        // For toy implementation, any flow_id in range [0, 2^l_bits - 1] is valid
        if flow_id < (1 << l_bits) {
            println!("  Found valid nonce {} after {} hashes", nonce, i);
            return (nonce, flow_id);
        }

        nonce += 1;
    }

    // If no valid nonce found after max_attempts, just return the last one
    // This shouldn't happen with reasonable parameters
    println!(
        "  No valid nonce found after {} attempts, using last one",
        max_attempts
    );
    let flow_id = calculate_flow_id(input, nonce, b_bits, l_bits);
    (nonce, flow_id)
}
