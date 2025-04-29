//! ColliderVM Signet Demo Binary
//!
//! This binary generates **real Bitcoin Signet transactions** that execute the
//! two‑step `F1/F2` ColliderVM toy program on‑chain.  It bridges the gap
//! between the purely in‑memory simulation (`src/simulation.rs`) and an actual
//! end‑to‑end flow that users can broadcast on Signet.
//!
//! # High‑level flow
//! 1.  **Key generation** – by default the program creates one Signer key and
//!     one Operator key and prints them (WIF + address).
//! 2.  **Funding phase** – if the user has _not_ supplied a `funding_txid`, the
//!     program prints clear CLI instructions telling the user how to fund the
//!     demo address on Signet and exits.
//! 3.  **Offline phase** – given a funding UTXO, the program
//!     * finds a nonce `r` such that `H(x‖r)|_B ∈ D` (using
//!       `collidervm_toy::core::find_valid_nonce`).
//!     * chooses the corresponding flow `d` and builds the **locking script**
//!       for `F1` (and `F2`) using the existing helpers.
//!     * constructs and signs **tx_f1** (spends the funding UTXO → P2WSH locked
//!       by the `F1` program).
//! 4.  **Online phase** – it then builds and signs **tx_f2**, spending the F1
//!     output with the witness `[sig, flow_id, x, script]`, paying the remaining
//!     funds to an Operator address.
//! 5.  Both transactions are written to `f1.tx` and `f2.tx` (raw hex), and all relevant IDs / next steps are printed.
//!
//! ## Build & run
//! ```bash
//! cargo run --bin demo -- -x 150           # prints funding instr.
//! cargo run --bin demo -- -x 150 -f <txid> # builds f1.tx + f2.tx
//! ```

#![allow(clippy::too_many_arguments)]

use std::{fs, str::FromStr};

use bitcoin::WScriptHash;
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness,
    absolute,
};
use bitcoin::{CompressedPublicKey, consensus::encode::Encodable};
use bitcoin::{EcdsaSighashType, hashes::Hash};
use bitcoin::{
    secp256k1::{Message, Secp256k1, SecretKey},
    sighash::SighashCache,
};
use clap::Parser;
use colored::*;
use serde::Serialize;

use collidervm_toy::core::{
    build_script_f1_blake3_locked, build_script_f2_blake3_locked, find_valid_nonce,
    flow_id_to_prefix_bytes,
};

/// Minimal amount we ask the user to deposit (10 000 sat ≈ 0.0001 BTC)
const REQUIRED_AMOUNT_SAT: u64 = 10_000;
/// Hard‑coded ColliderVM parameters (match the toy simulation)
const L_PARAM: usize = 4;
const B_PARAM: usize = 16; // multiple of 8 ≤ 32

const OUTPUT_DIR: &str = "target/demo";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input value x (checked by F1 > 100 and F2 < 200)
    #[arg(short, long, default_value_t = 114)]
    x: u32,

    /// Funding transaction ID (hex) that pays at least 10 000 sat to the demo address
    #[arg(short, long)]
    funding_txid: Option<String>,

    /// Optional vout index for the funding TX (default 0)
    #[arg(long, default_value_t = 0)]
    funding_vout: u32,

    /// Fee‑rate in sat/vB (default = 1 sat/vB, plenty for Signet)
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,

    /// Output in JSON format for easier parsing
    #[arg(long)]
    json: bool,

    /// Write JSON output to a file instead of stdout
    #[arg(long)]
    json_output_file: Option<String>,
}

/// Structure for serializing key details to JSON
#[derive(Serialize)]
struct KeyInfo {
    signer: KeyPair,
    operator: KeyPair,
}

/// Structure for serializing individual key pairs to JSON
#[derive(Serialize)]
struct KeyPair {
    address: String,
    wif: String,
}

/// Structure for serializing transaction details to JSON
#[derive(Serialize)]
struct TransactionInfo {
    f1: TxInfo,
    f2: TxInfo,
    nonce: u64,
    flow_id: u32,
}

/// Structure for serializing individual transaction information
#[derive(Serialize)]
struct TxInfo {
    txid: String,
    file_path: String,
}

/// Complete demo output for JSON serialization
#[derive(Serialize)]
struct DemoOutput {
    keys: KeyInfo,
    transactions: Option<TransactionInfo>,
    input_x: u32,
    parameters: DemoParameters,
}

/// Parameters used in the demo for JSON serialization
#[derive(Serialize)]
struct DemoParameters {
    required_amount_sat: u64,
    l_param: usize,
    b_param: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 0. Generate Signer & Operator keys (for demo we use 1‑of‑1)
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
    let (sk_signer, pk_signer) = secp.generate_keypair(&mut rand::thread_rng());
    let signer_compressed_pk =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(pk_signer)).unwrap();
    let signer_addr = Address::p2wpkh(&signer_compressed_pk, Network::Signet);

    let (sk_operator, pk_operator) = secp.generate_keypair(&mut rand::thread_rng());
    let operator_compressed_pk =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(pk_operator)).unwrap();
    let operator_addr = Address::p2wpkh(&operator_compressed_pk, Network::Signet);

    // Prepare key information for output
    let key_info = KeyInfo {
        signer: KeyPair {
            address: signer_addr.to_string(),
            wif: sk_to_wif(&sk_signer),
        },
        operator: KeyPair {
            address: operator_addr.to_string(),
            wif: sk_to_wif(&sk_operator),
        },
    };

    // Prepare demo output structure for JSON output
    let mut demo_output = DemoOutput {
        keys: key_info,
        transactions: None,
        input_x: args.x,
        parameters: DemoParameters {
            required_amount_sat: REQUIRED_AMOUNT_SAT,
            l_param: L_PARAM,
            b_param: B_PARAM,
        },
    };

    // If not using JSON, print key information in formatted text
    if !args.json {
        println!(
            "{}\n  Signer  → {} (WIF {})\n  Operator→ {} (WIF {})\n{}",
            "Generated demo keys:".bold().blue(),
            signer_addr,
            sk_to_wif(&sk_signer),
            operator_addr,
            sk_to_wif(&sk_operator),
            "---------------------------------------------".dimmed()
        );
    }

    // If the user did not supply a funding_txid, print instructions & exit
    if args.funding_txid.is_none() {
        if args.json {
            // Output JSON without transaction info
            let json_output = serde_json::to_string_pretty(&demo_output)?;

            // If a JSON output file is specified, write to it
            if let Some(file_path) = &args.json_output_file {
                fs::create_dir_all(
                    std::path::Path::new(file_path)
                        .parent()
                        .unwrap_or(std::path::Path::new("./")),
                )?;
                fs::write(file_path, &json_output)?;
            } else {
                // Otherwise print to stdout
                println!("{json_output}");
            }
        } else {
            print_funding_instructions(&signer_addr);
        }
        return Ok(());
    }

    // --------------------------------------------------------------------
    // 1. Parse CLI funding UTXO
    // --------------------------------------------------------------------
    let funding_txid_str = args.funding_txid.as_ref().unwrap();
    let funding_txid = if funding_txid_str.starts_with("dry_run") {
        // In dry run mode, use a placeholder txid
        Txid::all_zeros()
    } else {
        // In normal mode, parse the real txid
        Txid::from_str(funding_txid_str)?
    };
    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: args.funding_vout,
    };

    // In a production‑ready tool we would RPC‑query the node to retrieve the
    // exact amount & pkScript of the funding UTXO.  To keep the demo
    // self‑contained we *assume* the UTXO pays `REQUIRED_AMOUNT_SAT` to the
    // Signer's P2WPKH address.  The instructions ensured the user sends that.
    let funding_value_sat = REQUIRED_AMOUNT_SAT;

    // --------------------------------------------------------------------
    // 2. Find nonce r & flow‑id d  (operator work)
    // --------------------------------------------------------------------
    let (nonce, flow_id, _hash) =
        find_valid_nonce(args.x, B_PARAM, L_PARAM).expect("nonce search should succeed quickly");

    if !args.json {
        println!(
            "Found nonce r = {nonce} selecting flow d = {flow_id} (B={B_PARAM} bits, L={L_PARAM})"
        );
    }

    // --------------------------------------------------------------------
    // 3. Build locking scripts for F1 & F2 (for the chosen flow)
    // --------------------------------------------------------------------
    let prefix_nibbles = flow_id_to_prefix_bytes(flow_id, B_PARAM);
    let f1_lock =
        build_script_f1_blake3_locked(&PublicKey::new(pk_signer), &prefix_nibbles, B_PARAM);
    let _f2_lock =
        build_script_f2_blake3_locked(&PublicKey::new(pk_signer), &prefix_nibbles, B_PARAM);

    // P2WSH wrapper for F1 output
    let f1_wsh = WScriptHash::hash(f1_lock.as_bytes());
    let f1_spk = ScriptBuf::new_p2wsh(&f1_wsh);

    // --------------------------------------------------------------------
    // 4. Construct tx_f1  (funding → F1 output)
    // --------------------------------------------------------------------
    let fee_f1 = estimate_fee_vbytes(155, args.fee_rate); // ~1 input + 1 output
    let f1_output_value = funding_value_sat
        .checked_sub(fee_f1)
        .expect("funding not sufficient for fee");

    let mut tx_f1 = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(f1_output_value),
            script_pubkey: f1_spk.clone(),
        }],
    };

    // Sign the funding input (P2WPKH)
    let signer_pkh = signer_addr
        .witness_program()
        .expect("addr")
        .program() // 20 bytes = hash160(pubkey)
        .to_owned();
    let script_code =
        ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(signer_pkh.as_bytes())?);
    let mut sighash_cache = SighashCache::new(&mut tx_f1);
    let sighash = sighash_cache.p2wsh_signature_hash(
        0,
        &script_code,
        Amount::from_sat(funding_value_sat),
        EcdsaSighashType::All,
    )?;
    let sig = secp.sign_ecdsa(&Message::from_digest_slice(&sighash[..])?, &sk_signer);
    let mut sig_ser = sig.serialize_der().to_vec();
    sig_ser.push(EcdsaSighashType::All as u8);
    tx_f1.input[0].witness = Witness::from_slice(&[sig_ser, pk_signer.serialize().to_vec()]);

    // Create the output directory if it doesn't exist
    fs::create_dir_all(OUTPUT_DIR)?;

    // Serialize & save
    let tx_f1_hex = serialize_hex(&tx_f1);
    let f1_file_path = format!("{OUTPUT_DIR}/f1.tx");
    fs::write(&f1_file_path, &tx_f1_hex)?;
    let tx_f1_id = tx_f1.compute_txid();

    if !args.json {
        println!("tx_f1 created  →  {tx_f1_id}  (saved to f1.tx)");
    }

    // --------------------------------------------------------------------
    // 5. Construct tx_f2  (spend F1 output → Operator)
    // --------------------------------------------------------------------
    let fee_f2 = estimate_fee_vbytes(120, args.fee_rate); // 1 input P2WSH + 1 output
    let f2_output_value = f1_output_value
        .checked_sub(fee_f2)
        .expect("f1 output too small for f2 fee");

    let mut tx_f2 = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx_f1_id,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(f2_output_value),
            script_pubkey: operator_addr.script_pubkey(),
        }],
    };

    // Build the witness stack for the P2WSH spend
    let mut cache_f2 = SighashCache::new(&mut tx_f2);
    let sighash_f2 = cache_f2.p2wsh_signature_hash(
        0,
        &f1_lock,
        Amount::from_sat(f1_output_value),
        EcdsaSighashType::All,
    )?;
    let sig_f2 = secp.sign_ecdsa(&Message::from_digest_slice(&sighash_f2[..])?, &sk_signer);
    let mut sig_f2_ser = sig_f2.serialize_der().to_vec();
    sig_f2_ser.push(EcdsaSighashType::All as u8);

    // Encode flow_id & x as minimal‑encoded script numbers
    let flow_id_enc = encode_scriptnum(flow_id as i64);
    let x_enc = encode_scriptnum(args.x as i64);

    tx_f2.input[0].witness =
        Witness::from_slice(&[sig_f2_ser, flow_id_enc, x_enc, f1_lock.to_bytes()]);

    let tx_f2_hex = serialize_hex(&tx_f2);
    let f2_file_path = format!("{OUTPUT_DIR}/f2.tx");
    fs::write(&f2_file_path, &tx_f2_hex)?;
    let tx_f2_id = tx_f2.compute_txid();

    if !args.json {
        println!("tx_f2 created  →  {tx_f2_id}  (saved to f2.tx)");
        println!(
            "\n{}\n  1️⃣  broadcast f1.tx ({}).  Wait ≥1 confirmation.\n  2️⃣  broadcast f2.tx ({}).\n{}",
            "Next steps:".bold().green(),
            tx_f1_id,
            tx_f2_id,
            "---------------------------------------------".dimmed()
        );
    }

    // Update transaction information for JSON output
    demo_output.transactions = Some(TransactionInfo {
        f1: TxInfo {
            txid: tx_f1_id.to_string(),
            file_path: f1_file_path,
        },
        f2: TxInfo {
            txid: tx_f2_id.to_string(),
            file_path: f2_file_path,
        },
        nonce,
        flow_id,
    });

    // If JSON output is requested, print the full JSON structure
    if args.json {
        let json_output = serde_json::to_string_pretty(&demo_output)?;

        // If a JSON output file is specified, write to it
        if let Some(file_path) = &args.json_output_file {
            fs::create_dir_all(
                std::path::Path::new(file_path)
                    .parent()
                    .unwrap_or(std::path::Path::new("./")),
            )?;
            fs::write(file_path, &json_output)?;
        } else {
            // Otherwise print to stdout
            println!("{json_output}");
        }
    }

    Ok(())
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

/// Print instructions for creating the initial funding TX on signet.
fn print_funding_instructions(addr: &Address) {
    let btc = REQUIRED_AMOUNT_SAT as f64 / 100_000_000.0;
    println!(
        "\n{}\nSend ≈ {:.8} BTC ({} sat) to the demo address on Signet, then re‑run this command with --funding-txid <txid>.\n\nExample (bitcoin‑cli):\n  bitcoin-cli -signet sendtoaddress {} {:.8}\n",
        "🔗  Funding required".bold().yellow(),
        btc,
        REQUIRED_AMOUNT_SAT,
        addr,
        btc
    );
}

/// Encode an i64 as a minimally‑encoded script number (little‑endian)
fn encode_scriptnum(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let mut abs = n.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    // If the most‑significant bit is set, add a sign byte
    if out.last().unwrap() & 0x80 != 0 {
        out.push(if n < 0 { 0x80 } else { 0x00 });
    } else if n < 0 {
        *out.last_mut().unwrap() |= 0x80;
    }
    out
}

/// Quick & dirty fee estimator (vbytes × sat/vB)
fn estimate_fee_vbytes(vbytes: usize, rate: u64) -> u64 {
    (vbytes as u64) * rate
}

/// Very small helper to serialize a TX to hex
fn serialize_hex(tx: &bitcoin::Transaction) -> String {
    let mut v = Vec::new();
    tx.consensus_encode(&mut v).expect("encode");
    hex::encode(v)
}

/// Convert a SecretKey to WIF (signet/testnet)
fn sk_to_wif(sk: &SecretKey) -> String {
    use bitcoin::bip32::Xpriv;
    // Not ideal, but reuse XPriv to get WIF easily
    let xpriv = Xpriv::new_master(Network::Signet, sk.secret_bytes().as_slice()).expect("xpriv");
    xpriv.to_priv().to_wif()
}
