#![feature(proc_macro_hygiene)] // Required for bitvm scripts

mod collidervm_toy;
mod simulation;

use collidervm_toy::ColliderVmConfig;
use std::env;

fn main() {
    println!("ColliderVM Toy Simulation");

    // Parse command line arguments for input value or use default
    let input_value = env::args()
        .nth(1)
        .and_then(|arg| arg.parse::<u32>().ok())
        .unwrap_or(114); // Default input value is 114

    // Configure simulation parameters for ColliderVM
    // For a toy simulation, we use very small values
    // In a real system, the paper suggests L=46, B=120 or L=39, B=110
    let config = ColliderVmConfig {
        n: 3, // Number of signers
        m: 2, // Number of operators
        l: 4, // L value (log2 of D set size) - 2^4 = 16 flows
        b: 8, // B value (hash prefix bits)
        k: 2, // Number of subfunctions (F1 and F2)
    };

    println!("Running ColliderVM simulation with parameters:");
    println!("  n = {} signers (1-of-n honesty assumption)", config.n);
    println!("  m = {} operators", config.m);
    println!(
        "  L = {} (D set size: 2^L = {} flows)",
        config.l,
        1 << config.l
    );
    println!("  B = {} bits (hash prefix length)", config.b);
    println!(
        "  Expected operator work: 2^(B-L) = 2^{} hashes",
        config.b - config.l
    );
    println!("  Input value: {}", input_value);

    // Run the simulation
    match simulation::run_simulation(config, input_value) {
        Ok(result) => {
            if result.success {
                println!("Simulation succeeded! ✅");
            } else {
                println!("Simulation failed! ❌");
            }
        }
        Err(e) => {
            eprintln!("Error running simulation: {}", e);
        }
    }
}
