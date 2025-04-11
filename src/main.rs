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

    // Configure simulation parameters
    let config = ColliderVmConfig {
        n: 3, // Number of signers
        m: 2, // Number of operators
        l: 4, // L value (log2 of D set size)
        b: 8, // B value (hash prefix bits)
        k: 2, // Number of subfunctions (F1 and F2)
    };

    println!("Running simulation with input value: {}", input_value);

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
