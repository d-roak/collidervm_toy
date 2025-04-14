#![feature(proc_macro_hygiene)] // Required for bitvm scripts

mod collidervm_toy;
mod simulation;

use collidervm_toy::ColliderVmConfig;
use std::env;

/// Entry point for the ColliderVM toy simulation.
///
/// This executable demonstrates the core concepts of ColliderVM:
/// 1. Parses an optional input value `x` from command line arguments (defaults to 114).
/// 2. Defines the `ColliderVmConfig` parameters (n, m, L, B, k).
/// 3. Runs the simulation, encompassing both the offline setup and online execution phases.
/// 4. Prints the final simulation result (success or failure).
fn main() {
    println!("ColliderVM Toy Simulation - Demonstrating Presigned Flows and Hash Challenges");
    println!("-------------------------------------------------------------------------------");

    // 1. Parse input value `x` from command line arguments
    let input_value = env::args()
        .nth(1) // Get the second argument (index 1)
        .and_then(|arg| {
            // Attempt to parse the argument as u32
            match arg.parse::<u32>() {
                Ok(val) => Some(val),
                Err(_) => {
                    eprintln!(
                        "Warning: Could not parse argument '{}' as u32. Using default.",
                        arg
                    );
                    None
                }
            }
        })
        .unwrap_or_else(|| {
            // Use default value if no argument or parsing failed
            println!("No valid input value provided, using default: 114");
            114
        });

    // 2. Configure simulation parameters for ColliderVM
    // These are small values for demonstration. See paper for production parameters.
    // - L=46, B=120 => ~74 bits honest work, ~97 bits malicious work (double collision)
    // - L=39, B=110 => ~71 bits honest work, ~97 bits malicious work (triple collision)
    let config = ColliderVmConfig {
        n: 3, // Number of signers (1-of-n honest for safety)
        m: 2, // Number of operators (1-of-m honest for liveness)
        l: 4, // D set size = 2^L = 16 flows (Small for demo)
        b: 8, // B hash prefix bits (Small for demo)
        k: 2, // Number of subfunctions (F1 & F2)
    };

    // Display the simulation configuration being used
    println!("\nRunning ColliderVM simulation with parameters:");
    println!("  Signers (n):             {}", config.n);
    println!("  Operators (m):           {}", config.m);
    println!(
        "  Flow Set Size (2^L):   {} (L={})",
        1u64 << config.l,
        config.l
    );
    println!("  Hash Prefix Bits (B):  {}", config.b);
    println!(
        "  Expected Operator Work: ~2^({}) = {} hashes",
        config.b.saturating_sub(config.l),
        1u64 << (config.b.saturating_sub(config.l))
    );
    println!(
        "  Security Gap (double):  B - L/2 = {}.{} bits",
        config.b.saturating_sub(config.l / 2), // Integer part
        if config.l % 2 == 1 { 5 } else { 0 }  // Fractional part (0.5 if L is odd)
    );
    println!(
        "  Security Gap (triple): B - L/3 = {:.1} bits (approx)",
        config.b as f64 - (config.l as f64 / 3.0)
    );
    println!("  Input Value (x):       {}", input_value);

    // 3. Run the full simulation (Offline Setup + Online Execution)
    match simulation::run_simulation(config, input_value) {
        Ok(result) => {
            // 4. Print the final outcome
            println!("\n--- Final Simulation Result ---");
            if result.success {
                println!("✅ Simulation Succeeded!");
                println!("   Both F1 and F2 script checks passed for the chosen flow.");
            } else {
                println!("❌ Simulation Failed!");
                println!(
                    "   F1 Success: {}, F2 Success: {}",
                    result.f1_result, result.f2_result
                );
                println!("   At least one script check failed for the chosen flow.");
            }
            println!("-------------------------------");
        }
        Err(e) => {
            // Handle potential errors during simulation setup or execution
            eprintln!("\n--- Simulation Error ---");
            eprintln!("Error running simulation: {}", e);
            eprintln!("------------------------");
            std::process::exit(1); // Exit with error code
        }
    }
}
