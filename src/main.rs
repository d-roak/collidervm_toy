#![feature(proc_macro_hygiene)] // Required for bitvm scripts

mod collidervm_toy;
mod simulation;

use collidervm_toy::ColliderVmConfig;
use colored::*; // Import the colored crate
use std::env;

/// Entry point for the ColliderVM toy simulation.
///
/// This executable demonstrates the core concepts of ColliderVM:
/// 1. Parses an optional input value `x` from command line arguments (defaults to 114).
/// 2. Defines the `ColliderVmConfig` parameters (n, m, L, B, k).
/// 3. Runs the simulation, encompassing both the offline setup and online execution phases.
/// 4. Prints the final simulation result (success or failure).
fn main() {
    println!(
        "{}",
        "======================================================="
            .bold()
            .blue()
    );
    println!(
        "{}",
        "      ColliderVM Toy Simulation Demonstration        "
            .bold()
            .blue()
    );
    println!(
        "{}",
        "======================================================="
            .bold()
            .blue()
    );
    println!();

    // 1. Parse input value `x` from command line arguments
    let input_value = env::args()
        .nth(1) // Get the second argument (index 1)
        .and_then(|arg| {
            // Attempt to parse the argument as u32
            match arg.parse::<u32>() {
                Ok(val) => Some(val),
                Err(_) => {
                    eprintln!(
                        "{}: Could not parse argument '{}' as u32. Using default.",
                        "Warning".yellow(),
                        arg
                    );
                    None
                }
            }
        })
        .unwrap_or_else(|| {
            // Use default value if no argument or parsing failed
            println!(
                "{}: No valid input value provided, using default: {}",
                "Info".cyan(),
                "114".bold()
            );
            114
        });

    // 2. Configure simulation parameters for ColliderVM
    let config = ColliderVmConfig {
        n: 3, // Number of signers (1-of-n honest for safety)
        m: 2, // Number of operators (1-of-m honest for liveness)
        l: 4, // D set size = 2^L = 16 flows (Small for demo)
        b: 8, // B hash prefix bits (Small for demo)
        k: 2, // Number of subfunctions (F1 & F2)
    };

    // Display the simulation configuration being used
    println!("\n{}", "--- Simulation Configuration ---".bold().yellow());
    println!("  Signers (n):             {}", config.n.to_string().cyan());
    println!("  Operators (m):           {}", config.m.to_string().cyan());
    println!(
        "  Flow Set Size (2^L):   {} (L={})",
        (1u64 << config.l).to_string().cyan(),
        config.l.to_string().cyan()
    );
    println!("  Hash Prefix Bits (B):  {}", config.b.to_string().cyan());
    println!(
        "  Expected Operator Work: ~2^({}) = {} hashes",
        config.b.saturating_sub(config.l).to_string().cyan(),
        (1u64 << (config.b.saturating_sub(config.l)))
            .to_string()
            .cyan()
    );
    println!(
        "  Security Gap (double):  B - L/2 = {}.{} bits",
        config.b.saturating_sub(config.l / 2).to_string().cyan(),
        if config.l % 2 == 1 { "5" } else { "0" }.cyan()
    );
    println!(
        "  Security Gap (triple): B - L/3 = {:.1} bits (approx)",
        (config.b as f64 - (config.l as f64 / 3.0))
            .to_string()
            .cyan()
    );
    println!(
        "  Input Value (x):       {}",
        input_value.to_string().cyan()
    );
    println!("--------------------------------");
    println!("\n{}. Press Enter to start...", "Setup".bold());
    let _ = std::io::stdin().read_line(&mut String::new()); // Wait for user input

    // 3. Run the full simulation (Offline Setup + Online Execution)
    match simulation::run_simulation(config, input_value) {
        Ok(result) => {
            // 4. Print the final outcome
            println!("\n{}", "--- Final Simulation Result ---".bold().blue());
            if result.success {
                println!("{}", "✅ Simulation Succeeded!".bold().green());
                println!(
                    "   {}",
                    "Both F1 and F2 script checks passed for the chosen flow.".green()
                );
            } else {
                println!("{}", "❌ Simulation Failed!".bold().red());
                println!(
                    "   F1 Success: {}, F2 Success: {}",
                    result.f1_result.to_string().color(if result.f1_result {
                        Color::Green
                    } else {
                        Color::Red
                    }),
                    result.f2_result.to_string().color(if result.f2_result {
                        Color::Green
                    } else {
                        Color::Red
                    })
                );
                println!(
                    "   {}",
                    "At least one script check failed for the chosen flow.".red()
                );
            }
            println!("{}", "-------------------------------".bold().blue());
        }
        Err(e) => {
            // Handle potential errors during simulation setup or execution
            eprintln!("\n{}", "--- Simulation Error ---".bold().red());
            eprintln!("{} {}", "Error:".red(), e);
            eprintln!("{}", "------------------------".bold().red());
            std::process::exit(1); // Exit with error code
        }
    }
}
