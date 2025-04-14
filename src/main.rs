#![feature(proc_macro_hygiene)] // Required for bitvm scripts

mod collidervm_toy;
mod simulation;

use clap::{Parser, ValueEnum};
use collidervm_toy::{ColliderVmConfig, benchmark_hash_rate};
use colored::*; // Import the colored crate

#[derive(Parser)]
#[command(
    name = "ColliderVM Simulator",
    about = "A toy simulation of the ColliderVM protocol",
    version,
    long_about = None
)]
struct Cli {
    /// Input value to test (default: 114)
    #[arg(short, long, default_value = "114")]
    input: u32,

    /// Preset configuration to use
    #[arg(short, long, value_enum, default_value_t = Preset::Default)]
    preset: Preset,

    /// Number of signers (1-of-n honest for safety)
    #[arg(short, long)]
    signers: Option<usize>,

    /// Number of operators (1-of-m honest for liveness)
    #[arg(short, long)]
    operators: Option<usize>,

    /// Flow set size parameter L (set D size = 2^L)
    #[arg(short, long)]
    l_param: Option<usize>,

    /// Hash prefix bits parameter B
    #[arg(short, long)]
    b_param: Option<usize>,

    /// Number of subfunctions (fixed at 2 for the toy model)
    #[arg(short, long)]
    k_param: Option<usize>,

    /// Skip hash rate calibration and use the provided value
    #[arg(long)]
    hash_rate: Option<u64>,

    /// Disable hash rate calibration
    #[arg(long)]
    no_calibration: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum Preset {
    /// Default configuration (quick to run for demos)
    Default,

    /// Medium difficulty (10-15 seconds)
    Medium,

    /// Higher difficulty (~1 minute)
    Hard,

    /// Custom configuration (use with -n, -m, -l, -b, -k options)
    Custom,
}

/// Calculate an appropriate B parameter value given:
/// - hash_rate: The number of hashes per second the machine can perform
/// - l_param: The L parameter (size of set D = 2^L)
/// - target_seconds: How long we want the hash finding to take
fn calculate_b_param(hash_rate: u64, l_param: usize, target_seconds: f64) -> usize {
    // For a hash collision search with parameters L and B, we need to try
    // approximately 2^(B-L) hashes to find a match.
    // If we want this to take target_seconds, we need:
    // 2^(B-L) ≈ hash_rate * target_seconds
    // Taking log2 of both sides:
    // B-L ≈ log2(hash_rate * target_seconds)
    // Therefore: B ≈ L + log2(hash_rate * target_seconds)

    // Cap the target to prevent extremely long calculations
    let capped_target = target_seconds.min(120.0); // Maximum 2 minutes

    // We want to find a B such that 2^(B-L) hashes will take target_seconds
    // First, determine how many hashes we can do in target_seconds
    let hashes_in_target_time = hash_rate as f64 * capped_target;

    // To find B-L, we need the log base 2 of hashes_in_target_time
    let b_minus_l = hashes_in_target_time.log2().ceil() as usize;

    // Apply reasonable bounds (4 ≤ B-L ≤ 23)
    // This keeps maximum runtime under about 2 minutes on most systems
    let b_minus_l_bounded = b_minus_l.clamp(4, 23);

    // B = L + (B-L)
    l_param + b_minus_l_bounded
}

impl Preset {
    fn get_config(&self, hash_rate: u64) -> ColliderVmConfig {
        match self {
            Preset::Default => ColliderVmConfig {
                n: 3, // Number of signers
                m: 2, // Number of operators
                l: 4, // D set size = 2^L = 16 flows (Small for demo)
                b: 8, // B hash prefix bits (Small for demo)
                k: 2, // Number of subfunctions (F1 & F2)
            },
            Preset::Medium => {
                // Target ~10 seconds on this machine
                let l = 4; // Keep at 16 flows for the toy demo
                let target_seconds = 10.0;

                // Calculate b needed for this target time
                let b = calculate_b_param(hash_rate, l, target_seconds);

                ColliderVmConfig {
                    n: 3,
                    m: 2,
                    l,
                    b,
                    k: 2,
                }
            }
            Preset::Hard => {
                // Target ~60 seconds on this machine
                let l = 4; // Keep at 16 flows for the toy demo
                let target_seconds = 30.0;

                // Calculate b needed for this target time
                let b = calculate_b_param(hash_rate, l, target_seconds);

                // For Hard preset, intentionally make it 4x harder
                // by adding 2 more bits (each bit doubles difficulty)
                let b_harder = b + 2;

                ColliderVmConfig {
                    n: 3,
                    m: 2,
                    l,
                    b: b_harder,
                    k: 2,
                }
            }
            Preset::Custom => ColliderVmConfig {
                n: 3, // Will be overridden by CLI args
                m: 2, // Will be overridden by CLI args
                l: 4, // Will be overridden by CLI args
                b: 8, // Will be overridden by CLI args
                k: 2, // Will be overridden by CLI args
            },
        }
    }
}

/// Entry point for the ColliderVM toy simulation.
///
/// This executable demonstrates the core concepts of ColliderVM:
/// 1. Parses command line arguments to configure the simulation parameters.
/// 2. Defines the `ColliderVmConfig` parameters (n, m, L, B, k) based on presets or custom values.
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

    // Parse command line arguments using clap
    let cli = Cli::parse();
    let input_value = cli.input;

    // Calibrate hash rate if needed
    let hash_rate = if cli.no_calibration {
        // Use a default hash rate if calibration is disabled
        1_000_000 // 1M hashes/sec
    } else if let Some(rate) = cli.hash_rate {
        // Use user-provided hash rate if specified
        rate
    } else {
        // Run calibration to measure hash rate
        benchmark_hash_rate(2) // Run for 2 seconds
    };

    // Get the base configuration from the selected preset using the calibrated hash rate
    let mut config = cli.preset.get_config(hash_rate);

    // Override with custom values if provided
    if cli.preset == Preset::Custom {
        if let Some(n) = cli.signers {
            config.n = n;
        }
        if let Some(m) = cli.operators {
            config.m = m;
        }
        if let Some(l) = cli.l_param {
            config.l = l;
        }
        if let Some(b) = cli.b_param {
            config.b = b;
        }
        if let Some(k) = cli.k_param {
            config.k = k;
        }
    }

    // Display the simulation configuration being used
    println!("\n{}", "--- Simulation Configuration ---".bold().yellow());
    println!(
        "  Preset:                 {}",
        format!("{:?}", cli.preset).cyan()
    );
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
    println!(
        "  Measured Hash Rate:    {} hashes/sec",
        format!("{}", hash_rate).cyan()
    );
    println!("--------------------------------");

    // Calculate estimated time based on the calibrated hash rate
    let total_hashes = 1u64 << (config.b.saturating_sub(config.l));
    let estimated_seconds = total_hashes as f64 / hash_rate as f64;

    // Format time in a more readable way
    let time_display = if estimated_seconds < 1.0 {
        "less than 1 second".to_string()
    } else if estimated_seconds < 60.0 {
        format!("{:.1} seconds", estimated_seconds)
    } else if estimated_seconds < 3600.0 {
        format!(
            "{:.1} minutes ({:.0} seconds)",
            estimated_seconds / 60.0,
            estimated_seconds
        )
    } else {
        format!(
            "{:.1} hours ({:.1} minutes)",
            estimated_seconds / 3600.0,
            estimated_seconds / 60.0
        )
    };

    println!(
        "  Estimated time: {} @ {} hashes/sec",
        time_display,
        format!("{}", hash_rate).cyan()
    );

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
