use std::{fs, path::Path};
use clap::Parser;
use anyhow::Result;
use env_logger::Env;

// Import our modules
use zk_recursive::utils::circuit_stats::print_circuit_stats;
use zk_recursive::commands::{inner, outer, experiments};

/// Command-line arguments for the zk-recursive proof generator
#[derive(Parser)]
#[command(name = "zk-recursive")]
#[command(about = "Generate recursive ZK-SNARK proofs")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
    
    #[arg(short, long, default_value = "build", help = "Output directory for artifacts")]
    output_dir: String,
}

/// Available circuit types and proof generation commands
#[derive(Parser)]
enum Commands {
    /// Build circuit for C1 - C3, generate proof and verify
    Inner {
        #[arg(short, long, help = "Input JSON file with inner proof data")]
        input: String,
    },
    /// Build inner circuit and outer circuit for C4 and inner proof verification, generate inner and outer proofs and verify 
    Outer {
        #[arg(short, long, help = "Input JSON file with outer proof data")]
        input: String,
    },
    /// Experimental: Build circuit for C1 and C2, generate proof and verify
    ExpInnerKeyDer {
        #[arg(short, long, help = "Input JSON file with inner proof data")]
        input: String,
    },
    /// Experimental: Build experimental inner key derivation circuit and outer circuit for C4 and inner proof verification, generate inner and outer proofs and verify
    ExpOuterKeyDer {
        #[arg(short, long, help = "Input JSON file with outer proof data")]
        input: String,
    },
    /// Experimental: Build circuit for C3, generate proof and verify
    ExpInnerSigVerify {
        #[arg(short, long, help = "Input JSON file with inner proof data")]
        input: String,
    },
    /// Experimental: Build experimental inner signature verification circuit and outer circuit for C4 and inner proof verification, generate inner and outer proofs and verify
    ExpOuterSigVerify {
        #[arg(short, long, help = "Input JSON file with outer proof data")]
        input: String,
    },
}

fn main() -> Result<()> {
    // Initialize logger for TimingTree output
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    let args = Args::parse();
    use std::time::Instant;
    
    println!("=== ZK-RECURSIVE PLONKY2 PROOF SYSTEM ===");
    let total_start = Instant::now();
    
    // Create output directory for artifacts
    let build_dir = Path::new(&args.output_dir);
    if !build_dir.exists() {
        fs::create_dir_all(build_dir).expect("Failed to create output directory");
    }
    
    // Execute based on command
    match args.command {
        Some(Commands::Inner { input }) => {
            use zk_recursive::build_inner_circuit;
            println!("\nBuilding Inner (EUDI Credential Binding) circuit...");
            let inner_start = Instant::now();
            let inner = build_inner_circuit();
            let inner_total = inner_start.elapsed();
            println!("Inner circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner", &inner.data.common);
            
            println!("\n=== GENERATING INNER PROOF ===");
            inner::generate_inner_proof(&inner, &input, &build_dir)?;
        },
        Some(Commands::Outer { input }) => {
            use zk_recursive::{build_inner_circuit, build_outer_circuit};
            println!("\nBuilding outer circuits...");
            let inner_start = Instant::now();
            let inner = build_inner_circuit();
            let inner_total = inner_start.elapsed();
            println!("Inner circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner", &inner.data.common);
            
            let outer_start = Instant::now();
            let outer = build_outer_circuit(&inner.data.common);
            let outer_total = outer_start.elapsed();
            println!("Outer circuit build time: {:?}", outer_total);
            print_circuit_stats("Outer", &outer.data.common);

            println!("\n=== GENERATING OUTER PROOF ===");
            outer::generate_outer_proof(&inner, &outer, &input, &build_dir)?;
        },
        Some(Commands::ExpInnerKeyDer { input }) => {
            use zk_recursive::circuits::experiments::build_inner_key_der_circuit;
            println!("\nBuilding experimental inner key derivation circuit...");
            let inner_start = Instant::now();
            let inner = build_inner_key_der_circuit();
            let inner_total = inner_start.elapsed();
            println!("Experimental inner key derivation circuit build time: {:?}", inner_total);
            print_circuit_stats("Experimental Inner Key Derivation", &inner.data.common);
            
            println!("\n=== GENERATING EXPERIMENTAL INNER KEY DERIVATION PROOF ===");
            experiments::generate_exp_inner_key_der_proof(&inner, &input, &build_dir)?;
        },
        Some(Commands::ExpOuterKeyDer { input }) => {
            use zk_recursive::circuits::experiments::{build_inner_key_der_circuit, build_outer_key_der_circuit};
            println!("\nBuilding experimental recursive key derivation circuits...");
            let inner_start = Instant::now();
            let inner = build_inner_key_der_circuit();
            let inner_total = inner_start.elapsed();
            println!("Experimental inner key derivation circuit build time: {:?}", inner_total);
            print_circuit_stats("Experimental Inner Key Derivation", &inner.data.common);
            
            let outer_start = Instant::now();
            let outer = build_outer_key_der_circuit(&inner.data.common);
            let outer_total = outer_start.elapsed();
            println!("Experimental outer key derivation circuit build time: {:?}", outer_total);
            print_circuit_stats("Experimental Outer Key Derivation", &outer.data.common);
            
            println!("\n=== GENERATING EXPERIMENTAL RECURSIVE KEY DERIVATION PROOF ===");
            experiments::generate_exp_outer_key_der_proof(&inner, &outer, &input, &build_dir)?;
        },
        Some(Commands::ExpInnerSigVerify { input }) => {
            use zk_recursive::circuits::experiments::build_inner_sig_verify_circuit;
            println!("\nBuilding experimental inner signature verification circuit...");
            let inner_start = Instant::now();
            let inner = build_inner_sig_verify_circuit();
            let inner_total = inner_start.elapsed();
            println!("Experimental inner signature verification circuit build time: {:?}", inner_total);
            print_circuit_stats("Experimental Inner Signature Verification", &inner.data.common);
            
            println!("\n=== GENERATING EXPERIMENTAL INNER SIGNATURE VERIFICATION PROOF ===");
            experiments::generate_exp_inner_sig_verify_proof(&inner, &input, &build_dir)?;
        },
        Some(Commands::ExpOuterSigVerify { input }) => {
            use zk_recursive::circuits::experiments::{build_inner_sig_verify_circuit, build_outer_sig_verify_circuit};
            println!("\nBuilding experimental recursive signature verification circuits...");
            let inner_start = Instant::now();
            let inner = build_inner_sig_verify_circuit();
            let inner_total = inner_start.elapsed();
            println!("Experimental inner signature verification circuit build time: {:?}", inner_total);
            print_circuit_stats("Experimental Inner Signature Verification", &inner.data.common);
            
            let outer_start = Instant::now();
            let outer = build_outer_sig_verify_circuit(&inner.data.common);
            let outer_total = outer_start.elapsed();
            println!("Experimental outer signature verification circuit build time: {:?}", outer_total);
            print_circuit_stats("Experimental Outer Signature Verification", &outer.data.common);
            
            println!("\n=== GENERATING EXPERIMENTAL RECURSIVE SIGNATURE VERIFICATION PROOF ===");
            experiments::generate_exp_outer_sig_verify_proof(&inner, &outer, &input, &build_dir)?;
        },
        None => {
            println!("\nNo command specified. Available subcommands:");
            println!("Main circuits:");
            println!("  inner  - Inner circuit (C1 + C3: key derivation + signature verification)");
            println!("  outer  - Outer circuit (C2 + recursive verification of inner proof)");
            println!("Experimental circuits:");
            println!("  exp-inner-key-der     - Inner key derivation only (C1 and C2)");
            println!("  exp-inner-sig-verify  - Inner signature verification only (C3)");
            println!("  exp-outer-key-der     - Outer recursive key derivation");
            println!("  exp-outer-sig-verify  - Outer recursive signature verification");
            println!("Commands:");
            println!("  cargo run --release --bin zk-recursive -- inner --input inputs/outer.json");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/outer.json");
            println!("  cargo run --release --bin zk-recursive -- exp-inner-key-der --input inputs/experiments/outer_key_der.json");
            println!("  cargo run --release --bin zk-recursive -- exp-outer-key-der --input inputs/experiments/outer_key_der.json");
            println!("  cargo run --release --bin zk-recursive -- exp-inner-sig-verify --input inputs/experiments/outer_sig_verify.json");
            println!("  cargo run --release --bin zk-recursive -- exp-outer-sig-verify --input inputs/experiments/outer_sig_verify.json");
        }
    }
    
    println!("\nTotal execution time: {:?}", total_start.elapsed());
    println!("Artifacts saved to: {}", build_dir.display());
    println!("=== EXECUTION COMPLETE ===");
    
    Ok(())
}