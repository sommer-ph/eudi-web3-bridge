use std::{fs, path::Path};
use clap::Parser;
use anyhow::Result;
use env_logger::Env;

use zk_recursive::utils::circuit_stats::print_circuit_stats;
use zk_recursive::commands::{inner, outer, inner_extended, outer_extended, experiments};

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
    /// Build inner extended circuit for C1 - C4, generate proof and verify
    InnerExtended {
        #[arg(short, long, help = "Input JSON file with inner extended proof data")]
        input: String,
    },
    /// Build inner extended circuit and outer extended circuit for C5 and inner extended proof verification, generate inner extended and outer extended proofs and verify
    OuterExtended {
        #[arg(short, long, help = "Input JSON file with outer extended proof data")]
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
    /// Experimental: Build circuit for C3 with static public key, generate proof and verify
    ExpInnerSigVerifyStatic {
        #[arg(short, long, help = "Input JSON file with inner signature verification (static PK) data")]
        input: String,
    },
    /// Experimental: Build experimental inner signature verification circuit and outer circuit for C4 and inner proof verification, generate inner and outer proofs and verify
    ExpOuterSigVerify {
        #[arg(short, long, help = "Input JSON file with outer proof data")]
        input: String,
    },
    /// Experimental: Build BIP32 key derivation circuit, generate proof and verify
    ExpBip32KeyDer {
        #[arg(short, long, help = "Input JSON file with BIP32 key derivation data")]
        input: String,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    let args = Args::parse();
    use std::time::Instant;
    
    println!("=== ZK-RECURSIVE PLONKY2 PROOF SYSTEM ===");
    let total_start = Instant::now();
    
    let build_dir = Path::new(&args.output_dir);
    if !build_dir.exists() {
        fs::create_dir_all(build_dir).expect("Failed to create output directory");
    }
    
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
        Some(Commands::InnerExtended { input }) => {
            use zk_recursive::circuits::inner_extended::build_inner_extended_circuit;
            println!("\nBuilding inner extended circuit...");
            let inner_extended_start = Instant::now();
            let inner_extended = build_inner_extended_circuit();
            let inner_extended_total = inner_extended_start.elapsed();
            println!("Inner extended circuit build time: {:?}", inner_extended_total);
            print_circuit_stats("Inner Extended", &inner_extended.data.common);
            
            println!("\n=== GENERATING INNER EXTENDED PROOF ===");
            inner_extended::generate_inner_extended_proof(&inner_extended, &input, &build_dir)?;
        },
        Some(Commands::OuterExtended { input }) => {
            use zk_recursive::circuits::{inner_extended::build_inner_extended_circuit, outer_extended::build_outer_extended_circuit};
            println!("\nBuilding outer extended circuits...");
            let inner_extended_start = Instant::now();
            let inner_extended = build_inner_extended_circuit();
            let inner_extended_total = inner_extended_start.elapsed();
            println!("Inner extended circuit build time: {:?}", inner_extended_total);
            print_circuit_stats("Inner Extended", &inner_extended.data.common);
            
            let outer_extended_start = Instant::now();
            let outer_extended = build_outer_extended_circuit(&inner_extended.data.common);
            let outer_extended_total = outer_extended_start.elapsed();
            println!("Outer extended circuit build time: {:?}", outer_extended_total);
            print_circuit_stats("Outer Extended", &outer_extended.data.common);

            println!("\n=== GENERATING OUTER EXTENDED RECURSIVE PROOF ===");
            outer_extended::generate_outer_extended_proof(&inner_extended, &outer_extended, &input, &build_dir)?;
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
        Some(Commands::ExpInnerSigVerifyStatic { input }) => {
            use zk_recursive::circuits::experiments::build_inner_sig_verify_static_circuit;
            println!("\nBuilding experimental inner signature verification circuit (static PK)...");
            let inner_start = Instant::now();
            let inner = build_inner_sig_verify_static_circuit();
            let inner_total = inner_start.elapsed();
            println!("Experimental inner signature verification circuit (static PK) build time: {:?}", inner_total);
            print_circuit_stats("Experimental Inner Signature Verification (Static PK)", &inner.data.common);
            
            println!("\n=== GENERATING EXPERIMENTAL INNER SIGNATURE VERIFICATION PROOF (STATIC PK) ===");
            experiments::generate_exp_inner_sig_verify_static_proof(&inner, &input, &build_dir)?;
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
        Some(Commands::ExpBip32KeyDer { input }) => {
            use zk_recursive::circuits::experiments::build_bip32_key_der_circuit;
            println!("\nBuilding experimental BIP32 key derivation circuit...");
            let circuit_start = Instant::now();
            let circuit = build_bip32_key_der_circuit();
            let circuit_total = circuit_start.elapsed();
            println!("Experimental BIP32 key derivation circuit build time: {:?}", circuit_total);
            print_circuit_stats("Experimental BIP32 Key Derivation", &circuit.data.common);
            
            println!("\n=== GENERATING EXPERIMENTAL BIP32 KEY DERIVATION PROOF ===");
            experiments::generate_exp_bip32_key_der_proof(&circuit, &input, &build_dir)?;
        },
        None => {
            println!("\nNo command specified. Available commands:");
            println!("  cargo run --release --bin zk-recursive -- inner --input inputs/outer.json");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/outer.json");
            println!("  cargo run --release --bin zk-recursive -- inner-extended --input inputs/outer_extended.json");
            println!("  cargo run --release --bin zk-recursive -- outer-extended --input inputs/outer_extended.json");
            println!("  cargo run --release --bin zk-recursive -- exp-inner-key-der --input inputs/experiments/outer_key_der.json");
            println!("  cargo run --release --bin zk-recursive -- exp-outer-key-der --input inputs/experiments/outer_key_der.json");
            println!("  cargo run --release --bin zk-recursive -- exp-inner-sig-verify --input inputs/experiments/outer_sig_verify.json");
            println!("  cargo run --release --bin zk-recursive -- exp-inner-sig-verify-static --input inputs/experiments/inner_sig_verify_static.json");
            println!("  cargo run --release --bin zk-recursive -- exp-outer-sig-verify --input inputs/experiments/outer_sig_verify.json");
            println!("  cargo run --release --bin zk-recursive -- exp-bip32-key-der --input inputs/experiments/bip32_key_der.json");
        }
    }
    
    println!("\nTotal execution time: {:?}", total_start.elapsed());
    println!("Artifacts saved to: {}", build_dir.display());
    println!("=== EXECUTION COMPLETE ===");
    
    Ok(())
}