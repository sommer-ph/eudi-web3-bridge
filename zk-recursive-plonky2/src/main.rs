use std::{fs, path::Path};
use clap::Parser;
use anyhow::Result;
use env_logger::Env;

use zk_recursive::utils::circuit_stats::print_circuit_stats;
use zk_recursive::types::input::{SignatureMode, DerivationMode};

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

/// Command structure with inner, outer, and serial commands
#[derive(Parser)]
enum Commands {
    /// Build inner circuit (C1-C4) and generate proof
    Inner {
        #[arg(short, long, help = "Input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Signature verification mode: static or dynamic")]
        sig_mode: String,
    },
    /// Build inner-extended circuit (C1-C4 + msg/pk binding) and generate proof
    InnerExtended {
        #[arg(short, long, help = "Extended input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Signature verification mode: static or dynamic")]
        sig_mode: String,
    },
    /// Build outer circuit with recursive verification and BIP32 key derivation
    Outer {
        #[arg(short, long, help = "Input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Inner signature verification mode: static or dynamic")]
        inner_sig_mode: String,
        #[arg(long, default_value = "sha512", help = "Outer derivation mode: sha512 or poseidon")]
        outer_derive_mode: String,
    },
    /// Build outer-extended circuit (verifies inner-extended) and generate proof
    OuterExtended {
        #[arg(short, long, help = "Extended input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Inner signature verification mode: static or dynamic")]
        inner_sig_mode: String,
        #[arg(long, default_value = "sha512", help = "Outer derivation mode: sha512 or poseidon")]
        outer_derive_mode: String,
    },
    /// Generate serial recursive proof (C1_2 -> C3 -> C4 -> C5)
    Serial {
        #[arg(short, long, help = "Input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Signature verification mode: static or dynamic")]
        sig_mode: String,
        #[arg(long, default_value = "sha512", help = "Derivation mode for C5: sha512 or poseidon")]
        der_mode: String,
    },
    /// Generate parallel recursive proof (C1_2, C3, C4 in parallel -> C5)
    Parallel {
        #[arg(short, long, help = "Input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Signature verification mode: static or dynamic")]
        sig_mode: String,
        #[arg(long, default_value = "sha512", help = "Derivation mode for C5: sha512 or poseidon")]
        der_mode: String,
    },
    /// Generate combined proof: SHA-256(header '.' payload) == msg AND payload pk == pk_c
    MsgPkCBinding {
        #[arg(short, long, help = "Extended input JSON with header/payload and offsets")]
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
        Some(Commands::Inner { input, sig_mode }) => {
            use zk_recursive::circuits::inner::build_inner_circuit;
            
            let signature_mode = match sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid signature mode: {}. Use 'static' or 'dynamic'", sig_mode);
                    std::process::exit(1);
                }
            };
            
            println!("\nBuilding Inner Circuit (C1-C4) with {} signature verification...", sig_mode);
            let inner_start = Instant::now();
            let inner = build_inner_circuit(signature_mode);
            let inner_total = inner_start.elapsed();
            println!("Inner circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner", &inner.data.common);
            
            println!("\n=== GENERATING INNER PROOF ===");
            use zk_recursive::commands::inner::generate_inner_proof;
            generate_inner_proof(&inner, &input, &build_dir)?;
        },
        Some(Commands::Outer { input, inner_sig_mode, outer_derive_mode }) => {
            use zk_recursive::circuits::{inner::build_inner_circuit, outer::build_outer_circuit};
            
            let signature_mode = match inner_sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid inner signature mode: {}. Use 'static' or 'dynamic'", inner_sig_mode);
                    std::process::exit(1);
                }
            };
            
            let derivation_mode = match outer_derive_mode.as_str() {
                "sha512" => DerivationMode::Sha512,
                "poseidon" => DerivationMode::Poseidon,
                _ => {
                    eprintln!("Invalid outer derivation mode: {}. Use 'sha512' or 'poseidon'", outer_derive_mode);
                    std::process::exit(1);
                }
            };
            
            println!("\nBuilding Recursive Circuits with {} inner signature verification and {} derivation mode...", inner_sig_mode, outer_derive_mode);
            let inner_start = Instant::now();
            let inner = build_inner_circuit(signature_mode.clone());
            let inner_total = inner_start.elapsed();
            println!("Inner circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner", &inner.data.common);
            
            let outer_start = Instant::now();
            let outer = build_outer_circuit(&inner.data.common, signature_mode, derivation_mode);
            let outer_total = outer_start.elapsed();
            println!("Outer circuit build time: {:?}", outer_total);
            print_circuit_stats("Outer", &outer.data.common);

            println!("\n=== GENERATING RECURSIVE PROOF ===");
            use zk_recursive::commands::outer::generate_outer_proof;
            generate_outer_proof(&inner, &outer, &input, &build_dir)?;
        },
        Some(Commands::InnerExtended { input, sig_mode }) => {
            use zk_recursive::commands::inner_extended::generate_inner_extended_proof;
            use zk_recursive::circuits::inner_extended::build_inner_extended_circuit;
            let signature_mode = match sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid signature mode: {}. Use 'static' or 'dynamic'", sig_mode);
                    std::process::exit(1);
                }
            };

            println!("\nBuilding Inner-Extended Circuit with {} signature verification...", sig_mode);
            let inner_start = Instant::now();
            let inner = build_inner_extended_circuit(signature_mode.clone());
            let inner_total = inner_start.elapsed();
            println!("Inner-extended circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner-Extended", &inner.data.common);

            println!("\n=== GENERATING INNER-EXTENDED PROOF ===");
            generate_inner_extended_proof(&inner, &input, &build_dir)?;
        },
        Some(Commands::OuterExtended { input, inner_sig_mode, outer_derive_mode }) => {
            use zk_recursive::commands::{inner_extended::generate_inner_extended_proof, outer_extended::generate_outer_extended_proof};
            use zk_recursive::circuits::{inner_extended::build_inner_extended_circuit, outer_extended::build_outer_extended_circuit};
            let signature_mode = match inner_sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid inner signature mode: {}. Use 'static' or 'dynamic'", inner_sig_mode);
                    std::process::exit(1);
                }
            };
            let derivation_mode = match outer_derive_mode.as_str() {
                "sha512" => DerivationMode::Sha512,
                "poseidon" => DerivationMode::Poseidon,
                _ => {
                    eprintln!("Invalid derivation mode: {}. Use 'sha512' or 'poseidon'", outer_derive_mode);
                    std::process::exit(1);
                }
            };

            println!("\nBuilding Recursive Extended Circuits with {} inner signature verification and {} derivation mode...", inner_sig_mode, outer_derive_mode);
            let inner_start = Instant::now();
            let inner = build_inner_extended_circuit(signature_mode.clone());
            let inner_total = inner_start.elapsed();
            println!("Inner-extended circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner-Extended", &inner.data.common);

            let outer_start = Instant::now();
            let outer = build_outer_extended_circuit(&inner.data.common, signature_mode.clone(), derivation_mode.clone());
            let outer_total = outer_start.elapsed();
            println!("Outer-extended circuit build time: {:?}", outer_total);
            print_circuit_stats("Outer-Extended", &outer.data.common);

            println!("\n=== GENERATING INNER-EXTENDED PROOF ===");
            generate_inner_extended_proof(&inner, &input, &build_dir)?;

            println!("\n=== GENERATING OUTER-EXTENDED RECURSIVE PROOF ===");
            generate_outer_extended_proof(&inner, &outer, &input, &build_dir)?;
        },
        Some(Commands::Serial { input, sig_mode, der_mode }) => {
            use zk_recursive::commands::serial_recursion::{build_serial_circuits, generate_serial_recursive_proof};
            
            let signature_mode = match sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid signature mode: {}. Use 'static' or 'dynamic'", sig_mode);
                    std::process::exit(1);
                }
            };
            
            let derivation_mode = match der_mode.as_str() {
                "sha512" => DerivationMode::Sha512,
                "poseidon" => DerivationMode::Poseidon,
                _ => {
                    eprintln!("Invalid derivation mode: {}. Use 'sha512' or 'poseidon'", der_mode);
                    std::process::exit(1);
                }
            };
            
            println!("\nBuilding Serial Recursive Circuits with {} signature verification and {} derivation mode...", sig_mode, der_mode);
            let circuits_start = Instant::now();
            let circuits = build_serial_circuits(signature_mode, derivation_mode);
            let circuits_total = circuits_start.elapsed();
            println!("Serial circuits build time: {:?}", circuits_total);
            
            // Print circuit stats for each step
            print_circuit_stats("C1_2", &circuits.c1_2.data.common);
            print_circuit_stats("C3", &circuits.c3.data.common);
            print_circuit_stats("C4", &circuits.c4.data.common);
            print_circuit_stats("C5", &circuits.c5.data.common);
            
            println!("\n=== GENERATING SERIAL RECURSIVE PROOF ===");
            generate_serial_recursive_proof(&circuits, &input, &build_dir)?;
        },
        Some(Commands::Parallel { input, sig_mode, der_mode }) => {
            use zk_recursive::commands::parallel_recursion::{build_parallel_circuits, generate_parallel_recursive_proof};
            
            let signature_mode = match sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid signature mode: {}. Use 'static' or 'dynamic'", sig_mode);
                    std::process::exit(1);
                }
            };
            
            let derivation_mode = match der_mode.as_str() {
                "sha512" => DerivationMode::Sha512,
                "poseidon" => DerivationMode::Poseidon,
                _ => {
                    eprintln!("Invalid derivation mode: {}. Use 'sha512' or 'poseidon'", der_mode);
                    std::process::exit(1);
                }
            };
            
            println!("\nBuilding Parallel Recursive Circuits with {} signature verification and {} derivation mode...", sig_mode, der_mode);
            let circuits_start = Instant::now();
            let circuits = build_parallel_circuits(signature_mode, derivation_mode);
            let circuits_total = circuits_start.elapsed();
            println!("Parallel circuits build time: {:?}", circuits_total);
            
            // Print circuit stats for each step
            print_circuit_stats("C1_2", &circuits.c1_2.data.common);
            print_circuit_stats("C3", &circuits.c3.data.common);
            print_circuit_stats("C4", &circuits.c4.data.common);
            print_circuit_stats("C5", &circuits.c5.data.common);
            
            println!("\n=== GENERATING PARALLEL RECURSIVE PROOF ===");
            generate_parallel_recursive_proof(&circuits, &input, &build_dir)?;
        },
        Some(Commands::MsgPkCBinding { input }) => {
            use zk_recursive::commands::msg_pk_c_binding::generate_msg_pk_c_binding_proof;
            println!("\n=== GENERATING MSG+PK_C-BINDING PROOF ===");
            generate_msg_pk_c_binding_proof(&input, &build_dir)?;
        },
        None => {
            println!("\nNo command specified. Available commands:");
            println!("  cargo run --release --bin zk-recursive -- inner --input inputs/input.json --sig-mode dynamic");
            println!("  cargo run --release --bin zk-recursive -- inner --input inputs/input.json --sig-mode static");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/input.json --inner-sig-mode dynamic --outer-derive-mode sha512");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/input.json --inner-sig-mode dynamic --outer-derive-mode poseidon");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/input.json --inner-sig-mode static --outer-derive-mode sha512");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/input.json --inner-sig-mode static --outer-derive-mode poseidon");
            println!("  cargo run --release --bin zk-recursive -- msg-pk-c-binding --input inputs/input_extended.json");
            println!("  cargo run --release --bin zk-recursive -- inner-extended --input inputs/input_extended.json --sig-mode dynamic");
            println!("  cargo run --release --bin zk-recursive -- inner-extended --input inputs/input_extended.json --sig-mode static");
            println!("  cargo run --release --bin zk-recursive -- outer-extended --input inputs/input_extended.json --inner-sig-mode dynamic --outer-derive-mode sha512");
            println!("  cargo run --release --bin zk-recursive -- outer-extended --input inputs/input_extended.json --inner-sig-mode dynamic --outer-derive-mode poseidon");
            println!("  cargo run --release --bin zk-recursive -- outer-extended --input inputs/input_extended.json --inner-sig-mode static --outer-derive-mode sha512");
            println!("  cargo run --release --bin zk-recursive -- outer-extended --input inputs/input_extended.json --inner-sig-mode static --outer-derive-mode poseidon");
            println!("  cargo run --release --bin zk-recursive -- serial --input inputs/input.json --sig-mode dynamic --der-mode sha512");
            println!("  cargo run --release --bin zk-recursive -- serial --input inputs/input.json --sig-mode static --der-mode poseidon");
            println!("  cargo run --release --bin zk-recursive -- parallel --input inputs/input.json --sig-mode dynamic --der-mode sha512");
            println!("  cargo run --release --bin zk-recursive -- parallel --input inputs/input.json --sig-mode static --der-mode poseidon");
        }
    }
    
    println!("\nTotal execution time: {:?}", total_start.elapsed());
    println!("Artifacts saved to: {}", build_dir.display());
    println!("=== EXECUTION COMPLETE ===");
    
    Ok(())
}
