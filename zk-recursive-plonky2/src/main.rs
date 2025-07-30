use zk_recursive::{build_inner_circuit, build_outer_circuit, build_outer_p256_circuit, build_outer_only_circuit};
use zk_recursive::{InnerProofInput, OuterProofInput};
use std::fs;
use std::path::Path;
use clap::Parser;
use anyhow::Result;
use plonky2::field::types::{PrimeField, PrimeField64, Field};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

#[derive(Parser)]
#[command(name = "zk-recursive")]
#[command(about = "Generate recursive ZK-SNARK proofs")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
    
    #[arg(short, long, default_value = "build", help = "Output directory for artifacts")]
    output_dir: String,
}

#[derive(Parser)]
enum Commands {
    /// Build inner circuit + generate inner proof + verify
    Inner {
        #[arg(short, long, help = "Input JSON file with inner proof data")]
        input: String,
    },
    /// Load inner artifacts + build outer circuit + generate outer proof + verify
    Outer {
        #[arg(short, long, help = "Input JSON file with outer proof data")]
        input: String,
    },
    /// Load inner artifacts + build P256 outer circuit + generate outer proof + verify
    OuterP256 {
        #[arg(short, long, help = "Input JSON file with outer proof data")]
        input: String,
    },
    /// Build outer-only circuit (no inner verification) + generate proof + verify
    OuterOnly {
        #[arg(short, long, help = "Input JSON file with outer proof data")]
        input: String,
    },
}

fn hex_to_bigint(hex_str: &str) -> num_bigint::BigUint {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    num_bigint::BigUint::parse_bytes(hex_clean.as_bytes(), 16)
        .expect("Invalid hex string")
}

fn set_nonnative_target<FF: PrimeField>(
    pw: &mut PartialWitness<F>,
    target: &plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<FF>,
    value: FF,
) -> Result<()>
where
    F: PrimeField64,
{
    pw.set_biguint_target(&target.value, &value.to_canonical_biguint())?;
    Ok(())
}

fn main() -> Result<()> {
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
            println!("\nBuilding Inner (EUDI Credential Binding) circuit...");
            let inner_start = Instant::now();
            println!("- Building circuit topology and constraints...");
            let topology_start = Instant::now();
            let inner = build_inner_circuit();
            println!("- Circuit topology build time: {:?}", topology_start.elapsed());
            
            println!("- Computing polynomial commitments and FRI parameters...");
            let commitment_start = Instant::now();
            let _degree = inner.data.common.degree();
            println!("- FRI commitment setup time: {:?}", commitment_start.elapsed());
            
            let inner_total = inner_start.elapsed();
            println!("Inner circuit total building time: {:?}", inner_total);
            println!("Inner circuit size: {} gates", inner.data.common.degree());
            
            // Save only inner verifier data (needed for outer proof)
            println!("Serializing inner verifier data...");
            let serialize_start = Instant::now();
            let inner_verifier_data = bincode::serialize(&inner.data.verifier_only).expect("Failed to serialize inner verifier data");
            println!("Inner verifier serialization time: {:?}", serialize_start.elapsed());
            
            println!("Writing inner verifier artifacts to disk...");
            let write_start = Instant::now();
            fs::write(build_dir.join("inner_verifier_only.bin"), &inner_verifier_data)
                .expect("Failed to write inner verifier data");
            println!("Inner verifier disk write time: {:?}", write_start.elapsed());
            println!("Inner verifier data saved: {} bytes", inner_verifier_data.len());
            
            println!("\n=== GENERATING INNER PROOF ===");
            generate_inner_proof(&inner, &input, &build_dir)?;
        },
        Some(Commands::Outer { input }) => {
            // Check that inner proof exists first
            let inner_proof_path = build_dir.join("inner_proof.bin");
            
            if !inner_proof_path.exists() {
                return Err(anyhow::anyhow!("Inner proof not found. Run 'inner' command first to generate it."));
            }
            
            // Build inner circuit once (needed for both CommonCircuitData and VerifierData)
            // Note: Plonky2's VerifierOnlyCircuitData cannot be serialized, so we must rebuild
            println!("\nBuilding inner circuit (needed for outer circuit)...");
            let inner_start = Instant::now();
            let inner = build_inner_circuit();
            println!("Inner circuit build time: {:?}", inner_start.elapsed());
            
            println!("\nBuilding outer circuit...");
            let outer_start = Instant::now();
            let outer = build_outer_circuit(&inner.data.common);
            let outer_total = outer_start.elapsed();
            println!("Outer circuit build time: {:?}", outer_total);
            
            println!("\n=== GENERATING OUTER PROOF ===");
            generate_outer_proof(&outer, &inner.data.verifier_only, &input, &build_dir)?;
        },
        Some(Commands::OuterP256 { input }) => {
            // Check that inner proof exists first
            let inner_proof_path = build_dir.join("inner_proof.bin");
            
            if !inner_proof_path.exists() {
                return Err(anyhow::anyhow!("Inner proof not found. Run 'inner' command first to generate it."));
            }
            
            // Build inner circuit once (needed for both CommonCircuitData and VerifierData)
            // Note: Plonky2's VerifierOnlyCircuitData cannot be serialized, so we must rebuild
            println!("\nBuilding inner circuit (needed for P256 outer circuit)...");
            let inner_start = Instant::now();
            let inner = build_inner_circuit();
            println!("Inner circuit build time: {:?}", inner_start.elapsed());
            
            println!("\nBuilding P256 outer circuit...");
            let outer_start = Instant::now();
            let outer = build_outer_p256_circuit(&inner.data.common);
            let outer_total = outer_start.elapsed();
            println!("P256 outer circuit build time: {:?}", outer_total);
            
            println!("\n=== GENERATING P256 OUTER PROOF ===");
            generate_outer_p256_proof(&outer, &inner.data.verifier_only, &input, &build_dir)?;
        },
        Some(Commands::OuterOnly { input }) => {
            println!("\nBuilding outer-only circuit (no inner verification)...");
            let outer_start = Instant::now();
            let outer = build_outer_only_circuit();
            let outer_total = outer_start.elapsed();
            println!("Outer-only circuit build time: {:?}", outer_total);
            println!("Outer-only circuit size: {} gates", outer.data.common.degree());
            
            println!("\n=== GENERATING OUTER-ONLY PROOF ===");
            generate_outer_only_proof(&outer, &input, &build_dir)?;
        },
        None => {
            println!("\nNo command specified. Use 'inner', 'outer', 'outer-p256', or 'outer-only' subcommands.");
            println!("Examples:");
            println!("  cargo run -- inner --input inputs/inner_input.json");
            println!("  cargo run -- outer --input inputs/outer_input.json");
            println!("  cargo run -- outer-p256 --input inputs/outer_input.json");
            println!("  cargo run -- outer-only --input inputs/outer_input.json");
        }
    }
    
    println!("\nTotal execution time: {:?}", total_start.elapsed());
    println!("Artifacts saved to: {}", build_dir.display());
    println!("=== EXECUTION COMPLETE ===");
    
    Ok(())
}

fn generate_inner_proof(
    inner: &zk_recursive::InnerCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    use std::time::Instant;
    
    println!("Loading inner input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: InnerProofInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse inner proof inputs
    let pk_i_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.x));
    let pk_i_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.y));
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));
    let pk_cred_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_cred.x));
    let pk_cred_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_cred.y));
    let sk_c = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_c));
    
    // Set up inner circuit witness
    let mut pw = PartialWitness::<F>::new();
    pw.set_biguint_target(&inner.targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.msg, msg)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.r, sig_r)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.s, sig_s)?;
    pw.set_biguint_target(&inner.targets.pk_cred.x.value, &pk_cred_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_cred.y.value, &pk_cred_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.sk_c, sk_c)?;
    
    // Generate inner proof
    println!("Generating inner proof...");
    let proof_start = Instant::now();
    
    println!("- Initializing prover data and polynomial interpolation...");
    let prover_init_start = Instant::now();
    let proof = inner.data.prove(pw)?;
    let prover_init_time = prover_init_start.elapsed();
    
    let proof_time = proof_start.elapsed();
    println!("- Prover initialization + proof generation time: {:?}", prover_init_time);
    println!("Inner proof total generation time: {:?}", proof_time);
    println!("Inner proof size: {} bytes", proof.to_bytes().len());
    
    // Verify inner proof
    println!("Verifying inner proof...");
    let verify_start = Instant::now();
    inner.data.verify(proof.clone())?;
    println!("Inner proof verification time: {:?}", verify_start.elapsed());
    
    // Save inner proof
    println!("Serializing and saving inner proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("inner_proof.bin"), &proof_data)?;
    println!("Inner proof serialization + save time: {:?}", save_start.elapsed());
    println!("Inner proof saved: {} bytes", proof_data.len());
    
    println!("Inner proof generation completed in: {:?}", start.elapsed());
    println!("Inner proof artifacts ready for outer circuit.");
    
    Ok(())
}

fn generate_outer_proof(
    outer: &zk_recursive::OuterCircuit,
    inner_verifier: &plonky2::plonk::circuit_data::VerifierOnlyCircuitData<Cfg, D>,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    use std::time::Instant;
    
    println!("Loading outer input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterProofInput = serde_json::from_str(&input_data)?;
    
    // Load inner proof artifacts
    println!("Loading inner proof artifacts...");
    let load_start = Instant::now();
    let inner_proof_data = fs::read(build_dir.join("inner_proof.bin"))
        .map_err(|_| anyhow::anyhow!("Inner proof not found. Run 'inner' command first."))?;
    let inner_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D> = 
        bincode::deserialize(&inner_proof_data)?;
    println!("Inner proof load + deserialization time: {:?}", load_start.elapsed());
    
    println!("Inner proof loaded: {} bytes", inner_proof_data.len());
    println!("Using pre-loaded inner verifier data (optimized path)");
    
    let start = Instant::now();
    
    // Parse outer proof inputs
    let sk0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk0));
    let pk0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk0.x));
    let pk0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk0.y));
    
    // Set up outer circuit witness
    let mut pw = PartialWitness::<F>::new();
    
    pw.set_biguint_target(&outer.targets.pk0.x.value, &pk0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.pk0.y.value, &pk0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &outer.targets.sk0, sk0)?;
    pw.set_proof_with_pis_target(&outer.targets.proof, &inner_proof)?;
    pw.set_verifier_data_target(&outer.targets.vd, &inner_verifier)?;
    
    // Generate outer proof
    println!("Generating outer recursive proof...");
    let proof_start = Instant::now();
    
    println!("- Initializing recursive prover and verifying inner proof...");
    let recursive_start = Instant::now();
    let proof = outer.data.prove(pw)?;
    let recursive_time = recursive_start.elapsed();
    
    let proof_time = proof_start.elapsed();
    println!("- Recursive prover + verification time: {:?}", recursive_time);
    println!("Outer proof total generation time: {:?}", proof_time);
    println!("Outer proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer proof
    println!("Verifying outer proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer proof verification time: {:?}", verify_start.elapsed());
    
    // Save outer proof
    println!("Serializing and saving outer proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("outer_proof.bin"), &proof_data)?;
    println!("Outer proof serialization + save time: {:?}", save_start.elapsed());
    println!("Outer proof saved: {} bytes", proof_data.len());
    
    println!("Outer proof generation completed in: {:?}", start.elapsed());
    println!("Recursive proof system complete!");
    
    Ok(())
}

fn generate_outer_p256_proof(
    outer: &zk_recursive::OuterP256Circuit,
    inner_verifier: &plonky2::plonk::circuit_data::VerifierOnlyCircuitData<Cfg, D>,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    use std::time::Instant;
    
    println!("Loading outer P256 input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterProofInput = serde_json::from_str(&input_data)?;
    
    // Load inner proof artifacts
    println!("Loading inner proof artifacts...");
    let load_start = Instant::now();
    let inner_proof_data = fs::read(build_dir.join("inner_proof.bin"))
        .map_err(|_| anyhow::anyhow!("Inner proof not found. Run 'inner' command first."))?;
    let inner_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D> = 
        bincode::deserialize(&inner_proof_data)?;
    println!("Inner proof load + deserialization time: {:?}", load_start.elapsed());
    
    println!("Inner proof loaded: {} bytes", inner_proof_data.len());
    println!("Using pre-loaded inner verifier data (optimized path)");
    
    let start = Instant::now();
    
    // Parse outer proof inputs (using P256Scalar instead of Secp256K1Scalar)
    let sk0 = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk0));
    let pk0_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk0.x));
    let pk0_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk0.y));
    
    // Set up outer P256 circuit witness
    let mut pw = PartialWitness::<F>::new();
    
    pw.set_biguint_target(&outer.targets.pk0.x.value, &pk0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.pk0.y.value, &pk0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &outer.targets.sk0, sk0)?;
    pw.set_proof_with_pis_target(&outer.targets.proof, &inner_proof)?;
    pw.set_verifier_data_target(&outer.targets.vd, &inner_verifier)?;
    
    // Generate outer P256 proof
    println!("Generating outer P256 recursive proof...");
    let proof_start = Instant::now();
    
    println!("- Initializing recursive prover and verifying inner proof...");
    let recursive_start = Instant::now();
    let proof = outer.data.prove(pw)?;
    let recursive_time = recursive_start.elapsed();
    
    let proof_time = proof_start.elapsed();
    println!("- Recursive prover + verification time: {:?}", recursive_time);
    println!("Outer P256 proof total generation time: {:?}", proof_time);
    println!("Outer P256 proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer P256 proof
    println!("Verifying outer P256 proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer P256 proof verification time: {:?}", verify_start.elapsed());
    
    // Save outer P256 proof
    println!("Serializing and saving outer P256 proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("outer_p256_proof.bin"), &proof_data)?;
    println!("Outer P256 proof serialization + save time: {:?}", save_start.elapsed());
    println!("Outer P256 proof saved: {} bytes", proof_data.len());
    
    println!("Outer P256 proof generation completed in: {:?}", start.elapsed());
    println!("Recursive P256 proof system complete!");
    
    Ok(())
}

fn generate_outer_only_proof(
    outer: &zk_recursive::OuterOnlyCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    use std::time::Instant;
    
    println!("Loading outer-only input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterProofInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse outer-only proof inputs
    let sk0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk0));
    let pk0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk0.x));
    let pk0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk0.y));
    
    // Set up outer-only circuit witness
    let mut pw = PartialWitness::<F>::new();
    
    pw.set_biguint_target(&outer.targets.pk0.x.value, &pk0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.pk0.y.value, &pk0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &outer.targets.sk0, sk0)?;
    
    // Generate outer-only proof
    println!("Generating outer-only proof...");
    let proof_start = Instant::now();
    
    println!("- Initializing prover for secp256k1 key derivation...");
    let proof_time_start = Instant::now();
    let proof = outer.data.prove(pw)?;
    let proof_generation_time = proof_time_start.elapsed();
    
    let proof_time = proof_start.elapsed();
    println!("- Key derivation proof generation time: {:?}", proof_generation_time);
    println!("Outer-only proof total generation time: {:?}", proof_time);
    println!("Outer-only proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer-only proof
    println!("Verifying outer-only proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer-only proof verification time: {:?}", verify_start.elapsed());
    
    // Save outer-only proof
    println!("Serializing and saving outer-only proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("outer_only_proof.bin"), &proof_data)?;
    println!("Outer-only proof serialization + save time: {:?}", save_start.elapsed());
    println!("Outer-only proof saved: {} bytes", proof_data.len());
    
    println!("Outer-only proof generation completed in: {:?}", start.elapsed());
    println!("Secp256k1 key derivation proof system complete!");
    
    Ok(())
}
