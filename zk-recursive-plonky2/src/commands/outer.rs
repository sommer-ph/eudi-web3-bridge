//! Outer circuit proof generation command.

use anyhow::Result;
use std::{fs, path::Path, time::Instant};
use plonky2::field::{secp256k1_scalar::Secp256K1Scalar, types::{Field, PrimeField}};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use crate::types::input::OuterProofInput;
use crate::utils::parsing::{hex_to_bigint, set_nonnative_target};
use crate::commands::inner::generate_inner_proof;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Generate outer recursive proof (includes inner proof generation)
pub fn generate_outer_proof(
    inner: &crate::InnerCircuit,
    outer: &crate::OuterCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let total_start = Instant::now();
    
    // First generate inner proof
    println!("=== INNER PROOF ===");
    generate_inner_proof(inner, input_file, build_dir)?;
    
    // Load the generated inner proof
    println!("=== OUTER RECURSIVE PROOF ===");
    println!("Loading inner proof artifacts...");
    let load_start = Instant::now();
    let inner_proof_data = fs::read(build_dir.join("inner_proof.bin"))?;
    let inner_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D> = 
        bincode::deserialize(&inner_proof_data)?;
    println!("Inner proof load + deserialization time: {:?}", load_start.elapsed());
    
    // Load input data
    println!("Loading outer input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterProofInput = serde_json::from_str(&input_data)?;
        
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
    pw.set_verifier_data_target(&outer.targets.vd, &inner.data.verifier_only)?;
    
    // Generate outer recursive proof
    println!("Generating outer recursive proof...");
    let proof_start = Instant::now();
    let proof = outer.data.prove(pw)?;
    let proof_time = proof_start.elapsed();
    println!("Outer recursive proof generation time: {:?}", proof_time);
    println!("Outer recursive proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer recursive proof
    println!("Verifying outer recursive proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer recursive proof verification time: {:?}", verify_start.elapsed());
        
    // Save both proofs
    println!("\nSerializing and saving proofs...");
    let save_start = Instant::now();
    let outer_proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("outer_proof.bin"), &outer_proof_data)?;
    println!("Proof serialization + save time: {:?}", save_start.elapsed());
    println!("Outer proof saved: {} bytes", outer_proof_data.len());
    
    println!("Total recursive proof system time: {:?}", total_start.elapsed());
    
    Ok(())
}