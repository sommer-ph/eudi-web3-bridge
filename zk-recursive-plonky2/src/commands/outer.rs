//! Outer circuit proof generation command.

use anyhow::Result;
use log::Level;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;
use std::{fs, path::Path, time::Instant};
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use crate::types::input::{FullInput, SignatureMode};
use crate::utils::parsing::hex_to_bigint;
use crate::circuits::outer::OuterCircuit;
use crate::circuits::inner::InnerCircuit;
use crate::commands::inner::generate_inner_proof;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Generate outer recursive proof (includes inner proof generation)
pub fn generate_outer_proof(
    inner: &InnerCircuit,
    outer: &OuterCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let total_start = Instant::now();
    
    let inner_signature_mode_str = match outer.inner_signature_mode {
        SignatureMode::Static => "STATIC PK",
        SignatureMode::Dynamic => "DYNAMIC PK",
    };
    
    // First generate inner proof
    println!("=== INNER PROOF GENERATION ({}) ===", inner_signature_mode_str);
    generate_inner_proof(inner, input_file, build_dir)?;
    
    // Load the generated inner proof
    println!("\n=== OUTER RECURSIVE PROOF ===");
    println!("Loading inner proof artifacts...");
    let load_start = Instant::now();
    let inner_proof_data = fs::read(build_dir.join("inner_proof.bin"))?;
    let inner_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D> = 
        bincode::deserialize(&inner_proof_data)?;
    println!("Inner proof load + deserialization time: {:?}", load_start.elapsed());
    
    // Load input data
    println!("Loading outer input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: FullInput = serde_json::from_str(&input_data)?;
    
    println!("Setting up outer circuit witness...");
    let witness_start = Instant::now();
        
    // Parse parent data for BIP32 Key Derivation (C5)
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    
    // Parse parent chain code
    let cc_0_hex = hex_to_bigint(&input.cc_0);
    let mut cc_0 = [0u8; 32];
    let cc_0_bytes = cc_0_hex.to_bytes_be();
    let len = cc_0_bytes.len().min(32);
    cc_0[32-len..].copy_from_slice(&cc_0_bytes[..len]);
    
    // Parse derivation index
    let derivation_index = input.derivation_index;
    
    // Parse expected child outputs (should be public inputs per your design)
    let pk_i_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.x));
    let pk_i_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.y));
    
    let cc_i_hex = hex_to_bigint(&input.cc_i);
    let mut cc_i = [0u8; 32];
    let cc_i_bytes = cc_i_hex.to_bytes_be();
    let cc_len = cc_i_bytes.len().min(32);
    cc_i[32-cc_len..].copy_from_slice(&cc_i_bytes[..cc_len]);
    
    // ===== SET UP CIRCUIT WITNESSES =====
    
    let mut pw = PartialWitness::<F>::new();
    
    // Set recursive proof data - verifies inner proof (C1-C4)
    pw.set_proof_with_pis_target(&outer.targets.proof, &inner_proof)?;
    pw.set_verifier_data_target(&outer.targets.vd, &inner.data.verifier_only)?;
        
    // C5: BIP32 Key Derivation - Set parent public key (assuming this should be private input)
    pw.set_biguint_target(&outer.targets.bip32_targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.bip32_targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    
    // Set parent chain code (bits)
    let cc_0_bits: Vec<bool> = cc_0.iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    for (i, &bit) in cc_0_bits.iter().enumerate() {
        pw.set_bool_target(outer.targets.bip32_targets.cc_0[i], bit)?;
    }
    
    // Set child index bits
    let derivation_index_bits: Vec<bool> = (0..32).rev()
        .map(|i| (derivation_index >> i) & 1 == 1)
        .collect();
    for (i, &bit) in derivation_index_bits.iter().enumerate() {
        pw.set_bool_target(outer.targets.bip32_targets.derivation_index[i], bit)?;
    }
    
    // Set expected child public key
    pw.set_biguint_target(&outer.targets.bip32_targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.bip32_targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
    
    // Set expected child chain code
    let cc_i_bits: Vec<bool> = cc_i.iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    for (i, &bit) in cc_i_bits.iter().enumerate() {
        pw.set_bool_target(outer.targets.bip32_targets.cc_i[i], bit)?;
    }
    
    println!("Outer witness setup time: {:?}", witness_start.elapsed());
    
    // Generate outer recursive proof
    println!("Generating outer recursive proof (Inner: {})...", inner_signature_mode_str);
    let mut timing = TimingTree::new("outer_recursive_proof", Level::Info);
    let proof = prove(&outer.data.prover_only, &outer.data.common, pw, &mut timing)?;
    println!("Outer recursive proof timing breakdown:");
    timing.print();
    println!("Outer recursive proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer recursive proof
    println!("Verifying outer recursive proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer recursive proof verification time: {:?}", verify_start.elapsed());
        
    // Save outer proof
    println!("Serializing and saving outer proof...");
    let save_start = Instant::now();
    let outer_proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("outer_proof.bin"), &outer_proof_data)?;
    println!("Outer proof serialization + save time: {:?}", save_start.elapsed());
    println!("Outer proof saved: {} bytes", outer_proof_data.len());
    
    println!("\n=== PERFORMANCE SUMMARY ===");
    println!("Total recursive proof system time: {:?}", total_start.elapsed());
    println!("=== OUTER UNIFIED RECURSIVE PROOF COMPLETE (Inner: {}) ===", inner_signature_mode_str);
    
    Ok(())
}