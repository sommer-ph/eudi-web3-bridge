//! Outer circuit proof generation command.

use anyhow::Result;
use std::{fs, path::Path, time::Instant};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2::plonk::circuit_data::CircuitData; 

use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use crate::types::input::FullInput;
use crate::utils::parsing::hex_to_bigint;
use crate::circuits::debug::DebugCircuit;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

fn print_env(tag: &str, data: &CircuitData<F, Cfg, D>) {
    println!("--- {tag} ENV ---");
    println!("CFG hasher    = {}", std::any::type_name::<<Cfg as GenericConfig<D>>::Hasher>());
    println!("CFG type      = {}", std::any::type_name::<Cfg>());
    println!("D             = {}", D);
    println!("degree_bits   = {}", data.common.degree_bits());
    println!("fri rate_bits = {}", data.common.config.fri_config.rate_bits);
    println!("num_challenges= {}", data.common.config.num_challenges);
    println!("verifier_only_digest = {:?}", data.verifier_only.circuit_digest);
}

pub fn generate_debug_proof(
    debug: &DebugCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    println!("Loading debug input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: FullInput = serde_json::from_str(&input_data)?;
    
    println!("Setting up debug circuit witness...");
    let witness_start = Instant::now();
        
    // Parse parent data for BIP32 Key Derivation (C5)
    let pk_0_x = hex_to_bigint(&input.pk_0.x);
    let pk_0_y = hex_to_bigint(&input.pk_0.y);
    
    // Parse parent chain code
    let cc_0_hex = hex_to_bigint(&input.cc_0);
    let mut cc_0 = [0u8; 32];
    let cc_0_bytes = cc_0_hex.to_bytes_be();
    let len = cc_0_bytes.len().min(32);
    cc_0[32-len..].copy_from_slice(&cc_0_bytes[..len]);
    
    // Parse derivation index
    let derivation_index = input.derivation_index;
    
    // Parse expected child outputs (should be public inputs per your design)
    let pk_i_x = hex_to_bigint(&input.pk_i.x);
    let pk_i_y = hex_to_bigint(&input.pk_i.y);
    
    let cc_i_hex = hex_to_bigint(&input.cc_i);
    let mut cc_i = [0u8; 32];
    let cc_i_bytes = cc_i_hex.to_bytes_be();
    let cc_len = cc_i_bytes.len().min(32);
    cc_i[32-cc_len..].copy_from_slice(&cc_i_bytes[..cc_len]);
    
    // ===== SET UP CIRCUIT WITNESSES =====
    
    let mut pw = PartialWitness::<F>::new();
            
    // C5: BIP32 Key Derivation - Set parent public key (assuming this should be private input)
    pw.set_biguint_target(&debug.targets.pk_0.x.value, &pk_0_x)?;
    pw.set_biguint_target(&debug.targets.pk_0.y.value, &pk_0_y)?;
    
    // Set parent chain code (bits)
    let cc_0_bits: Vec<bool> = cc_0.iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    for (i, &bit) in cc_0_bits.iter().enumerate() {
        pw.set_bool_target(debug.targets.cc_0[i], bit)?;
    }
    
    // Set child index bits
    let derivation_index_bits: Vec<bool> = (0..32).rev()
        .map(|i| (derivation_index >> i) & 1 == 1)
        .collect();
    for (i, &bit) in derivation_index_bits.iter().enumerate() {
        pw.set_bool_target(debug.targets.derivation_index[i], bit)?;
    }
    
    // Set expected child public key
    pw.set_biguint_target(&debug.targets.pk_i.x.value, &pk_i_x)?;
    pw.set_biguint_target(&debug.targets.pk_i.y.value, &pk_i_y)?;
    
    // Set expected child chain code
    let cc_i_bits: Vec<bool> = cc_i.iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    for (i, &bit) in cc_i_bits.iter().enumerate() {
        pw.set_bool_target(debug.targets.cc_i[i], bit)?;
    }
    
    println!("Outer witness setup time: {:?}", witness_start.elapsed());
    
    // Before proving: dump environment
    print_env("PROVE", &debug.data);
    
    // Generate outer recursive proof using method-based API
    println!("Generating debug proof");
    let proof = debug.data.prove(pw)?;
    println!("verifier_only_digest (data) = {:?}", debug.data.verifier_only.circuit_digest);
    println!("public_inputs_len(proof)    = {}", proof.public_inputs.len());
    println!("Debug proof size: {} bytes", proof.to_bytes().len());
    
    // DEBUG: Dump all public inputs for step-by-step comparison
    println!("\n=== DEBUG: PUBLIC INPUTS DUMP ({} elements) ===", proof.public_inputs.len());
    for (i, x) in proof.public_inputs.iter().enumerate() {
        println!("PI[{i:04}]: {}", x.0); // Goldilocks field element as u64
    }
    println!("=== END PUBLIC INPUTS DUMP ===\n");
    
    // Verify outer recursive proof
    println!("Verifying debug proof...");
    let verify_start = Instant::now();
    if let Err(e) = debug.data.verify(proof.clone()) {
        println!("Verify: ERROR -> {e}");
        print_env("VERIFY", &debug.data);
        return Err(e.into());
    } else {
        println!("Verify: OK");
    }
    println!("Debug proof verification time: {:?}", verify_start.elapsed());
        
    // Save outer proof
    println!("Serializing and saving debug proof...");
    let save_start = Instant::now();
    let debug_proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("debug_proof.bin"), &debug_proof_data)?;
    println!("Debug proof serialization + save time: {:?}", save_start.elapsed());
    println!("Debug proof saved: {} bytes", debug_proof_data.len());
    
    println!("\n=== PERFORMANCE SUMMARY ===");
    println!("=== DEBUG PROOF COMPLETE");
    
    Ok(())
}