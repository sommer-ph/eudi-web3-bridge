//! Experimental circuit proof generation commands.
//! 
//! This module contains experimental proof generation functions for testing
//! and development of recursive ZK-SNARK circuits. These functions handle
//! both inner and outer proof generation for key derivation and signature
//! verification circuits.

use std::{fs, path::Path, time::Instant};
use anyhow::Result;
use plonky2::field::types::{PrimeField, Field};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use serde_json;

use crate::utils::parsing::{hex_to_bigint, set_nonnative_target};
use crate::types::input::{OuterKeyDerInput, OuterSigVerifyInput};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Generate experimental inner key derivation proof
pub fn generate_exp_inner_key_der_proof(
    inner: &crate::circuits::experiments::InnerKeyDerCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    println!("Loading inner key derivation input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterKeyDerInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse key derivation proof inputs
    let sk_c = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_c));
    let pk_cred_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_cred.x));
    let pk_cred_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_cred.y));
    
    // Set up inner key derivation circuit witness
    let mut pw = PartialWitness::<F>::new();
    pw.set_biguint_target(&inner.targets.pk_c.x.value, &pk_cred_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_c.y.value, &pk_cred_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.sk_c, sk_c)?;
    
    // Generate inner key derivation proof
    println!("Generating inner key derivation proof...");
    let proof_start = Instant::now();
    let proof = inner.data.prove(pw)?;
    let proof_time = proof_start.elapsed();
    println!("Inner key derivation proof generation time: {:?}", proof_time);
    println!("Inner key derivation proof size: {} bytes", proof.to_bytes().len());
    
    // Verify inner key derivation proof
    println!("Verifying inner key derivation proof...");
    let verify_start = Instant::now();
    inner.data.verify(proof.clone())?;
    println!("Inner key derivation proof verification time: {:?}", verify_start.elapsed());
    
    // Save inner key derivation proof
    println!("Serializing and saving inner key derivation proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("exp_inner_key_der_proof.bin"), &proof_data)?;
    println!("Inner key derivation proof serialization + save time: {:?}", save_start.elapsed());
    println!("Inner key derivation proof saved: {} bytes", proof_data.len());
    
    println!("Experimental inner key derivation proof generation completed in: {:?}", start.elapsed());
    
    Ok(())
}

/// Generate experimental inner signature verification proof
pub fn generate_exp_inner_sig_verify_proof(
    inner: &crate::circuits::experiments::InnerSigVerifyCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    println!("Loading inner signature verification input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterSigVerifyInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse signature verification proof inputs
    let pk_i_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.x));
    let pk_i_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.y));
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));
    
    // Set up inner signature verification circuit witness
    let mut pw = PartialWitness::<F>::new();
    pw.set_biguint_target(&inner.targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.msg, msg)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.r, sig_r)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.s, sig_s)?;
    
    // Generate inner signature verification proof
    println!("Generating inner signature verification proof...");
    let proof_start = Instant::now();
    let proof = inner.data.prove(pw)?;
    let proof_time = proof_start.elapsed();
    println!("Inner signature verification proof generation time: {:?}", proof_time);
    println!("Inner signature verification proof size: {} bytes", proof.to_bytes().len());
    
    // Verify inner signature verification proof
    println!("Verifying inner signature verification proof...");
    let verify_start = Instant::now();
    inner.data.verify(proof.clone())?;
    println!("Inner signature verification proof verification time: {:?}", verify_start.elapsed());
    
    // Save inner signature verification proof
    println!("Serializing and saving inner signature verification proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("exp_inner_sig_verify_proof.bin"), &proof_data)?;
    println!("Inner signature verification proof serialization + save time: {:?}", save_start.elapsed());
    println!("Inner signature verification proof saved: {} bytes", proof_data.len());
    
    println!("Experimental inner signature verification proof generation completed in: {:?}", start.elapsed());
    
    Ok(())
}

/// Generate experimental outer key derivation proof (recursive)
pub fn generate_exp_outer_key_der_proof(
    inner: &crate::circuits::experiments::InnerKeyDerCircuit,
    outer: &crate::circuits::experiments::OuterKeyDerCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let total_start = Instant::now();
    
    // First generate inner proof
    println!("=== INNER KEY DERIVATION PROOF ===");
    generate_exp_inner_key_der_proof(inner, input_file, build_dir)?;
    
    // Load the generated inner proof
    println!("=== OUTER RECURSIVE KEY DERIVATION PROOF ===");
    println!("Loading inner key derivation proof artifacts...");
    let load_start = Instant::now();
    let inner_proof_data = fs::read(build_dir.join("exp_inner_key_der_proof.bin"))?;
    let inner_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D> = 
        bincode::deserialize(&inner_proof_data)?;
    println!("Inner proof load + deserialization time: {:?}", load_start.elapsed());
    
    // Load outer input data
    println!("Loading outer key derivation input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterKeyDerInput = serde_json::from_str(&input_data)?;
        
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
    println!("Generating outer recursive key derivation proof...");
    let proof_start = Instant::now();
    let proof = outer.data.prove(pw)?;
    let proof_time = proof_start.elapsed();
    println!("Outer recursive key derivation proof generation time: {:?}", proof_time);
    println!("Outer recursive key derivation proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer recursive proof
    println!("Verifying outer recursive key derivation proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer recursive key derivation proof verification time: {:?}", verify_start.elapsed());
    
    // Save outer recursive proof
    println!("Serializing and saving outer recursive key derivation proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("exp_outer_key_der_proof.bin"), &proof_data)?;
    println!("Outer recursive key derivation proof serialization + save time: {:?}", save_start.elapsed());
    println!("Outer recursive key derivation proof saved: {} bytes", proof_data.len());
    
    println!("Experimental recursive key derivation proof generation completed in: {:?}", total_start.elapsed());
    
    Ok(())
}

/// Generate experimental outer signature verification proof (recursive)
pub fn generate_exp_outer_sig_verify_proof(
    inner: &crate::circuits::experiments::InnerSigVerifyCircuit,
    outer: &crate::circuits::experiments::OuterSigVerifyCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let total_start = Instant::now();
    
    // First generate inner proof
    println!("=== INNER SIGNATURE VERIFICATION PROOF ===");
    generate_exp_inner_sig_verify_proof(inner, input_file, build_dir)?;
    
    // Load the generated inner proof
    println!("=== OUTER RECURSIVE SIGNATURE VERIFICATION PROOF ===");
    println!("Loading inner signature verification proof artifacts...");
    let load_start = Instant::now();
    let inner_proof_data = fs::read(build_dir.join("exp_inner_sig_verify_proof.bin"))?;
    let inner_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D> = 
        bincode::deserialize(&inner_proof_data)?;
    println!("Inner proof load + deserialization time: {:?}", load_start.elapsed());
    
    // Load outer input data
    println!("Loading outer signature verification input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterSigVerifyInput = serde_json::from_str(&input_data)?;
        
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
    println!("Generating outer recursive signature verification proof...");
    let proof_start = Instant::now();
    let proof = outer.data.prove(pw)?;
    let proof_time = proof_start.elapsed();
    println!("Outer recursive signature verification proof generation time: {:?}", proof_time);
    println!("Outer recursive signature verification proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer recursive proof
    println!("Verifying outer recursive signature verification proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer recursive signature verification proof verification time: {:?}", verify_start.elapsed());
    
    // Save outer recursive proof
    println!("Serializing and saving outer recursive signature verification proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("exp_outer_sig_verify_proof.bin"), &proof_data)?;
    println!("Outer recursive signature verification proof serialization + save time: {:?}", save_start.elapsed());
    println!("Outer recursive signature verification proof saved: {} bytes", proof_data.len());
    
    println!("Experimental recursive signature verification proof generation completed in: {:?}", total_start.elapsed());
    
    Ok(())
}