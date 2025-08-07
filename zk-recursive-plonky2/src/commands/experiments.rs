//! Experimental circuit proof generation commands.
//! 
//! This module contains experimental proof generation functions for testing
//! and development of recursive ZK-SNARK circuits. These functions handle
//! both inner and outer proof generation.

use std::{fs, path::Path, time::Instant};
use anyhow::Result;
use log::Level;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;
use plonky2::field::types::{PrimeField, Field};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use serde_json;

use crate::utils::parsing::{hex_to_bigint, set_nonnative_target};
use crate::types::input::{OuterKeyDerInput, OuterSigVerifyInput, Bip32KeyDerInput, InnerSigVerifyStaticInput};
use hex;

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
    let pk_c_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.x));
    let pk_c_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.y));
    
    // Set up inner key derivation circuit witness
    let mut pw = PartialWitness::<F>::new();
    pw.set_biguint_target(&inner.targets.pk_c.x.value, &pk_c_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_c.y.value, &pk_c_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.sk_c, sk_c)?;
    
    // Generate inner key derivation proof
    println!("Generating inner key derivation proof...");
    let mut timing = TimingTree::new("inner_key_der_proof", Level::Info);
    let proof = prove(&inner.data.prover_only, &inner.data.common, pw, &mut timing)?;
    println!("Inner key derivation proof timing breakdown:");
    timing.print();
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
    let pk_issuer_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.x));
    let pk_issuer_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.y));
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));
    
    // Set up inner signature verification circuit witness
    let mut pw = PartialWitness::<F>::new();
    pw.set_biguint_target(&inner.targets.pk_issuer.x.value, &pk_issuer_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_issuer.y.value, &pk_issuer_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.msg, msg)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.r, sig_r)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.s, sig_s)?;
    
    // Generate inner signature verification proof
    println!("Generating inner signature verification proof...");
    let mut timing = TimingTree::new("inner_sig_verify_proof", Level::Info);
    let proof = prove(&inner.data.prover_only, &inner.data.common, pw, &mut timing)?;
    println!("Inner signature verification proof timing breakdown:");
    timing.print();
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
    let sk_0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_0));
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    
    // Set up outer circuit witness
    let mut pw = PartialWitness::<F>::new();
    pw.set_biguint_target(&outer.targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &outer.targets.sk_0, sk_0)?;
    pw.set_proof_with_pis_target(&outer.targets.proof, &inner_proof)?;
    pw.set_verifier_data_target(&outer.targets.vd, &inner.data.verifier_only)?;
    
    // Generate outer recursive proof
    println!("Generating outer recursive key derivation proof...");
    let mut timing = TimingTree::new("outer_key_der_recursive_proof", Level::Info);
    let proof = prove(&outer.data.prover_only, &outer.data.common, pw, &mut timing)?;
    println!("Outer recursive key derivation proof timing breakdown:");
    timing.print();
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
    let sk_0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_0));
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    
    // Set up outer circuit witness
    let mut pw = PartialWitness::<F>::new();
    pw.set_biguint_target(&outer.targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &outer.targets.sk_0, sk_0)?;
    pw.set_proof_with_pis_target(&outer.targets.proof, &inner_proof)?;
    pw.set_verifier_data_target(&outer.targets.vd, &inner.data.verifier_only)?;
    
    // Generate outer recursive proof
    println!("Generating outer recursive signature verification proof...");
    let mut timing = TimingTree::new("outer_sig_verify_recursive_proof", Level::Info);
    let proof = prove(&outer.data.prover_only, &outer.data.common, pw, &mut timing)?;
    println!("Outer recursive signature verification proof timing breakdown:");
    timing.print();
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

/// Generate experimental BIP32 key derivation proof
pub fn generate_exp_bip32_key_der_proof(
    circuit: &crate::circuits::experiments::bip_32_key_der::Bip32KeyDerCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    println!("Loading BIP32 key derivation input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: Bip32KeyDerInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse BIP32 key derivation inputs
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    let pk_i_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.x));
    let pk_i_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.y));
    
    // Parse chain codes (hex strings to bytes)
    let cc_0_hex = input.cc_0.trim_start_matches("0x");
    let cc_0_bytes = hex::decode(cc_0_hex).expect("Invalid cc_0 hex");
    let cc_i_hex = input.cc_i.trim_start_matches("0x");
    let cc_i_bytes = hex::decode(cc_i_hex).expect("Invalid cc_i hex");
    
    // Set up BIP32 key derivation circuit witness
    let mut pw = PartialWitness::<F>::new();
    
    // Set parent public key (private input)
    pw.set_biguint_target(&circuit.targets.bip32_targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.bip32_targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    
    // Set parent chain code (public input)
    let cc_0_bits: Vec<bool> = cc_0_bytes.iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    for (i, &bit) in cc_0_bits.iter().enumerate() {
        pw.set_bool_target(circuit.targets.bip32_targets.cc_0[i], bit)?;
    }
    
    // Set derivation index bits (public input)
    let derivation_index_bits: Vec<bool> = (0..32).rev()
        .map(|i| (input.derivation_index >> i) & 1 == 1)
        .collect();
    for (i, &bit) in derivation_index_bits.iter().enumerate() {
        pw.set_bool_target(circuit.targets.bip32_targets.derivation_index[i], bit)?;
    }
    
    // Set expected child public key (public input)
    pw.set_biguint_target(&circuit.targets.bip32_targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.bip32_targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
    
    // Set expected child chain code (public input)
    let cc_i_bits: Vec<bool> = cc_i_bytes.iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    for (i, &bit) in cc_i_bits.iter().enumerate() {
        pw.set_bool_target(circuit.targets.bip32_targets.cc_i[i], bit)?;
    }
    
    // Generate BIP32 key derivation proof
    println!("Generating BIP32 key derivation proof...");
    let mut timing = TimingTree::new("bip32_key_der_proof", Level::Info);
    let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing)?;
    println!("BIP32 key derivation proof timing breakdown:");
    timing.print();
    println!("BIP32 key derivation proof size: {} bytes", proof.to_bytes().len());
    
    // Verify BIP32 key derivation proof
    println!("Verifying BIP32 key derivation proof...");
    let verify_start = Instant::now();
    circuit.data.verify(proof.clone())?;
    println!("BIP32 key derivation proof verification time: {:?}", verify_start.elapsed());
    
    // Save BIP32 key derivation proof
    println!("Serializing and saving BIP32 key derivation proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("exp_bip32_key_der_proof.bin"), &proof_data)?;
    println!("BIP32 key derivation proof serialization + save time: {:?}", save_start.elapsed());
    println!("BIP32 key derivation proof saved: {} bytes", proof_data.len());
    
    println!("Experimental BIP32 key derivation proof generation completed in: {:?}", start.elapsed());
    
    Ok(())
}

/// Generate experimental inner signature verification proof with static public key
pub fn generate_exp_inner_sig_verify_static_proof(
    inner: &crate::circuits::experiments::InnerSigVerifyStaticCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    println!("Loading inner signature verification (static PK) input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: InnerSigVerifyStaticInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse signature verification proof inputs
    // No pk_issuer needed - it's fixed in the circuit
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));
    
    // Set up inner signature verification circuit witness (static PK)
    let mut pw = PartialWitness::<F>::new();
    // No need to set pk_issuer - it's fixed in the circuit
    set_nonnative_target(&mut pw, &inner.targets.msg, msg)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.r, sig_r)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.s, sig_s)?;
    
    // Generate inner signature verification proof with static PK
    println!("Generating inner signature verification (static PK) proof...");
    let mut timing = TimingTree::new("inner_sig_verify_static_proof", Level::Info);
    let proof = prove(&inner.data.prover_only, &inner.data.common, pw, &mut timing)?;
    println!("Inner signature verification (static PK) proof timing breakdown:");
    timing.print();
    println!("Inner signature verification (static PK) proof size: {} bytes", proof.to_bytes().len());
    
    // Verify inner signature verification proof with static PK
    println!("Verifying inner signature verification (static PK) proof...");
    let verify_start = Instant::now();
    inner.data.verify(proof.clone())?;
    println!("Inner signature verification (static PK) proof verification time: {:?}", verify_start.elapsed());

    // Save inner signature verification proof with static PK
    println!("Serializing and saving inner signature verification (static PK) proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("exp_inner_sig_verify_static_proof.bin"), &proof_data)?;
    println!("Inner signature verification (static PK) proof serialization + save time: {:?}", save_start.elapsed());
    println!("Inner signature verification (static PK) proof saved: {} bytes", proof_data.len());
    
    println!("Experimental inner signature verification (static PK) proof generation completed in: {:?}", start.elapsed());
    
    Ok(())
}