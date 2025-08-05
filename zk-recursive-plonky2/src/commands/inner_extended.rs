//! Inner extended circuit proof generation command.

use anyhow::Result;
use log::Level;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;
use std::{fs, path::Path, time::Instant};
use plonky2::field::types::{PrimeField, Field};
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use crate::types::input::OuterExtendedInput;
use crate::utils::parsing::{hex_to_bigint, set_nonnative_target};
use crate::circuits::inner_extended::InnerExtendedCircuit;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Generate inner extended circuit proof
pub fn generate_inner_extended_proof(
    inner_extended: &InnerExtendedCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    println!("=== INNER EXTENDED CIRCUIT: EUDI + SECP256K1 ===");
    println!("Loading inner extended input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterExtendedInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse EUDI (P-256) inputs
    let pk_issuer_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.x));
    let pk_issuer_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.y));
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));
    let pk_c_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.x));
    let pk_c_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.y));
    let sk_c = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_c));
    
    // Parse secp256k1 inputs
    let sk_0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_0));
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    
    // Set up inner extended circuit witness
    println!("Setting up inner extended circuit witness...");
    let mut pw = PartialWitness::<F>::new();
    // EUDI P-256 witness data
    pw.set_biguint_target(&inner_extended.targets.pk_issuer.x.value, &pk_issuer_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner_extended.targets.pk_issuer.y.value, &pk_issuer_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner_extended.targets.msg, msg)?;
    set_nonnative_target(&mut pw, &inner_extended.targets.sig.r, sig_r)?;
    set_nonnative_target(&mut pw, &inner_extended.targets.sig.s, sig_s)?;
    pw.set_biguint_target(&inner_extended.targets.pk_c.x.value, &pk_c_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner_extended.targets.pk_c.y.value, &pk_c_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner_extended.targets.sk_c, sk_c)?;
    // Secp256k1 witness data
    pw.set_biguint_target(&inner_extended.targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner_extended.targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner_extended.targets.sk_0, sk_0)?;
        
    // Generate inner extended proof
    println!("Generating inner extended proof...");
    let mut timing = TimingTree::new("inner_extended_proof", Level::Info);
    let proof = prove(&inner_extended.data.prover_only, &inner_extended.data.common, pw, &mut timing)?;
    println!("Inner extended proof timing breakdown:");
    timing.print();
    println!("Inner extended proof size: {} bytes", proof.to_bytes().len());
    
    // Verify inner extended proof
    println!("Verifying inner extended proof...");
    let verify_start = Instant::now();
    inner_extended.data.verify(proof.clone())?;
    println!("Inner extended proof verification time: {:?}", verify_start.elapsed());
    
    // Save inner extended proof
    println!("Serializing and saving inner extended proof...");
    let save_start = Instant::now();
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("inner_extended_proof.bin"), &proof_data)?;
    println!("Inner extended proof serialization + save time: {:?}", save_start.elapsed());
    println!("Inner extended proof saved: {} bytes", proof_data.len());
    
    let inner_extended_total = start.elapsed();
    println!("Inner extended circuit total time: {:?}", inner_extended_total);
    
    Ok(())
}