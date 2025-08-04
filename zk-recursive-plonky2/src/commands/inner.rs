//! Inner circuit proof generation command.

use anyhow::Result;
use log::Level;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;
use std::{fs, path::Path, time::Instant};
use plonky2::field::types::{PrimeField, Field};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use crate::types::input::OuterProofInput;
use crate::utils::parsing::{hex_to_bigint, set_nonnative_target};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Generate inner circuit proof
pub fn generate_inner_proof(
    inner: &crate::InnerCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    println!("Loading inner input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: OuterProofInput = serde_json::from_str(&input_data)?;
    
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
    let mut timing = TimingTree::new("inner_proof", Level::Info);
    let proof = prove(&inner.data.prover_only, &inner.data.common, pw, &mut timing)?;
    println!("Inner proof timing breakdown:");
    timing.print();
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
    
    let inner_total = start.elapsed();
    println!("Inner circuit total time: {:?}", inner_total);
    
    Ok(())
}
