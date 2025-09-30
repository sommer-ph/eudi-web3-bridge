//! Serial recursive proof generation command.

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
use plonky2_ecdsa::field::p256_scalar::P256Scalar;

use crate::types::input::{FullInputExtended, SignatureMode, DerivationMode};
use crate::utils::parsing::{hex_to_bigint, hex_to_fixed_be_bytes, set_bytes_as_bits_be, set_u32_be_bits_non_hardened};
use crate::circuits::serial_recursion::{
    c1::{build_c1_circuit, C1Circuit},
    c2::{build_c2_circuit, C2Circuit},
    c3::{build_c3_circuit, C3Circuit},
    c4::{build_c4_circuit, C4Circuit},
    c5::{build_c5_circuit_optimized, C5Circuit, C5KeyDerivationTargets},
};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Convert chain code hex string to field elements (8×u32 limbs in LE order)
fn cc_hex_to_field_elements(cc_hex: &str) -> [F; 8] {
    use num_bigint::BigUint;
    let cc_bytes = hex::decode(&cc_hex[2..]).expect("Invalid cc hex");
    let big = BigUint::from_bytes_be(&cc_bytes);
    let mut le_bytes = big.to_bytes_le();
    le_bytes.resize(32, 0); // Pad to 32 bytes
    
    let mut out = [F::ZERO; 8];
    for i in 0..8 {
        let limb = u32::from_le_bytes(le_bytes[i*4..i*4+4].try_into().unwrap());
        out[i] = F::from_canonical_u32(limb);
    }
    out
}

/// Serial recursive circuits container
pub struct SerialCircuits {
    pub c1: C1Circuit,
    pub c2: C2Circuit,
    pub c3: C3Circuit,
    pub c4: C4Circuit,
    pub c5: C5Circuit,
}

/// Build all serial recursive circuits
pub fn build_serial_circuits(signature_mode: SignatureMode, derivation_mode: DerivationMode) -> SerialCircuits {
    println!("Building serial recursive circuits...");
    let total_start = Instant::now();

    // Build circuits sequentially (each depends on the previous one)
    println!("Building C1 circuit (EUDI Key Derivation)...");
    let c1_start = Instant::now();
    let c1 = build_c1_circuit();
    println!("C1 circuit built in {:?} ({} gates)", c1_start.elapsed(), c1.data.common.degree());

    println!("Building C2 circuit (Public Key Decode and Check + C1 recursive)...");
    let c2_start = Instant::now();
    let c2 = build_c2_circuit(&c1.data.common);
    println!("C2 circuit built in {:?} ({} gates)", c2_start.elapsed(), c2.data.common.degree());
    
    println!("Building C3 circuit (Hash Calculation + Signature Verification + C2 recursive)...");
    let c3_start = Instant::now();
    let c3 = build_c3_circuit(&c2.data.common, signature_mode);
    println!("C3 circuit built in {:?} ({} gates)", c3_start.elapsed(), c3.data.common.degree());

    println!("Building C4 circuit (Secp256k1 Key Derivation + C3 recursive)...");
    let c4_start = Instant::now();
    let c4 = build_c4_circuit(&c3.data.common);
    println!("C4 circuit built in {:?} ({} gates)", c4_start.elapsed(), c4.data.common.degree());

    println!("Building C5 circuit (BIP32 Key Derivation + C4 recursive) with {:?} derivation mode...", derivation_mode);
    let c5_start = Instant::now();
    let c5 = build_c5_circuit_optimized(&c4.data.common, derivation_mode.clone());
    println!("C5 circuit built in {:?} ({} gates)", c5_start.elapsed(), c5.data.common.degree());
    
    println!("All serial circuits built in {:?}", total_start.elapsed());

    SerialCircuits { c1, c2, c3, c4, c5 }
}

/// Generate serial recursive proof
pub fn generate_serial_recursive_proof(
    circuits: &SerialCircuits,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let total_start = Instant::now();
    
    let signature_mode_str = match circuits.c3.signature_mode {
        SignatureMode::Static => "STATIC PK",
        SignatureMode::Dynamic => "DYNAMIC PK",
    };
    
    println!("=== SERIAL RECURSIVE PROOF GENERATION ({}) ===", signature_mode_str);
    
    // Load input data
    println!("Loading extended input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: FullInputExtended = serde_json::from_str(&input_data)?;

    // === STEP 1: Generate C1 Proof ===
    println!("\n=== STEP 1: C1 PROOF (EUDI Key Derivation) ===");
    let c1_proof = generate_c1_proof(&circuits.c1, &input, build_dir)?;

    // === STEP 2: Generate C2 Proof ===
    println!("\n=== STEP 2: C2 PROOF (Public Key Decode and Check + C1 recursive) ===");
    let c2_proof = generate_c2_proof(&circuits.c2, &circuits.c1, &input, &c1_proof, build_dir)?;

    // === STEP 3: Generate C3 Proof ===
    println!("\n=== STEP 3: C3 PROOF (Hash Calculation + Signature Verification + C2 Recursive) ===");
    let c3_proof = generate_c3_proof(&circuits.c3, &circuits.c2, &input, &c2_proof, build_dir)?;

    // === STEP 4: Generate C4 Proof ===
    println!("\n=== STEP 4: C4 PROOF (Secp256k1 Key Derivation + C3 Recursive) ===");
    let c4_proof = generate_c4_proof(&circuits.c4, &circuits.c3, &input, &c3_proof, build_dir)?;

    // === STEP 5: Generate C5 Proof (Final) ===
    println!("\n=== STEP 5: C5 PROOF (BIP32 Key Derivation + C4 Recursive) ===");
    let c5_proof = generate_c5_proof(&circuits.c5, &circuits.c4, &input, &c4_proof, build_dir)?;
    
    // Verify final proof
    println!("Verifying final C5 proof...");
    let verify_start = Instant::now();
    circuits.c5.data.verify(c5_proof.clone())?;
    println!("Final proof verification time: {:?}", verify_start.elapsed());
    
    // Save final proof artifacts
    println!("Saving final serial proof artifacts...");
    
    // Save proof
    let final_proof_data = bincode::serialize(&c5_proof)?;
    fs::write(build_dir.join("serial_proof.bin"), &final_proof_data)?;
    println!("Final proof saved: {} bytes", final_proof_data.len());
    
    // Save verifier data
    let verifier_data = bincode::serialize(&circuits.c5.data.verifier_only)?;
    fs::write(build_dir.join("serial_verifier.bin"), &verifier_data)?;
    println!("Final verifier data saved: {} bytes", verifier_data.len());
    
    // Save common circuit data
    let common_data = bincode::serialize(&circuits.c5.data.common)?;
    fs::write(build_dir.join("serial_common.bin"), &common_data)?;
    println!("Final common data saved: {} bytes", common_data.len());
    
    println!("\n=== PERFORMANCE SUMMARY ===");
    println!("Total serial recursive proof time: {:?}", total_start.elapsed());
    println!("=== SERIAL-STEP RECURSIVE PROOF COMPLETE ({}) ===", signature_mode_str);
    
    Ok(())
}

/// Generate C1 proof (EUDI Key Derivation)
fn generate_c1_proof(
    circuit: &C1Circuit,
    input: &FullInputExtended,
    build_dir: &Path,
) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>> {
    println!("Setting up C1 witness...");
    let witness_start = Instant::now();

    // Parse inputs
    let pk_c_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.x));
    let pk_c_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.y));
    let sk_c = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_c));

    let mut pw = PartialWitness::<F>::new();

    // Set public input: pk_c
    pw.set_biguint_target(&circuit.targets.pk_c.x.value, &pk_c_x.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.pk_c.y.value, &pk_c_y.to_canonical_biguint())?;

    // Set private input: sk_c
    pw.set_biguint_target(&circuit.targets.sk_c.value, &sk_c.to_canonical_biguint())?;

    println!("C1 witness setup time: {:?}", witness_start.elapsed());

    // Generate proof
    println!("Generating C1 proof...");
    let mut timing = TimingTree::new("c1_proof", Level::Info);
    let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing)?;
    timing.print();

    // Save proof artifacts
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("c1_proof.bin"), &proof_data)?;
    println!("C1 proof size: {} bytes", proof.to_bytes().len());

    // Save verifier data
    let verifier_data = bincode::serialize(&circuit.data.verifier_only)?;
    fs::write(build_dir.join("c1_verifier.bin"), &verifier_data)?;
    println!("C1 verifier data saved: {} bytes", verifier_data.len());

    // Save common circuit data
    let common_data = bincode::serialize(&circuit.data.common)?;
    fs::write(build_dir.join("c1_common.bin"), &common_data)?;
    println!("C1 common data saved: {} bytes", common_data.len());

    Ok(proof)
}

/// Generate C2 proof (Public Key Decode and Check + C1 recursive)
fn generate_c2_proof(
    circuit: &C2Circuit,
    c1_circuit: &C1Circuit,
    input: &FullInputExtended,
    c1_proof: &plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>,
    build_dir: &Path,
) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>> {
    use crate::utils::sha256::{MAX_PAYLOAD};

    println!("Setting up C2 witness...");
    let witness_start = Instant::now();

    let mut pw = PartialWitness::<F>::new();

    // Set recursive proof
    pw.set_proof_with_pis_target(&circuit.targets.c1_proof, c1_proof)?;
    pw.set_verifier_data_target(&circuit.targets.c1_vd, &c1_circuit.data.verifier_only)?;

    // Set payload bytes
    if input.payloadB64.len() < MAX_PAYLOAD {
        println!("Warning: payloadB64 has {} entries; expected {}. Missing entries treated as 0.", input.payloadB64.len(), MAX_PAYLOAD);
    }
    for i in 0..MAX_PAYLOAD {
        let v = input
            .payloadB64
            .get(i)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        pw.set_target(circuit.targets.payload[i], F::from_canonical_u32(v))?;
    }

    // Set payload length
    let payload_len_u32 = input.payloadB64Length.parse::<u32>().unwrap_or(0);
    pw.set_target(circuit.targets.payload_len, F::from_canonical_u32(payload_len_u32))?;

    // Set Base64url extraction parameters
    let off_x_b64 = input.offXB64.parse::<u32>().unwrap_or(0);
    let len_x_b64 = input.lenXB64.parse::<u32>().unwrap_or(0);
    let drop_x = input.dropX.parse::<u32>().unwrap_or(0);
    let len_x_inner = input.lenXInner.parse::<u32>().unwrap_or(0);
    let off_y_b64 = input.offYB64.parse::<u32>().unwrap_or(0);
    let len_y_b64 = input.lenYB64.parse::<u32>().unwrap_or(0);
    let drop_y = input.dropY.parse::<u32>().unwrap_or(0);
    let len_y_inner = input.lenYInner.parse::<u32>().unwrap_or(0);

    pw.set_target(circuit.targets.off_x_b64, F::from_canonical_u32(off_x_b64))?;
    pw.set_target(circuit.targets.len_x_b64, F::from_canonical_u32(len_x_b64))?;
    pw.set_target(circuit.targets.drop_x, F::from_canonical_u32(drop_x))?;
    pw.set_target(circuit.targets.len_x_inner, F::from_canonical_u32(len_x_inner))?;
    pw.set_target(circuit.targets.off_y_b64, F::from_canonical_u32(off_y_b64))?;
    pw.set_target(circuit.targets.len_y_b64, F::from_canonical_u32(len_y_b64))?;
    pw.set_target(circuit.targets.drop_y, F::from_canonical_u32(drop_y))?;
    pw.set_target(circuit.targets.len_y_inner, F::from_canonical_u32(len_y_inner))?;
    
    println!("C2 witness setup time: {:?}", witness_start.elapsed());

    // Generate proof
    println!("Generating C2 proof...");
    let mut timing = TimingTree::new("c2_proof", Level::Info);
    let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing)?;
    timing.print();

    // Save proof artifacts
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("c2_proof.bin"), &proof_data)?;
    println!("C2 proof size: {} bytes", proof.to_bytes().len());

    // Save verifier data
    let verifier_data = bincode::serialize(&circuit.data.verifier_only)?;
    fs::write(build_dir.join("c2_verifier.bin"), &verifier_data)?;
    println!("C2 verifier data saved: {} bytes", verifier_data.len());

    // Save common circuit data
    let common_data = bincode::serialize(&circuit.data.common)?;
    fs::write(build_dir.join("c2_common.bin"), &common_data)?;
    println!("C2 common data saved: {} bytes", common_data.len());
    
    Ok(proof)
}

/// Generate C3 proof (Hash Calculation + Signature Verification + C2 Recursive)
fn generate_c3_proof(
    circuit: &C3Circuit,
    c2_circuit: &C2Circuit,
    input: &FullInputExtended,
    c2_proof: &plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>,
    build_dir: &Path,
) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>> {
    use crate::utils::sha256::{MAX_HEADER, MAX_PAYLOAD};

    println!("Setting up C3 witness...");
    let witness_start = Instant::now();

    // Parse inputs
    let pk_issuer = &input.pk_issuer;
    let pk_issuer_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&pk_issuer.x));
    let pk_issuer_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&pk_issuer.y));
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));

    let mut pw = PartialWitness::<F>::new();

    // Set recursive proof
    pw.set_proof_with_pis_target(&circuit.targets.c2_proof, c2_proof)?;
    pw.set_verifier_data_target(&circuit.targets.c2_vd, &c2_circuit.data.verifier_only)?;

    // Set public input: pk_issuer
    pw.set_biguint_target(&circuit.targets.pk_issuer.x.value, &pk_issuer_x.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.pk_issuer.y.value, &pk_issuer_y.to_canonical_biguint())?;

    // Set private inputs: msg, signature
    pw.set_biguint_target(&circuit.targets.msg.value, &msg.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.sig.r.value, &sig_r.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.sig.s.value, &sig_s.to_canonical_biguint())?;

    // Set header bytes for SHA-256 hash calculation
    if input.headerB64.len() < MAX_HEADER {
        println!("Warning: headerB64 has {} entries; expected {}. Missing entries treated as 0.", input.headerB64.len(), MAX_HEADER);
    }
    for i in 0..MAX_HEADER {
        let v = input
            .headerB64
            .get(i)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        pw.set_target(circuit.targets.header[i], F::from_canonical_u32(v))?;
    }

    // Set header length
    let header_len_u32 = input.headerB64Length.parse::<u32>().unwrap_or(0);
    pw.set_target(circuit.targets.header_len, F::from_canonical_u32(header_len_u32))?;

    // Set payload bytes for SHA-256 hash calculation
    if input.payloadB64.len() < MAX_PAYLOAD {
        println!("Warning: payloadB64 has {} entries; expected {}. Missing entries treated as 0.", input.payloadB64.len(), MAX_PAYLOAD);
    }
    for i in 0..MAX_PAYLOAD {
        let v = input
            .payloadB64
            .get(i)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        pw.set_target(circuit.targets.payload[i], F::from_canonical_u32(v))?;
    }

    // Set payload length
    let payload_len_u32 = input.payloadB64Length.parse::<u32>().unwrap_or(0);
    pw.set_target(circuit.targets.payload_len, F::from_canonical_u32(payload_len_u32))?;

    // Set message_bits for SHA-256 calculation
    // Build msg_bytes: header || '.' || payload
    let mut msg_bytes = Vec::new();
    let hlen = header_len_u32.min(MAX_HEADER as u32) as usize;
    for i in 0..MAX_HEADER {
        let b = if i < hlen {
            input.headerB64.get(i).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0)
        } else {
            0
        };
        msg_bytes.push(b);
    }
    msg_bytes.push(46u8); // '.' separator
    let plen = payload_len_u32.min(MAX_PAYLOAD as u32) as usize;
    for i in 0..MAX_PAYLOAD {
        let b = if i < plen {
            input.payloadB64.get(i).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0)
        } else {
            0
        };
        msg_bytes.push(b);
    }

    // Convert bytes to bits (MSB first)
    debug_assert_eq!(circuit.targets.message_bits.len(), msg_bytes.len() * 8);
    let mut k = 0;
    for &b in &msg_bytes {
        for i in (0..8).rev() {
            let bit = ((b >> i) & 1) == 1;
            pw.set_bool_target(circuit.targets.message_bits[k], bit)?;
            k += 1;
        }
    }

    println!("C3 witness setup time: {:?}", witness_start.elapsed());
    
    // Generate proof
    println!("Generating C3 proof...");
    let mut timing = TimingTree::new("c3_proof", Level::Info);
    let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing)?;
    timing.print();
    
    // Save proof artifacts
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("c3_proof.bin"), &proof_data)?;
    println!("C3 proof size: {} bytes", proof.to_bytes().len());
    
    // Save verifier data
    let verifier_data = bincode::serialize(&circuit.data.verifier_only)?;
    fs::write(build_dir.join("c3_verifier.bin"), &verifier_data)?;
    println!("C3 verifier data saved: {} bytes", verifier_data.len());
    
    // Save common circuit data
    let common_data = bincode::serialize(&circuit.data.common)?;
    fs::write(build_dir.join("c3_common.bin"), &common_data)?;
    println!("C3 common data saved: {} bytes", common_data.len());
    
    Ok(proof)
}

/// Generate C4 proof (Secp256k1 Key Derivation + C3 Recursive)
fn generate_c4_proof(
    circuit: &C4Circuit,
    c3_circuit: &C3Circuit,
    input: &FullInputExtended,
    c3_proof: &plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>,
    build_dir: &Path,
) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>> {
    println!("Setting up C4 witness...");
    let witness_start = Instant::now();
    
    // Parse inputs
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    let sk_0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_0));
    
    let mut pw = PartialWitness::<F>::new();
    
    // Set recursive proof
    pw.set_proof_with_pis_target(&circuit.targets.c3_proof, c3_proof)?;
    pw.set_verifier_data_target(&circuit.targets.c3_vd, &c3_circuit.data.verifier_only)?;
    
    // Set public input: pk_0
    pw.set_biguint_target(&circuit.targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    
    // Set private input: sk_0
    pw.set_biguint_target(&circuit.targets.sk_0.value, &sk_0.to_canonical_biguint())?;
    
    println!("C4 witness setup time: {:?}", witness_start.elapsed());
    
    // Generate proof
    println!("Generating C4 proof...");
    let mut timing = TimingTree::new("c4_proof", Level::Info);
    let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing)?;
    timing.print();
    
    // Save proof artifacts
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("c4_proof.bin"), &proof_data)?;
    println!("C4 proof size: {} bytes", proof.to_bytes().len());
    
    // Save verifier data
    let verifier_data = bincode::serialize(&circuit.data.verifier_only)?;
    fs::write(build_dir.join("c4_verifier.bin"), &verifier_data)?;
    println!("C4 verifier data saved: {} bytes", verifier_data.len());
    
    // Save common circuit data
    let common_data = bincode::serialize(&circuit.data.common)?;
    fs::write(build_dir.join("c4_common.bin"), &common_data)?;
    println!("C4 common data saved: {} bytes", common_data.len());
    
    Ok(proof)
}

/// Generate C5 proof (BIP32 Key Derivation + C4 Recursive)
fn generate_c5_proof(
    circuit: &C5Circuit,
    c4_circuit: &C4Circuit,
    input: &FullInputExtended,
    c4_proof: &plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>,
    build_dir: &Path,
) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D>> {
    println!("Setting up C5 witness...");
    let witness_start = Instant::now();
    
    // Parse parent data for BIP32 Key Derivation
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    
    // Parse parent chain code
    let cc_0 = hex_to_fixed_be_bytes::<32>(&input.cc_0);
    
    // Parse derivation index
    let derivation_index = input.derivation_index;
    
    // Parse expected child outputs
    let pk_i_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.x));
    let pk_i_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.y));
    
    let cc_i = match &input.cc_i {
        Some(cc_i_str) => hex_to_fixed_be_bytes::<32>(cc_i_str),
        None => [0u8; 32], // Default for Poseidon mode (not used)
    };
    
    let mut pw = PartialWitness::<F>::new();
    
    // Set recursive proof
    pw.set_proof_with_pis_target(&circuit.targets.c4_proof, c4_proof)?;
    pw.set_verifier_data_target(&circuit.targets.c4_vd, &c4_circuit.data.verifier_only)?;
    
    // Set parent public key
    //pw.set_biguint_target(&circuit.targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    //pw.set_biguint_target(&circuit.targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    
    // Set key derivation witnesses (mode-specific)
    match &circuit.targets.key_derivation_targets {
        C5KeyDerivationTargets::Bip32(bip32_targets) => {
            println!("Setting SHA512-based BIP32 witnesses for C5...");
            
            // Set parent public key (private input)
            pw.set_biguint_target(&bip32_targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
            pw.set_biguint_target(&bip32_targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
            
            // Set expected child public key
            pw.set_biguint_target(&bip32_targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
            pw.set_biguint_target(&bip32_targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
            
            // Set parent chain code (256 bits as BoolTargets)
            set_bytes_as_bits_be(
                &mut pw,
                &bip32_targets.cc_0,
                &cc_0,
            )?;
            
            // Set child index (32 bits, non-hardened enforced)
            set_u32_be_bits_non_hardened(
                &mut pw,
                &bip32_targets.derivation_index,
                derivation_index,
            )?;
            
            // Set expected child chain code (256 bits as BoolTargets)
            set_bytes_as_bits_be(
                &mut pw,
                &bip32_targets.cc_i,
                &cc_i,
            )?;
        }
        C5KeyDerivationTargets::Poseidon(poseidon_targets) => {
            println!("Setting Poseidon-based key derivation witnesses for C5...");
            
            // Set parent public key (private input)
            pw.set_biguint_target(&poseidon_targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
            pw.set_biguint_target(&poseidon_targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
            
            // Set expected child public key
            pw.set_biguint_target(&poseidon_targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
            pw.set_biguint_target(&poseidon_targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
            
            // Set parent chain code (8×u32 field elements)
            let cc_0_fields = cc_hex_to_field_elements(&input.cc_0);
            for (target, &field_val) in poseidon_targets.cc_0.iter().zip(cc_0_fields.iter()) {
                let _ = pw.set_target(*target, field_val);
            }
            
            // Set derivation index (single field element)
            let _ = pw.set_target(poseidon_targets.derivation_index, F::from_canonical_u32(derivation_index));
            
            // Note: No cc_i for Poseidon mode (no chain code output)
        }
    }
    
    println!("C5 witness setup time: {:?}", witness_start.elapsed());
    
    // Generate proof
    println!("Generating C5 proof...");
    let mut timing = TimingTree::new("c5_proof", Level::Info);
    let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing)?;
    timing.print();
    
    // Save proof artifacts
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("c5_proof.bin"), &proof_data)?;
    println!("C5 proof size: {} bytes", proof.to_bytes().len());
    
    // Save verifier data
    let verifier_data = bincode::serialize(&circuit.data.verifier_only)?;
    fs::write(build_dir.join("c5_verifier.bin"), &verifier_data)?;
    println!("C5 verifier data saved: {} bytes", verifier_data.len());
    
    // Save common circuit data
    let common_data = bincode::serialize(&circuit.data.common)?;
    fs::write(build_dir.join("c5_common.bin"), &common_data)?;
    println!("C5 common data saved: {} bytes", common_data.len());
    
    Ok(proof)
}