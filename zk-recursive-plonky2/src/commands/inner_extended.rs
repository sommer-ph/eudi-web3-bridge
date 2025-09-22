//! Inner-extended inner_ext proof generation command.

use anyhow::Result;
use log::Level;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;
use std::{fs, path::Path, time::Instant};
use plonky2::field::types::{PrimeField, Field};
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

use crate::types::input::{FullInputExtended, SignatureMode};
use crate::utils::parsing::{hex_to_bigint, set_nonnative_target};
use crate::utils::sha256::{MAX_HEADER, MAX_PAYLOAD};
use crate::circuits::inner_extended::InnerExtendedCircuit;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

pub fn generate_inner_extended_proof(
    inner_ext: &InnerExtendedCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let signature_mode_str = match inner_ext.signature_mode {
        SignatureMode::Static => "STATIC PK",
        SignatureMode::Dynamic => "DYNAMIC PK",
    };

    println!("=== INNER-EXTENDED CIRCUIT: C1–C4 + MSG/PK BINDING ({}) ===", signature_mode_str);
    println!("Loading input from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: FullInputExtended = serde_json::from_str(&input_data)?;

    // Prepare witness
    println!("Setting up inner-extended inner_ext witness...");
    let witness_start = Instant::now();
    let mut pw = PartialWitness::<F>::new();

    // Parse EUDI (P-256) inputs - C1+C2: Key Derivation, C3: Signature Verification
    let pk_c_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.x));
    let pk_c_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.y));
    let sk_c = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_c));
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));

    // C4: Parse secp256k1 inputs
    let sk_0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_0));
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));

    // C1+C2: EUDI Key Derivation (P256) witness data
    pw.set_biguint_target(&inner_ext.targets.pk_c.x.value, &pk_c_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner_ext.targets.pk_c.y.value, &pk_c_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner_ext.targets.sk_c, sk_c)?;

    // C3: Signature Verification witness data
    set_nonnative_target(&mut pw, &inner_ext.targets.msg, msg)?;
    set_nonnative_target(&mut pw, &inner_ext.targets.sig.r, sig_r)?;
    set_nonnative_target(&mut pw, &inner_ext.targets.sig.s, sig_s)?;

    // C3: Set pk_issuer (always present now, validated in static mode)
    let pk_issuer_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.x));
    let pk_issuer_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.y));
    pw.set_biguint_target(&inner_ext.targets.pk_issuer.x.value, &pk_issuer_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner_ext.targets.pk_issuer.y.value, &pk_issuer_y.to_canonical_biguint())?;

    // C4: Secp256k1 Key Derivation witness data
    pw.set_biguint_target(&inner_ext.targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner_ext.targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner_ext.targets.sk_0, sk_0)?;

    // Extended: header/payload bytes & lengths
    if input.headerB64.len() < MAX_HEADER {
        println!("Warning: headerB64 has {} entries; expected {}.", input.headerB64.len(), MAX_HEADER);
    }
    for i in 0..MAX_HEADER {
        let v = input.headerB64.get(i).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        pw.set_target(inner_ext.targets.header[i], F::from_canonical_u32(v))?;
    }
    if input.payloadB64.len() < MAX_PAYLOAD {
        println!("Warning: payloadB64 has {} entries; expected {}.", input.payloadB64.len(), MAX_PAYLOAD);
    }
    for i in 0..MAX_PAYLOAD {
        let v = input.payloadB64.get(i).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        pw.set_target(inner_ext.targets.payload[i], F::from_canonical_u32(v))?;
    }
    let header_len_u32 = input.headerB64Length.parse::<u32>().unwrap_or(0);
    let payload_len_u32 = input.payloadB64Length.parse::<u32>().unwrap_or(0);
    pw.set_target(inner_ext.targets.header_len, F::from_canonical_u32(header_len_u32))?;
    pw.set_target(inner_ext.targets.payload_len, F::from_canonical_u32(payload_len_u32))?;

    // Extended: set SHA message bits MSB-first per byte
    let mut msg_bytes: Vec<u8> = Vec::with_capacity(MAX_HEADER + 1 + MAX_PAYLOAD);
    let hlen = header_len_u32.min(MAX_HEADER as u32) as usize;
    for i in 0..MAX_HEADER {
        let b = if i < hlen { input.headerB64.get(i).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0) } else { 0 };
        msg_bytes.push(b);
    }
    msg_bytes.push(46u8);
    let plen = payload_len_u32.min(MAX_PAYLOAD as u32) as usize;
    for i in 0..MAX_PAYLOAD {
        let b = if i < plen { input.payloadB64.get(i).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0) } else { 0 };
        msg_bytes.push(b);
    }
    debug_assert_eq!(inner_ext.targets.message_bits.len(), msg_bytes.len() * 8);
    let mut k = 0;
    for &b in &msg_bytes {
        for i in (0..8).rev() {
            let bit = ((b >> i) & 1) == 1;
            pw.set_bool_target(inner_ext.targets.message_bits[k], bit)?;
            k += 1;
        }
    }

    // Extended: Base64url pk-binding parameters
    let off_x_b64 = input.offXB64.parse::<u32>().unwrap_or(0);
    let len_x_b64 = input.lenXB64.parse::<u32>().unwrap_or(0);
    let drop_x = input.dropX.parse::<u32>().unwrap_or(0);
    let len_x_inner = input.lenXInner.parse::<u32>().unwrap_or(0);
    let off_y_b64 = input.offYB64.parse::<u32>().unwrap_or(0);
    let len_y_b64 = input.lenYB64.parse::<u32>().unwrap_or(0);
    let drop_y = input.dropY.parse::<u32>().unwrap_or(0);
    let len_y_inner = input.lenYInner.parse::<u32>().unwrap_or(0);

    pw.set_target(inner_ext.targets.off_x_b64, F::from_canonical_u32(off_x_b64))?;
    pw.set_target(inner_ext.targets.len_x_b64, F::from_canonical_u32(len_x_b64))?;
    pw.set_target(inner_ext.targets.drop_x, F::from_canonical_u32(drop_x))?;
    pw.set_target(inner_ext.targets.len_x_inner, F::from_canonical_u32(len_x_inner))?;
    pw.set_target(inner_ext.targets.off_y_b64, F::from_canonical_u32(off_y_b64))?;
    pw.set_target(inner_ext.targets.len_y_b64, F::from_canonical_u32(len_y_b64))?;
    pw.set_target(inner_ext.targets.drop_y, F::from_canonical_u32(drop_y))?;
    pw.set_target(inner_ext.targets.len_y_inner, F::from_canonical_u32(len_y_inner))?;

    println!("Inner-extended witness setup time: {:?}", witness_start.elapsed());

    // Generate inner-extended proof
    println!("Generating inner-extended proof...");
    let mut timing = TimingTree::new("inner_extended_proof", Level::Info);
    let proof = prove(&inner_ext.data.prover_only, &inner_ext.data.common, pw, &mut timing)?;
    println!("Inner-extended proof timing breakdown:");
    timing.print();
    println!("Inner-extended proof size: {} bytes", proof.to_bytes().len());

    // Verify inner-extended proof
    println!("Verifying inner-extended proof...");
    let verify_start = Instant::now();
    inner_ext.data.verify(proof.clone())?;
    println!("Inner-extended proof verification time: {:?}", verify_start.elapsed());

    // Save inner-extended proof, verifier data, and common data
    println!("Serializing and saving inner-extended proof artifacts...");
    let save_start = Instant::now();

    // Save proof
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("inner_extended_proof.bin"), &proof_data)?;
    println!("Inner-extended proof saved: {} bytes", proof_data.len());

    // Save verifier data
    let verifier_data = bincode::serialize(&inner_ext.data.verifier_only)?;
    fs::write(build_dir.join("inner_extended_verifier.bin"), &verifier_data)?;
    println!("Inner-extended verifier data saved: {} bytes", verifier_data.len());

    // Save common inner_ext data
    let common_data = bincode::serialize(&inner_ext.data.common)?;
    fs::write(build_dir.join("inner_extended_common.bin"), &common_data)?;
    println!("Inner-extended common data saved: {} bytes", common_data.len());

    println!("Inner-extended proof serialization + save time: {:?}", save_start.elapsed());

    println!("=== INNER-EXTENDED PROOF COMPLETE ({}) ===", signature_mode_str);

    Ok(())
}
