//! Message and public key binding circuit proof generation command.

use anyhow::Result;
use log::Level;
use plonky2::field::types::{Field, PrimeField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use std::{fs, path::Path, time::Instant};

use crate::circuits::msg_pk_c_binding::build_msg_pk_c_binding_circuit;
use crate::types::input::FullInputExtended;
use crate::utils::circuit_stats::print_circuit_stats;
use crate::utils::sha256::{MAX_HEADER, MAX_PAYLOAD};
use crate::utils::parsing::hex_to_bigint;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

pub fn generate_msg_pk_c_binding_proof(input_file: &str, build_dir: &Path) -> Result<()> {
    println!("=== MSG+PK_C BINDING CIRCUIT ===");
    println!("Loading extended input from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: FullInputExtended = serde_json::from_str(&input_data)?;

    // Build circuit
    let build_start = Instant::now();
    let circuit = build_msg_pk_c_binding_circuit();
    println!("Msg+pk_c-binding circuit built in {:?}", build_start.elapsed());
    print_circuit_stats("MSG_PK_C_BINDING", &circuit.data.common);

    // Prepare witness
    println!("Setting up msg+pk_c-binding circuit witness...");
    let witness_start = Instant::now();
    let mut pw = PartialWitness::<F>::new();

    // Set header bytes
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

    // Set lengths
    let header_len_u32 = input.headerB64Length.parse::<u32>().unwrap_or(0);
    let payload_len_u32 = input.payloadB64Length.parse::<u32>().unwrap_or(0);
    pw.set_target(circuit.targets.header_len, F::from_canonical_u32(header_len_u32))?;
    pw.set_target(circuit.targets.payload_len, F::from_canonical_u32(payload_len_u32))?;

    // Set SHA-256 message bits (MSB-first per byte) to match gated layout
    let mut msg_bytes: Vec<u8> = Vec::with_capacity(MAX_HEADER + 1 + MAX_PAYLOAD);
    let hlen = header_len_u32.min(MAX_HEADER as u32) as usize;
    for i in 0..MAX_HEADER {
        let b = if i < hlen {
            input
                .headerB64
                .get(i)
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0u8)
        } else { 0u8 };
        msg_bytes.push(b);
    }
    msg_bytes.push(46u8); // '.'
    let plen = payload_len_u32.min(MAX_PAYLOAD as u32) as usize;
    for i in 0..MAX_PAYLOAD {
        let b = if i < plen {
            input
                .payloadB64
                .get(i)
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0u8)
        } else { 0u8 };
        msg_bytes.push(b);
    }
    debug_assert_eq!(circuit.targets.message_bits.len(), msg_bytes.len() * 8, "message bit length must match");
    let mut k = 0;
    for &b in &msg_bytes {
        for i in (0..8).rev() { // MSB-first
            let bit = ((b >> i) & 1) == 1;
            pw.set_bool_target(circuit.targets.message_bits[k], bit)?;
            k += 1;
        }
    }

    // Set expected msg (digest)
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    pw.set_biguint_target(&circuit.targets.msg.value, &msg.to_canonical_biguint())?;

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

    // pk_c limbs (little-endian u32 words from big-endian 32 bytes)
    fn hex_to_limbs_le(hex: &str) -> [u32; 8] {
        let mut be = [0u8; 32];
        let bytes = hex::decode(hex.trim_start_matches("0x")).unwrap_or_default();
        let src = if bytes.len() > 32 { &bytes[bytes.len() - 32..] } else { &bytes[..] };
        be[32 - src.len()..].copy_from_slice(src);
        let mut limbs = [0u32; 8];
        for i in 0..8 {
            let start = 32 - (i + 1) * 4;
            limbs[i] = u32::from_be_bytes([
                be[start], be[start + 1], be[start + 2], be[start + 3],
            ]);
        }
        limbs
    }
    let pkc_x_limbs = hex_to_limbs_le(&input.pk_c.x);
    let pkc_y_limbs = hex_to_limbs_le(&input.pk_c.y);
    for i in 0..8 { pw.set_target(circuit.targets.pkc_x_limbs[i], F::from_canonical_u32(pkc_x_limbs[i]))?; }
    for i in 0..8 { pw.set_target(circuit.targets.pkc_y_limbs[i], F::from_canonical_u32(pkc_y_limbs[i]))?; }

    println!("Msg+pk_c-binding witness setup time: {:?}", witness_start.elapsed());

    // Prove
    println!("Generating msg+pk_c-binding proof...");
    let mut timing = TimingTree::new("msg_pk_c_binding_proof", Level::Info);
    let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing)?;
    timing.print();
    println!("Msg+pk_c-binding proof size: {} bytes", proof.to_bytes().len());

    // Verify
    println!("Verifying msg+pk_c-binding proof...");
    let verify_start = Instant::now();
    circuit.data.verify(proof.clone())?;
    println!("Msg+pk_c-binding proof verification time: {:?}", verify_start.elapsed());

    // Save artifacts
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("msg_pk_c_binding_proof.bin"), &proof_data)?;
    let verifier_data = bincode::serialize(&circuit.data.verifier_only)?;
    fs::write(build_dir.join("msg_pk_c_binding_verifier.bin"), &verifier_data)?;
    let common_data = bincode::serialize(&circuit.data.common)?;
    fs::write(build_dir.join("msg_pk_c_binding_common.bin"), &common_data)?;
    println!(
        "Msg+pk_c-binding artifacts saved: proof={}, verifier={}, common={}",
        proof_data.len(), verifier_data.len(), common_data.len()
    );

    println!("=== MSG+PK_C BINDING CIRCUIT COMPLETE ===");
    Ok(())
}
