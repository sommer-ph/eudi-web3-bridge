use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints, Bip32KeyDerivationTargets
};
use crate::utils::bit_packing::{pack_256_bits_to_field_elements, pack_32_bits_to_field_element};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets returned when building the outer extended circuit.
#[allow(dead_code)]
pub struct OuterExtendedCircuitTargets {
    // Recursive verification targets
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
    
    // BIP32 Key Derivation targets
    pub bip32_targets: Bip32KeyDerivationTargets,
}

/// Circuit and targets for the outer extended recursive circuit.
#[allow(dead_code)]
pub struct OuterExtendedCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: OuterExtendedCircuitTargets,
}

/// Build the outer extended circuit that recursively verifies the inner extended proof
/// and performs BIP32 non-hardened key derivation.
/// This circuit:
/// 1. Recursively verifies the inner extended EUDI + secp256k1 proof
/// 2. Performs BIP32 non-hardened key derivation: pk_i = KeyDer(pk_0, cc_0, i)
/// 3. Uses cc_0, i, and pk_i as public inputs and pk_0 as private input
/// 4. Verifies that the computed pk_i matches the expected public input
pub fn build_outer_extended_circuit(
    inner_extended_common: &CommonCircuitData<F, D>
) -> OuterExtendedCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // === Recursive Proof Verification ===
    // Add targets for the proof of the inner extended circuit and verify it recursively
    let proof = builder.add_virtual_proof_with_pis(inner_extended_common);
    let vd = builder.add_virtual_verifier_data(inner_extended_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_extended_common);

    // === BIP32 Non-Hardened Key Derivation ===
    // Implement BIP32 key derivation: pk_i = KeyDer(pk_0, cc_0, i)
    let bip32_targets = add_bip32_key_derivation_constraints(&mut builder);
    
    // === Public Inputs Registration (Optimized with Bit Packing) ===
    println!("Optimizing public inputs: Packing bits into field elements...");
    
    // Pack cc_0 (256 bits) into 4 field elements
    let cc_0_packed = pack_256_bits_to_field_elements(&bip32_targets.cc_0, &mut builder);
    for &target in &cc_0_packed {
        builder.register_public_input(target);
    }
    
    // Pack derivation_index (32 bits) into 1 field element  
    let index_packed = pack_32_bits_to_field_element(&bip32_targets.derivation_index, &mut builder);
    builder.register_public_input(index_packed);
    
    // Register pk_i as public input
    for limb in bip32_targets.pk_i.x.value.limbs.iter().chain(
        bip32_targets.pk_i.y.value.limbs.iter()
    ) {
        builder.register_public_input(limb.0);
    }
    
    // Pack cc_i (256 bits) into 4 field elements
    let cc_i_packed = pack_256_bits_to_field_elements(&bip32_targets.cc_i, &mut builder);
    for &target in &cc_i_packed {
        builder.register_public_input(target);
    }
    
    println!("Public input optimization: 560 bits -> ~17 field elements (256+32+256 bits packed + pk_i limbs)");
    
    let data = builder.build::<Cfg>();
    let targets = OuterExtendedCircuitTargets {
        proof,
        vd,
        bip32_targets,
    };
    OuterExtendedCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::inner_extended::build_inner_extended_circuit;
    use anyhow::Result;
    use plonky2::field::types::{Sample, PrimeField, Field};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
    use plonky2_ecdsa::curve::p256::P256;
    use plonky2_ecdsa::curve::secp256k1::Secp256K1;
    use plonky2_ecdsa::field::p256_scalar::P256Scalar;
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
    use num_bigint::BigUint;

    #[test]
    #[ignore]
    fn test_recursive_extended_proof() -> Result<()> {
        use std::time::Instant;
        
        println!("=== RECURSIVE EXTENDED ZK-SNARK PROOF SYSTEM ===");
        let total_start = Instant::now();

        println!("\n=== INNER EXTENDED CIRCUIT: EUDI + SECP256K1 ===");
        
        // Build inner extended circuit and generate witness.
        let inner_start = Instant::now();
        let inner_extended = build_inner_extended_circuit();
        println!("Inner extended circuit building time: {:?}", inner_start.elapsed());
        println!("Inner extended circuit size: {} gates", inner_extended.data.common.degree());

        println!("\nGenerating inner extended circuit test data...");
        let data_start = Instant::now();
        
        // P256 test data
        let msg = P256Scalar::rand();
        let sk_issuer_val = P256Scalar::rand();
        let sk_issuer = ECDSASecretKey::<P256>(sk_issuer_val);
        let pk_issuer = sk_issuer.to_public().0;
        let sig = sign_message(msg, sk_issuer);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk_c = sk_c.to_public().0;

        // Secp256k1 test data
        let sk_0_val = Secp256K1Scalar::rand();
        let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_val);
        let pk_0 = sk_0.to_public().0;

        println!("Inner extended test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up inner extended circuit witness...");
        let witness_start = Instant::now();
        let mut pw1 = PartialWitness::<F>::new();
        
        // P256 witness data
        pw1.set_biguint_target(&inner_extended.targets.pk_issuer.x.value, &pk_issuer.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&inner_extended.targets.pk_issuer.y.value, &pk_issuer.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &inner_extended.targets.msg, msg)?;
        set_nonnative_target(&mut pw1, &inner_extended.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw1, &inner_extended.targets.sig.s, sig.s)?;
        pw1.set_biguint_target(&inner_extended.targets.pk_c.x.value, &pk_c.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&inner_extended.targets.pk_c.y.value, &pk_c.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &inner_extended.targets.sk_c, sk_c_val)?;

        // Secp256k1 witness data
        pw1.set_biguint_target(&inner_extended.targets.pk_0.x.value, &pk_0.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&inner_extended.targets.pk_0.y.value, &pk_0.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &inner_extended.targets.sk_0, sk_0_val)?;

        println!("Inner extended witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating inner extended circuit proof...");
        let prove1_start = Instant::now();
        let proof1 = inner_extended.data.prove(pw1)?;
        let prove1_time = prove1_start.elapsed();
        println!("Inner extended proof generation time: {:?}", prove1_time);
        println!("Inner extended proof size: {} bytes", proof1.to_bytes().len());

        println!("\nVerifying inner extended circuit proof...");
        let verify1_start = Instant::now();
        inner_extended.data.verify(proof1.clone())?;
        println!("Inner extended proof verification time: {:?}", verify1_start.elapsed());
        
        let inner_total = inner_start.elapsed();
        println!("Inner extended circuit total time: {:?}", inner_total);

        println!("\n=== OUTER EXTENDED CIRCUIT: RECURSIVE VERIFICATION ===");

        // Build outer extended circuit and prove recursively.
        let outer_start = Instant::now();
        let outer_extended = build_outer_extended_circuit(&inner_extended.data.common);
        println!("Outer extended circuit building time: {:?}", outer_start.elapsed());
        println!("Outer extended circuit size: {} gates", outer_extended.data.common.degree());

        println!("\nSetting up outer extended circuit witness...");
        let witness2_start = Instant::now();
        let mut pw2 = PartialWitness::<F>::new();
        pw2.set_proof_with_pis_target(&outer_extended.targets.proof, &proof1)?;
        pw2.set_verifier_data_target(&outer_extended.targets.vd, &inner_extended.data.verifier_only)?;
        
        // Set BIP32 witness data using pure public-to-public derivation
        use crate::utils::parsing::set_nonnative_target;
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        use k256::SecretKey;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        
        type HmacSha512 = Hmac<Sha512>;
        
        // Generate test BIP32 data for reference computation
        let sk_0_val = Secp256K1Scalar::rand();
        let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_val);
        let pk_0 = sk_0.to_public().0;
        let cc_0 = [42u8; 32];
        let derivation_index = 0u32; // First non-hardened child
        
        // Compute expected child public key using reference BIP32 implementation
        let parent_key_bytes = sk_0_val.to_canonical_biguint().to_bytes_be();
        let mut key_array = [0u8; 32];
        let len = parent_key_bytes.len().min(32);
        key_array[32-len..].copy_from_slice(&parent_key_bytes[..len]);
        let parent_pk_k256 = SecretKey::from_bytes((&key_array).into())?;
        let parent_pubkey_k256 = parent_pk_k256.public_key();
        let parent_pubkey_compressed = parent_pubkey_k256.to_encoded_point(true);
        
        // Create HMAC input: compressed_parent_pubkey || child_index
        let mut hmac_input = parent_pubkey_compressed.as_bytes().to_vec();
        hmac_input.extend_from_slice(&derivation_index.to_be_bytes());
        
        // Compute HMAC-SHA512
        let mut hmac = HmacSha512::new_from_slice(&cc_0)?;
        hmac.update(&hmac_input);
        let hmac_result = hmac.finalize().into_bytes();
        
        // Extract I_L and child chain code
        let il_bytes = &hmac_result[0..32];
        let child_chain_code_bytes = &hmac_result[32..64];
        
        // Compute expected child public key using ECC point addition
        let il_scalar = Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_bytes_be(il_bytes)
        );
        
        // Use the ECDSASecretKey to compute I_L * G properly
        let il_secret_key = ECDSASecretKey::<Secp256K1>(il_scalar);
        let il_point = il_secret_key.to_public().0;
        
        // Child public key = parent public key + I_L * G (using projective addition)
        let expected_child_public_key = (pk_0.to_projective() + il_point.to_projective()).to_affine();
        
        // Set parent public key (private input - not revealed in proof)
        pw2.set_biguint_target(&outer_extended.targets.bip32_targets.pk_0.x.value, &pk_0.x.to_canonical_biguint())?;
        pw2.set_biguint_target(&outer_extended.targets.bip32_targets.pk_0.y.value, &pk_0.y.to_canonical_biguint())?;
        
        // Set parent chain code (public input)
        let parent_chain_code_bits: Vec<bool> = cc_0.iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .collect();
        for (i, &bit) in parent_chain_code_bits.iter().enumerate() {
            pw2.set_bool_target(outer_extended.targets.bip32_targets.cc_0[i], bit)?;
        }
        
        // Set child index bits (public input)
        let child_index_bits: Vec<bool> = (0..32).rev()
            .map(|i| (derivation_index >> i) & 1 == 1)
            .collect();
        for (i, &bit) in child_index_bits.iter().enumerate() {
            pw2.set_bool_target(outer_extended.targets.bip32_targets.derivation_index[i], bit)?;
        }
        
        // Set expected child public key (public input to verify against)
        pw2.set_biguint_target(&outer_extended.targets.bip32_targets.pk_i.x.value, &expected_child_public_key.x.to_canonical_biguint())?;
        pw2.set_biguint_target(&outer_extended.targets.bip32_targets.pk_i.y.value, &expected_child_public_key.y.to_canonical_biguint())?;
        
        // Set expected child chain code (public input to verify against)
        let child_chain_code_bits: Vec<bool> = child_chain_code_bytes.iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .collect();
        for (i, &bit) in child_chain_code_bits.iter().enumerate() {
            pw2.set_bool_target(outer_extended.targets.bip32_targets.cc_i[i], bit)?;
        }
        
        println!("Outer extended witness setup time: {:?}", witness2_start.elapsed());

        println!("\nGenerating outer extended circuit recursive proof...");
        let prove2_start = Instant::now();
        let proof2 = outer_extended.data.prove(pw2)?;
        let prove2_time = prove2_start.elapsed();
        println!("Outer extended proof generation time: {:?}", prove2_time);
        println!("Outer extended proof size: {} bytes", proof2.to_bytes().len());

        println!("\nVerifying outer extended circuit recursive proof...");
        let verify2_start = Instant::now();
        let result = outer_extended.data.verify(proof2);
        println!("Outer extended proof verification time: {:?}", verify2_start.elapsed());
        
        let outer_total = outer_start.elapsed();
        println!("Outer extended circuit total time: {:?}", outer_total);
        
        println!("\n=== PERFORMANCE SUMMARY ===");
        println!("Inner Extended Circuit (EUDI + secp256k1) total time: {:?}", inner_total);
        println!("Outer Extended Circuit (Recursive) total time: {:?}", outer_total);
        println!("Total recursive extended proof system time: {:?}", total_start.elapsed());
        println!("=== RECURSIVE EXTENDED PROOF COMPLETE ===\n");
        
        result
    }
}