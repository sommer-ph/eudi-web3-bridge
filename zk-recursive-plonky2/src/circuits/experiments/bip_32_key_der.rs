use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints, Bip32KeyDerivationTargets
};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets returned when building the BIP32 key derivation circuit.
pub struct Bip32KeyDerCircuitTargets {
    pub bip32_targets: Bip32KeyDerivationTargets,
}

/// Circuit and targets for the BIP32 key derivation circuit.
pub struct Bip32KeyDerCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: Bip32KeyDerCircuitTargets,
}

/// Build the BIP32 key derivation circuit that performs non-hardened key derivation
/// without recursive verification.
/// This circuit:
/// 1. Performs BIP32 non-hardened key derivation: (pk_i, cc_i) = KeyDer(pk_0, cc_0, i)
/// 2. Uses cc_0, i, pk_i, and cc_i as public inputs and pk_0 as private input
/// 3. Verifies that the computed pk_i matches the expected public input
/// 4. Verifies that the computed cc_i matches the expected public input
pub fn build_bip32_key_der_circuit() -> Bip32KeyDerCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // === BIP32 Non-Hardened Key Derivation ===
    // Implement BIP32 key derivation: (pk_i, cc_i) = KeyDer(pk_0, cc_0, i)
    let bip32_targets = add_bip32_key_derivation_constraints(&mut builder);
    
    // === Public Inputs Registration ===
    // Register cc_0 as public input
    for cc_0_bit in &bip32_targets.cc_0 {
        builder.register_public_input(cc_0_bit.target);
    }
    
    // Register derivation index as public input 
    for derivation_index_bit in &bip32_targets.derivation_index {
        builder.register_public_input(derivation_index_bit.target);
    }
    
    // Register pk_i as public input
    for limb in bip32_targets.pk_i.x.value.limbs.iter().chain(
        bip32_targets.pk_i.y.value.limbs.iter()
    ) {
        builder.register_public_input(limb.0);
    }
    
    // Register cc_i as public input (derived from HMAC)
    for cc_i_bit in &bip32_targets.cc_i {
        builder.register_public_input(cc_i_bit.target);
    }
    
    let data = builder.build::<Cfg>();
    let targets = Bip32KeyDerCircuitTargets {
        bip32_targets,
    };
    Bip32KeyDerCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::field::types::{Sample, PrimeField, Field};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2_ecdsa::curve::ecdsa::ECDSASecretKey;
    use plonky2_ecdsa::curve::secp256k1::Secp256K1;
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
    use num_bigint::BigUint;

    #[test]
    #[ignore]
    fn test_bip32_key_derivation() -> Result<()> {
        use std::time::Instant;
        
        println!("=== BIP32 KEY DERIVATION CIRCUIT TEST ===");
        let total_start = Instant::now();

        println!("\n=== BUILDING BIP32 KEY DERIVATION CIRCUIT ===");
        
        // Build BIP32 key derivation circuit
        let circuit_start = Instant::now();
        let circuit = build_bip32_key_der_circuit();
        println!("BIP32 key derivation circuit building time: {:?}", circuit_start.elapsed());
        println!("BIP32 key derivation circuit size: {} gates", circuit.data.common.degree());

        println!("\nGenerating BIP32 key derivation test data...");
        let data_start = Instant::now();
        
        // Generate test BIP32 data
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
        
        println!("BIP32 test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up BIP32 key derivation circuit witness...");
        let witness_start = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        
        // Set parent public key (private input - not revealed in proof)
        pw.set_biguint_target(&circuit.targets.bip32_targets.pk_0.x.value, &pk_0.x.to_canonical_biguint())?;
        pw.set_biguint_target(&circuit.targets.bip32_targets.pk_0.y.value, &pk_0.y.to_canonical_biguint())?;
        
        // Set parent chain code (public input)
        let parent_chain_code_bits: Vec<bool> = cc_0.iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .collect();
        for (i, &bit) in parent_chain_code_bits.iter().enumerate() {
            pw.set_bool_target(circuit.targets.bip32_targets.cc_0[i], bit)?;
        }
        
        // Set child index bits (public input)
        let child_index_bits: Vec<bool> = (0..32).rev()
            .map(|i| (derivation_index >> i) & 1 == 1)
            .collect();
        for (i, &bit) in child_index_bits.iter().enumerate() {
            pw.set_bool_target(circuit.targets.bip32_targets.derivation_index[i], bit)?;
        }
        
        // Set expected child public key (public input to verify against)
        pw.set_biguint_target(&circuit.targets.bip32_targets.pk_i.x.value, &expected_child_public_key.x.to_canonical_biguint())?;
        pw.set_biguint_target(&circuit.targets.bip32_targets.pk_i.y.value, &expected_child_public_key.y.to_canonical_biguint())?;
        
        // Set expected child chain code (public input to verify against)
        let child_chain_code_bits: Vec<bool> = child_chain_code_bytes.iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .collect();
        for (i, &bit) in child_chain_code_bits.iter().enumerate() {
            pw.set_bool_target(circuit.targets.bip32_targets.cc_i[i], bit)?;
        }
        
        println!("BIP32 witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating BIP32 key derivation proof...");
        let prove_start = Instant::now();
        let proof = circuit.data.prove(pw)?;
        let prove_time = prove_start.elapsed();
        println!("BIP32 key derivation proof generation time: {:?}", prove_time);
        println!("BIP32 key derivation proof size: {} bytes", proof.to_bytes().len());

        println!("\nVerifying BIP32 key derivation proof...");
        let verify_start = Instant::now();
        let result = circuit.data.verify(proof);
        println!("BIP32 key derivation proof verification time: {:?}", verify_start.elapsed());
        
        let total_time = total_start.elapsed();
        println!("BIP32 key derivation circuit total time: {:?}", total_time);
        
        println!("\n=== BIP32 KEY DERIVATION TEST COMPLETE ===\n");
        
        result
    }
}