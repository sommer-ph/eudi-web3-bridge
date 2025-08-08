use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints, Bip32KeyDerivationTargets
};
use crate::utils::bit_packing::{pack_256_bits_to_field_elements, pack_32_bits_to_field_element};
use crate::types::input::SignatureMode;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the outer circuit.
#[allow(dead_code)]
pub struct OuterCircuitTargets {
    // Recursive verification targets
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
    
    // BIP32 Key Derivation targets (C5)
    pub bip32_targets: Bip32KeyDerivationTargets,
}

/// Outer circuit that recursively verifies the inner proof and performs BIP32 key derivation.
#[allow(dead_code)]
pub struct OuterCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: OuterCircuitTargets,
    pub inner_signature_mode: SignatureMode,
}

/// Build the outer circuit that recursively verifies the inner proof
/// and performs BIP32 non-hardened key derivation.
/// This circuit always implements:
/// - Recursive verification of inner proof (C1-C4)
/// - C5: BIP32 non-hardened key derivation: pk_i = KeyDer(pk_0, cc_0, i)
pub fn build_outer_circuit(
    inner_common: &CommonCircuitData<F, D>,
    inner_signature_mode: SignatureMode,
) -> OuterCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // === Recursive Proof Verification ===
    // Add targets for the proof of the inner circuit and verify it recursively
    let proof = builder.add_virtual_proof_with_pis(inner_common);
    let vd = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_common);

    // === C5: BIP32 Non-Hardened Key Derivation ===
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
        
    let data = builder.build::<Cfg>();
    let targets = OuterCircuitTargets {
        proof,
        vd,
        bip32_targets,
    };
    
    OuterCircuit { 
        data, 
        targets, 
        inner_signature_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::inner::build_inner_circuit;
    
    #[test]
    fn test_build_outer_circuit_with_static_inner() {
        let inner = build_inner_circuit(SignatureMode::Static);
        let outer = build_outer_circuit(&inner.data.common, SignatureMode::Static);
        println!("Outer circuit (static inner) built successfully");
        println!("Circuit size: {} gates", outer.data.common.degree());
    }
    
    #[test]
    fn test_build_outer_circuit_with_dynamic_inner() {
        let inner = build_inner_circuit(SignatureMode::Dynamic);
        let outer = build_outer_circuit(&inner.data.common, SignatureMode::Dynamic);
        println!("Outer circuit (dynamic inner) built successfully");
        println!("Circuit size: {} gates", outer.data.common.degree());
    }
}