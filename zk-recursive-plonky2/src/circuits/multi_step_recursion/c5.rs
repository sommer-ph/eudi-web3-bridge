use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints, add_bip32_key_derivation_constraints_fixed, Bip32KeyDerivationTargets
};
use crate::utils::bit_packing::{pack_256_bits_to_field_elements, pack_32_bits_to_field_element};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the C5 circuit (BIP32 Key Derivation + C4 recursive verification).
pub struct C5CircuitTargets {
    // Recursive verification targets
    pub c4_proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub c4_vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
    
    // Private input: parent public key (pk_0)
    pub pk_0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    // BIP32 Key Derivation targets
    pub bip32_targets: Bip32KeyDerivationTargets,
}

/// C5 circuit that implements C5 (BIP32 Key Derivation) + recursive verification of C4.
pub struct C5Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C5CircuitTargets,
}

/// Build the C5 circuit implementing:
/// - Recursive verification of C4 proof
/// - C5: BIP32 non-hardened key derivation: pk_i = KeyDer(pk_0, cc_0, i)
pub fn build_c5_circuit(
    c4_common: &CommonCircuitData<F, D>,
    use_fixed_hmac: bool,
) -> C5Circuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Recursive Proof Verification ===
    // Add targets for the proof of the C4 circuit and verify it recursively
    let c4_proof = builder.add_virtual_proof_with_pis(c4_common);
    let c4_vd = builder.add_virtual_verifier_data(c4_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&c4_proof, &c4_vd, c4_common);

    // === Private Input: Parent Public Key (pk_0) ===
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();

    // === C5: BIP32 Non-Hardened Key Derivation ===
    // Implement BIP32 key derivation: pk_i = KeyDer(pk_0, cc_0, i)
    let bip32_targets = if use_fixed_hmac {
        println!("Using optimized fixed-shape HMAC-SHA512 for BIP32 derivation...");
        add_bip32_key_derivation_constraints_fixed(&mut builder)
    } else {
        println!("Using generic HMAC-SHA512 for BIP32 derivation...");
        add_bip32_key_derivation_constraints(&mut builder)
    };

    // Connect the private pk_0 input to the BIP32 derivation targets
    builder.connect_affine_point(&pk_0, &bip32_targets.pk_0);

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
    let targets = C5CircuitTargets {
        c4_proof,
        c4_vd,
        pk_0,
        bip32_targets,
    };

    C5Circuit { data, targets }
}

/// Build the C5 circuit with fixed-shape HMAC optimization (recommended).
pub fn build_c5_circuit_optimized(c4_common: &CommonCircuitData<F, D>) -> C5Circuit {
    build_c5_circuit(c4_common, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::multi_step_recursion::c1_2::build_c1_2_circuit;
    use crate::circuits::multi_step_recursion::c3::build_c3_circuit;
    use crate::circuits::multi_step_recursion::c4::build_c4_circuit;
    use crate::types::input::SignatureMode;
    
    #[test]
    fn test_build_c5_circuit_with_static_chain() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Static);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        let c5_circuit = build_c5_circuit_optimized(&c4_circuit.data.common);
        println!("C5 circuit (static chain) built successfully");
        println!("Circuit size: {} gates", c5_circuit.data.common.degree());
    }
    
    #[test]
    fn test_build_c5_circuit_with_dynamic_chain() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Dynamic);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        let c5_circuit = build_c5_circuit_optimized(&c4_circuit.data.common);
        println!("C5 circuit (dynamic chain) built successfully");
        println!("Circuit size: {} gates", c5_circuit.data.common.degree());
    }
}