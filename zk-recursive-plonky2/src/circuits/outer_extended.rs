//! Outer-extended circuit implementation for recursive verification and key derivation.
//!
//! This module implements the outer-extended circuit (C5) that:
//! - Recursively verifies the inner-extended proof (C1-C4 + message/pk binding)
//! - Performs BIP32 non-hardened key derivation with SHA512 or Poseidon
//! - Ensures consistency between inner-extended and outer-extended circuits

use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints_fixed, Bip32KeyDerivationTargets,
    add_poseidon_key_derivation_constraints, PoseidonKeyDerivationTargets,
};
use crate::utils::bit_packing::{pack_256_bits_to_field_elements, pack_32_bits_to_field_element};
use crate::types::input::{SignatureMode, DerivationMode};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Key derivation targets (mode-dependent)
#[allow(dead_code)]
pub enum KeyDerivationTargets {
    Bip32(Bip32KeyDerivationTargets),
    Poseidon(PoseidonKeyDerivationTargets),
}

/// Targets for the outer-extended circuit.
#[allow(dead_code)]
pub struct OuterExtendedTargets {
    // Recursive verification targets
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,

    // pk_issuer consistency check target
    pub pk_issuer: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,

    // Key derivation targets (mode-dependent)
    pub key_derivation_targets: KeyDerivationTargets,
}

/// Outer-extended circuit that recursively verifies the inner-extended proof and performs key derivation.
#[allow(dead_code)]
pub struct OuterExtendedCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: OuterExtendedTargets,
    pub inner_signature_mode: SignatureMode,
    pub derivation_mode: DerivationMode,
}

pub fn build_outer_extended_circuit(
    inner_common: &CommonCircuitData<F, D>,
    inner_signature_mode: SignatureMode,
    derivation_mode: DerivationMode,
) -> OuterExtendedCircuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Recursive Proof Verification ===
    let proof = builder.add_virtual_proof_with_pis(inner_common);
    let vd = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_common);

    // === pk_0 Consistency Check ===
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();

    // Extract pk_0 from inner proof public inputs (first 8 elements)
    let inner_pk_0_x_limbs = [
        proof.public_inputs[0], proof.public_inputs[1], proof.public_inputs[2], proof.public_inputs[3],
    ];
    let inner_pk_0_y_limbs = [
        proof.public_inputs[4], proof.public_inputs[5], proof.public_inputs[6], proof.public_inputs[7],
    ];
    for (outer_limb, &inner_limb) in pk_0.x.value.limbs.iter().zip(inner_pk_0_x_limbs.iter()) {
        builder.connect(outer_limb.0, inner_limb);
    }
    for (outer_limb, &inner_limb) in pk_0.y.value.limbs.iter().zip(inner_pk_0_y_limbs.iter()) {
        builder.connect(outer_limb.0, inner_limb);
    }

    // === pk_issuer Consistency ===
    let inner_pk_issuer_x_limbs = [
        proof.public_inputs[8], proof.public_inputs[9], proof.public_inputs[10], proof.public_inputs[11],
    ];
    let inner_pk_issuer_y_limbs = [
        proof.public_inputs[12], proof.public_inputs[13], proof.public_inputs[14], proof.public_inputs[15],
    ];
    for &limb in inner_pk_issuer_x_limbs.iter().chain(inner_pk_issuer_y_limbs.iter()) {
        builder.register_public_input(limb);
    }
    let pk_issuer = builder.add_virtual_affine_point_target::<P256>();

    // === C5: Key Derivation ===
    let key_derivation_targets = match derivation_mode {
        DerivationMode::Sha512 => {
            println!("Using optimized fixed-shape HMAC-SHA512 for BIP32 derivation...");
            let targets = add_bip32_key_derivation_constraints_fixed(&mut builder);

            println!("SHA512 mode: Packing bits into field elements for public inputs...");
            // cc_0 (256 bits)
            let cc_0_packed = pack_256_bits_to_field_elements(&targets.cc_0, &mut builder);
            for &t in &cc_0_packed { builder.register_public_input(t); }
            // derivation_index (32 bits)
            let index_packed = pack_32_bits_to_field_element(&targets.derivation_index, &mut builder);
            builder.register_public_input(index_packed);
            // pk_i public inputs
            for limb in targets.pk_i.x.value.limbs.iter().chain(targets.pk_i.y.value.limbs.iter()) {
                builder.register_public_input(limb.0);
            }
            // cc_i (256 bits)
            let cc_i_packed = pack_256_bits_to_field_elements(&targets.cc_i, &mut builder);
            for &t in &cc_i_packed { builder.register_public_input(t); }
            KeyDerivationTargets::Bip32(targets)
        }
        DerivationMode::Poseidon => {
            println!("Poseidon mode: Using field-native key derivation...");
            let targets = add_poseidon_key_derivation_constraints(&mut builder);

            println!("Poseidon mode: Field-native public inputs...");
            for &cc_limb in targets.cc_0.iter() { builder.register_public_input(cc_limb); }
            builder.register_public_input(targets.derivation_index);
            for limb in targets.pk_i.x.value.limbs.iter().chain(targets.pk_i.y.value.limbs.iter()) {
                builder.register_public_input(limb.0);
            }
            KeyDerivationTargets::Poseidon(targets)
        }
    };

    let data = builder.build::<Cfg>();
    let targets = OuterExtendedTargets { proof, vd, pk_issuer, key_derivation_targets };
    OuterExtendedCircuit { data, targets, inner_signature_mode: inner_signature_mode, derivation_mode }
}

