use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the C1_2 circuit (EUDI wallet key derivation + credential public key check + msg_pk_c_binding recursive verification).
pub struct C1_2CircuitTargets {
    // Recursive verification targets
    pub msg_pk_c_binding_proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub msg_pk_c_binding_vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,

    pub pk_c: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
}

/// C1_2 circuit that implements C1 (EUDI wallet key derivation) + C2 (Credential public key check) + recursive verification of msg_pk_c_binding.
pub struct C1_2Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C1_2CircuitTargets,
}

/// Build the C1_2 circuit implementing:
/// - Recursive verification of msg_pk_c_binding proof
/// - C1: pk_c = KeyDer(sk_c) - EUDI wallet key derivation over P256
/// - C2: pk_c === pk_c_calc - Public key equality check (pk_c extracted from EUDI credential)
pub fn build_c1_2_circuit(
    msg_pk_c_binding_common: &CommonCircuitData<F, D>,
) -> C1_2Circuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Recursive Proof Verification ===
    // Add targets for the proof of the msg_pk_c_binding circuit and verify it recursively
    let msg_pk_c_binding_proof = builder.add_virtual_proof_with_pis(msg_pk_c_binding_common);
    let msg_pk_c_binding_vd = builder.add_virtual_verifier_data(msg_pk_c_binding_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&msg_pk_c_binding_proof, &msg_pk_c_binding_vd, msg_pk_c_binding_common);

    // Public input: EUDI public key (pk_c)
    let pk_c = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_c.x.value.limbs.iter().chain(pk_c.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private input: EUDI wallet secret key (P256)
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // === C1: EUDI Wallet Key Derivation (pk_c = KeyDer(sk_c)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk_c_calc =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);

    // === C2: Credential Public Key Check (pk_c === pk_c_calc) ===
    // Ensure the derived public key matches the public input
    builder.connect_affine_point(&pk_c_calc, &pk_c);

    let data = builder.build::<Cfg>();
    let targets = C1_2CircuitTargets {
        msg_pk_c_binding_proof,
        msg_pk_c_binding_vd,
        pk_c,
        sk_c
    };

    C1_2Circuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_c1_2_circuit() {
        use super::super::msg_pk_c_binding::build_msg_pk_c_binding_circuit;
        let msg_pk_c_binding_circuit = build_msg_pk_c_binding_circuit();
        let circuit = build_c1_2_circuit(&msg_pk_c_binding_circuit.data.common);
        println!("C1_2 circuit built successfully");
        println!("Circuit size: {} gates", circuit.data.common.degree());
    }
}