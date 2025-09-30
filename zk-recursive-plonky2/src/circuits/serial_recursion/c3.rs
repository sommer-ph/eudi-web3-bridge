use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::ecdsa::{
    verify_p256_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecdsa::add_static_pk_ecdsa_verify_constraints;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2::field::types::Field;

use crate::types::input::SignatureMode;
use crate::utils::sha256 as sha_g;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

// Fixed issuer public key values
const STATIC_PK_ISSUER_X: &str = "66432692286261411630769223098970693805397596870633670159153355502222145619968";
const STATIC_PK_ISSUER_Y: &str = "63182586149833488067701290985084360701345487374231728189741684364091950142361";

/// Targets for the C3 circuit (Hash calculation + EUDI credential signature Verification + C2 recursive verification).
pub struct C3CircuitTargets {
    // Recursive verification targets
    pub c2_proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub c2_vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,

    // Public input: issuer public key (always present, validated in static mode)
    pub pk_issuer: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,

    // Private inputs: message and signature
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,

    // SHA-256 hash calculation inputs
    pub header: Vec<Target>,        // 64 bytes
    pub payload: Vec<Target>,       // 1024 bytes
    pub header_len: Target,         // 0..64
    pub payload_len: Target,        // 0..1024
    pub message_bits: Vec<BoolTarget>, // MSB-first, len 8640
}

/// C3 circuit that implements Hash calculation + C3 (Signature Verification) + recursive verification of C2.
pub struct C3Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C3CircuitTargets,
    pub signature_mode: SignatureMode,
}

/// Build the C3 circuit implementing:
/// - Recursive verification of C2 proof
/// - SHA-256(header '.' payload) == msg verification
/// - C3: SigVerify(pk_issuer, msg, sig) - Credential signature verification over P256
/// - In static mode: additionally validates that pk_issuer matches fixed values
pub fn build_c3_circuit(
    c2_common: &CommonCircuitData<F, D>,
    signature_mode: SignatureMode,
) -> C3Circuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true; 
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Recursive Proof Verification ===
    // Add targets for the proof of the C2 circuit and verify it recursively
    let c2_proof = builder.add_virtual_proof_with_pis(c2_common);
    let c2_vd = builder.add_virtual_verifier_data(c2_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&c2_proof, &c2_vd, c2_common);

    // === Public Input: Issuer Public Key (always present) ===
    let pk_issuer = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_issuer.x.value.limbs.iter().chain(pk_issuer.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // === Private Inputs ===
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    // SHA-256 inputs
    let header: Vec<Target> = (0..sha_g::MAX_HEADER).map(|_| builder.add_virtual_target()).collect();
    let payload: Vec<Target> = (0..sha_g::MAX_PAYLOAD).map(|_| builder.add_virtual_target()).collect();
    let header_len = builder.add_virtual_target();
    let payload_len = builder.add_virtual_target();

    // === SHA-256(header '.' payload) == msg ===
    let header_arr: [Target; sha_g::MAX_HEADER] = core::array::from_fn(|i| header[i]);
    let payload_arr: [Target; sha_g::MAX_PAYLOAD] = core::array::from_fn(|i| payload[i]);
    let sha_targets = sha_g::add_sha256_header_dot_payload_equals_msg(
        &mut builder,
        &header_arr,
        &payload_arr,
        header_len,
        payload_len,
        &msg,
    );

    // === C3: Credential Signature Verification ===
    match signature_mode {
        SignatureMode::Dynamic => {
            // Dynamic mode: pk_issuer from public input is used directly
            let pk_target = ECDSAPublicKeyTarget(pk_issuer.clone());
            verify_p256_message_circuit(&mut builder, msg.clone(), signature.clone(), pk_target);
        }
        SignatureMode::Static => {
            // Static mode: use hardcoded issuer public key with lookup table optimization
            add_static_pk_ecdsa_verify_constraints(&mut builder, msg.clone(), signature.clone());
            
            // Additionally validate that pk_issuer matches the fixed static values
            let expected_x = BigUint::from_str_radix(STATIC_PK_ISSUER_X, 10).unwrap();
            let expected_y = BigUint::from_str_radix(STATIC_PK_ISSUER_Y, 10).unwrap();
            
            // Add constraints to ensure pk_issuer matches expected values
            // Use the p256_base field for the coordinates
            use plonky2_ecdsa::field::p256_base::P256Base;
            let expected_x_target = builder.constant_nonnative(P256Base::from_noncanonical_biguint(expected_x));
            let expected_y_target = builder.constant_nonnative(P256Base::from_noncanonical_biguint(expected_y));
            
            builder.connect_nonnative(&pk_issuer.x, &expected_x_target);
            builder.connect_nonnative(&pk_issuer.y, &expected_y_target);
        }
    }

    let data = builder.build::<Cfg>();
    let targets = C3CircuitTargets {
        c2_proof,
        c2_vd,
        pk_issuer,
        msg,
        sig: signature,
        header,
        payload,
        header_len,
        payload_len,
        message_bits: sha_targets.message_bits,
    };

    C3Circuit {
        data,
        targets,
        signature_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::serial_recursion::c1::build_c1_circuit;
    use crate::circuits::serial_recursion::c2::build_c2_circuit;

    #[test]
    fn test_build_c3_circuit_static() {
        let c1_circuit = build_c1_circuit();
        let c2_circuit = build_c2_circuit(&c1_circuit.data.common);
        let c3_circuit = build_c3_circuit(&c2_circuit.data.common, SignatureMode::Static);
        println!("C3 circuit (static mode) built successfully");
        println!("Circuit size: {} gates", c3_circuit.data.common.degree());
    }

    #[test]
    fn test_build_c3_circuit_dynamic() {
        let c1_circuit = build_c1_circuit();
        let c2_circuit = build_c2_circuit(&c1_circuit.data.common);
        let c3_circuit = build_c3_circuit(&c2_circuit.data.common, SignatureMode::Dynamic);
        println!("C3 circuit (dynamic mode) built successfully");
        println!("Circuit size: {} gates", c3_circuit.data.common.degree());
    }
}