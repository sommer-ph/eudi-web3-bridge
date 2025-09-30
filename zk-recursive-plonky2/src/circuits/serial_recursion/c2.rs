//! C2 circuit implementation for public key decoding and verification (Serial Recursion variant).
//!
//! This module implements a specialized circuit that verifies:
//! - Base64url extraction and binding of pk_c from payload
//! - Ensures extracted pk_c matches the provided pk_c
//! - Recursively verifies the previous circuit (C1) proof
//!
//! The circuit reuses modular gadgets from utils:
//! - utils::base64_decode::add_pk_binding_extract
//!
//! All inputs are private except for recursive verification:
//! - payload[1024] ASCII bytes and payload_len (0..1024)
//! - Base64url extraction params: offXB64, lenXB64, dropX, lenXInner, offYB64, lenYB64, dropY, lenYInner
//! - pk_c.x, pk_c.y as 8×u32 LE limbs
//! - Previous circuit (C1) proof for recursive verification
//!
//! Public outputs:
//! - pk_c extracted and verified from the payload

use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputsTarget};
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;

use crate::utils::base64_decode as b64_g;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the C2 circuit (Public Key Decode and Check + C1 recursive verification).
pub struct C2CircuitTargets {
    // Recursive verification of C1
    pub c1_proof: ProofWithPublicInputsTarget<D>,
    pub c1_vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,

    // Public output: extracted and verified pk_c
    pub pk_c: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,

    // Private inputs
    pub payload: Vec<Target>,       // 1024 bytes
    pub payload_len: Target,        // 0..1024

    // Base64url extraction params
    pub off_x_b64: Target,
    pub len_x_b64: Target,
    pub drop_x: Target,
    pub len_x_inner: Target,
    pub off_y_b64: Target,
    pub len_y_b64: Target,
    pub drop_y: Target,
    pub len_y_inner: Target,

}

pub struct C2Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C2CircuitTargets,
}

pub fn build_c2_circuit(c1_common: &CommonCircuitData<F, D>) -> C2Circuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Recursive verification of C1 ===
    let c1_proof = builder.add_virtual_proof_with_pis(c1_common);
    let c1_vd = builder.add_virtual_verifier_data(c1_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&c1_proof, &c1_vd, c1_common);

    // === Public output: pk_c ===
    let pk_c = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_c.x.value.limbs.iter().chain(pk_c.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // === Private inputs ===
    let payload: Vec<Target> = (0..1024).map(|_| builder.add_virtual_target()).collect();
    let payload_len = builder.add_virtual_target();

    let off_x_b64 = builder.add_virtual_target();
    let len_x_b64 = builder.add_virtual_target();
    let drop_x = builder.add_virtual_target();
    let len_x_inner = builder.add_virtual_target();
    let off_y_b64 = builder.add_virtual_target();
    let len_y_b64 = builder.add_virtual_target();
    let drop_y = builder.add_virtual_target();
    let len_y_inner = builder.add_virtual_target();


    // === Base64url extraction: payload pk == pk_c ===
    let payload_arr: [Target; 1024] = core::array::from_fn(|i| payload[i]);
    let extracted = b64_g::add_pk_binding_extract(
        &mut builder,
        &payload_arr,
        off_x_b64,
        len_x_b64,
        drop_x,
        len_x_inner,
        off_y_b64,
        len_y_b64,
        drop_y,
        len_y_inner,
    );

    // Connect extracted limbs directly to public key point
    for i in 0..8 {
        builder.connect(extracted.x_limbs[i], pk_c.x.value.limbs[i].0);
        builder.connect(extracted.y_limbs[i], pk_c.y.value.limbs[i].0);
    }

    // === Consistency check: Connect C1's pk_c output with C2's pk_c ===
    // C1 proof should have pk_c as public inputs (first 16 limbs)
    // Extract C1's pk_c from its public inputs and ensure consistency
    for i in 0..8 {
        builder.connect(c1_proof.public_inputs[i], pk_c.x.value.limbs[i].0);
        builder.connect(c1_proof.public_inputs[i + 8], pk_c.y.value.limbs[i].0);
    }

    let data = builder.build::<Cfg>();
    C2Circuit {
        data,
        targets: C2CircuitTargets {
            c1_proof,
            c1_vd,
            pk_c,
            payload,
            payload_len,
            off_x_b64,
            len_x_b64,
            drop_x,
            len_x_inner,
            off_y_b64,
            len_y_b64,
            drop_y,
            len_y_inner,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::serial_recursion::c1::build_c1_circuit;

    #[test]
    fn test_build_c2_circuit() {
        // Build C1 first to get its common data
        let c1_circuit = build_c1_circuit();
        let circuit = build_c2_circuit(&c1_circuit.data.common);
        println!("C2 circuit built successfully");
        println!("Circuit size: {} gates", circuit.data.common.degree());
    }
}