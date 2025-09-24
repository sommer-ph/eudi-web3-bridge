//! Message and public key binding circuit implementation for serial recursion.
//!
//! This module implements a specialized circuit that verifies:
//! - SHA-256(header '.' payload) == msg verification
//! - Base64url extraction and binding of pk_c from payload
//!
//! The circuit reuses modular gadgets from utils:
//! - utils::sha256::add_sha256_header_dot_payload_equals_msg
//! - utils::base64_decode::add_pk_binding_extract
//!
//! All inputs are private:
//! - header[64] ASCII bytes and header_len (0..64)
//! - payload[1024] ASCII bytes and payload_len (0..1024)
//! - msg as P256 scalar (SHA-256 digest)
//! - Base64url extraction params: offXB64, lenXB64, dropX, lenXInner, offYB64, lenYB64, dropY, lenYInner
//! - pk_c.x, pk_c.y as 8×u32 LE limbs

use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

use crate::utils::sha256 as sha_g;
use crate::utils::base64_decode as b64_g;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the message/pk_c binding circuit.
pub struct MsgPkCBindingTargets {
    // SHA-256 inputs/outputs
    pub header: Vec<Target>,        // 64 bytes
    pub payload: Vec<Target>,       // 1024 bytes
    pub header_len: Target,         // 0..64
    pub payload_len: Target,        // 0..1024
    pub msg: NonNativeTarget<P256Scalar>,
    pub message_bits: Vec<BoolTarget>, // MSB-first, len 8640

    // Base64url extraction params
    pub off_x_b64: Target,
    pub len_x_b64: Target,
    pub drop_x: Target,
    pub len_x_inner: Target,
    pub off_y_b64: Target,
    pub len_y_b64: Target,
    pub drop_y: Target,
    pub len_y_inner: Target,

    // pk_c limbs to compare with extracted limbs
    pub pkc_x_limbs: Vec<Target>,
    pub pkc_y_limbs: Vec<Target>,
}

pub struct MsgPkCBindingCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: MsgPkCBindingTargets,
}

pub fn build_msg_pk_c_binding_circuit() -> MsgPkCBindingCircuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Private inputs ===
    let header: Vec<Target> = (0..sha_g::MAX_HEADER).map(|_| builder.add_virtual_target()).collect();
    let payload: Vec<Target> = (0..sha_g::MAX_PAYLOAD).map(|_| builder.add_virtual_target()).collect();
    let header_len = builder.add_virtual_target();
    let payload_len = builder.add_virtual_target();
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();

    let off_x_b64 = builder.add_virtual_target();
    let len_x_b64 = builder.add_virtual_target();
    let drop_x = builder.add_virtual_target();
    let len_x_inner = builder.add_virtual_target();
    let off_y_b64 = builder.add_virtual_target();
    let len_y_b64 = builder.add_virtual_target();
    let drop_y = builder.add_virtual_target();
    let len_y_inner = builder.add_virtual_target();

    let mut pkc_x_limbs = Vec::with_capacity(8);
    let mut pkc_y_limbs = Vec::with_capacity(8);
    for _ in 0..8 { pkc_x_limbs.push(builder.add_virtual_target()); }
    for _ in 0..8 { pkc_y_limbs.push(builder.add_virtual_target()); }

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

    // === Base64url extraction: payload pk == pk_c ===
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
    // Connect extracted limbs with pk_c limbs
    for i in 0..8 {
        builder.connect(extracted.x_limbs[i], pkc_x_limbs[i]);
        builder.connect(extracted.y_limbs[i], pkc_y_limbs[i]);
    }

    let data = builder.build::<Cfg>();
    MsgPkCBindingCircuit {
        data,
        targets: MsgPkCBindingTargets {
            header,
            payload,
            header_len,
            payload_len,
            msg,
            message_bits: sha_targets.message_bits,
            off_x_b64,
            len_x_b64,
            drop_x,
            len_x_inner,
            off_y_b64,
            len_y_b64,
            drop_y,
            len_y_inner,
            pkc_x_limbs,
            pkc_y_limbs,
        },
    }
}