//! SHA-256(header '.' payload) gadget for reuse in circuits.
//!
//! Provides a helper to constrain the SHA-256 hash of a fixed layout:
//!   [ header (≤64 ASCII bytes) | zeros to 64 ] '.' [ payload (≤1024 ASCII bytes) | zeros to 1024 ]
//! and connect it to a provided P256Scalar non-native target `msg`.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::nonnative::NonNativeTarget;

pub const MAX_HEADER: usize = 64;
pub const MAX_PAYLOAD: usize = 1024;
pub const MAX_TOTAL: usize = MAX_HEADER + 1 + MAX_PAYLOAD; // '.' at position 64
pub const MSG_BITS: usize = MAX_TOTAL * 8;

/// Exposed for debugging/introspection (optional).
pub struct Sha256HeaderPayloadTargets {
    pub message_bits: Vec<BoolTarget>, // MSB-first, len MSG_BITS
}

/// Add constraints enforcing SHA-256(header '.' payload) == msg.
/// - `header` must have length 64; bytes beyond `header_len` are gated to 0.
/// - `payload` must have length 1024; bytes beyond `payload_len` are gated to 0.
/// - `msg` is interpreted as a P256Scalar big integer (256-bit digest).
pub fn add_sha256_header_dot_payload_equals_msg<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    header: &[Target; MAX_HEADER],
    payload: &[Target; MAX_PAYLOAD],
    header_len: Target,
    payload_len: Target,
    msg: &NonNativeTarget<P256Scalar>,
) -> Sha256HeaderPayloadTargets {
    use plonky2_sha256::circuit::make_circuits;

    // Prepare SHA-256 message/digest targets for fixed bitlength
    let sha = make_circuits(builder, MSG_BITS as u64);
    let message = sha.message;
    let digest = sha.digest;

    // Decompose lengths (MSB-first) using builder-provided bit decomposition
    let header_len_bits = bits_msb_from_target(builder, header_len, 8);
    let payload_len_bits = bits_msb_from_target(builder, payload_len, 10);

    // Header region [0..63]
    for i in 0..MAX_HEADER {
        // message byte from 8 bits (MSB→LSB)
        let mut acc = builder.zero();
        for j in 0..8 {
            let bit = message[i * 8 + j].target;
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (7 - j)));
            let contrib = builder.mul(bit, coeff);
            acc = builder.add(acc, contrib);
        }
        // Gate by (i < header_len)
        let lt = lt_const_from_bits(builder, &header_len_bits, i as u32);
        let gated = builder.mul(header[i], lt.target);
        builder.connect(acc, gated);
    }

    // '.' at index 64
    let dot_base = MAX_HEADER * 8;
    let mut dot_acc = builder.zero();
    for j in 0..8 {
        let bit = message[dot_base + j].target;
        let coeff = builder.constant(F::from_canonical_u64(1u64 << (7 - j)));
        let contrib = builder.mul(bit, coeff);
        dot_acc = builder.add(dot_acc, contrib);
    }
    let dot_const = builder.constant(F::from_canonical_u64(46));
    builder.connect(dot_acc, dot_const);

    // Payload region [65..(65+1023)]
    let payload_base = (MAX_HEADER + 1) * 8;
    for i in 0..MAX_PAYLOAD {
        let mut acc = builder.zero();
        for j in 0..8 {
            let bit = message[payload_base + i * 8 + j].target;
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (7 - j)));
            let contrib = builder.mul(bit, coeff);
            acc = builder.add(acc, contrib);
        }
        // Gate by (i < payload_len)
        let lt = lt_const_from_bits(builder, &payload_len_bits, i as u32);
        let gated = builder.mul(payload[i], lt.target);
        builder.connect(acc, gated);
    }

    // Pack digest bits (MSB-first) into 8×u32 limbs (LE) and connect to msg
    let limb_count = msg.value.limbs.len();
    debug_assert_eq!(limb_count * 32, 256, "Unexpected limb count for 256-bit digest");
    for limb_idx in 0..limb_count {
        let mut limb_acc = builder.zero();
        for k in 0..32 {
            // digest is MSB-first; numeric LSB-first index is reversed
            let bit = digest[255 - (limb_idx * 32 + k)].target;
            let coeff = builder.constant(F::from_canonical_u64(1u64 << k));
            let contrib = builder.mul(bit, coeff);
            limb_acc = builder.add(limb_acc, contrib);
        }
        builder.connect(limb_acc, msg.value.limbs[limb_idx].0);
    }

    Sha256HeaderPayloadTargets { message_bits: message.clone() }
}

// === Local helpers ===

fn bits_msb_from_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    t: Target,
    nbits: usize,
) -> Vec<BoolTarget> {
    // split_le_base::<2> returns LSB-first bits; reverse to MSB-first for comparisons
    let bits_le = builder.split_le_base::<2>(t, nbits);
    bits_le
        .into_iter()
        .rev()
        .map(BoolTarget::new_unsafe)
        .collect()
}

fn lt_const_from_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget],
    i_const: u32,
) -> BoolTarget {
    // Compute (i_const < value(bits_msb)). Note: This returns "value > i_const".
    let n = bits_msb.len();
    let mut eq_prefix = builder._true();
    let mut result = builder._false();
    for k in 0..n {
        let a_k_one = ((i_const >> (n - 1 - k)) & 1) == 1; // bit of const i
        let b_k = bits_msb[k]; // bit of value
        if !a_k_one {
            let t1 = builder.and(eq_prefix, b_k);
            result = builder.or(result, t1);
        }
        let eq_bit = if a_k_one { b_k } else { builder.not(b_k) };
        eq_prefix = builder.and(eq_prefix, eq_bit);
    }
    result
}

