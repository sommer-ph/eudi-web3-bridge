//! Msg–pk_c binding circuit (plonky2).
//!
//! Goal (parity with Circom version):
//! - Recompute SHA-256 over fixed-length message layout: [headerB64 ASCII (<=64, zero-padded)] '.' [payloadB64 ASCII (<=1024, zero-padded)]
//! - Optionally: extract pk_c (x,y) from JWK Base64url inside payload and compare to provided pk_c
//!
//! This initial version scaffolds the SHA-256 recomputation over the fixed message layout
//! and exposes digest bits as public inputs. Base64url parsing and pk_c extraction will be
//! added incrementally (leveraging aligned-slice inputs from the backend).

use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::types::Field;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::nonnative::{NonNativeTarget, CircuitBuilderNonNative};
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use plonky2_ecdsa::field::p256_base::P256Base;
use plonky2_ecdsa::curve::p256::P256;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Fixed byte lengths matching the Circom circuit.
pub const MAX_HEADER: usize = 64;      // headerB64 ASCII max length
pub const MAX_PAYLOAD: usize = 1024;   // payloadB64 ASCII max length
pub const MAX_TOTAL: usize = MAX_HEADER + 1 + MAX_PAYLOAD; // '.' at position 64
pub const MSG_BITS: usize = MAX_TOTAL * 8; // message length in bits

/// Targets for the Msg–pk_c binding circuit.
pub struct MsgPkCBindingTargets {
    /// Message bits (fixed-length, MSB-first per byte)
    pub message: Vec<BoolTarget>,
    /// SHA-256 digest bits (MSB-first), registered as public inputs
    pub digest: Vec<BoolTarget>,
}

/// Compiled circuit container.
pub struct MsgPkCBindingCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: MsgPkCBindingTargets,
}

/// Build the SHA-256 recomputation circuit over a fixed-length message layout.
///
/// Note: This version only enforces SHA-256(message) == digest (both provided via targets).
/// The Base64url decode and pk_c extraction/comparison will be implemented in follow-ups.
pub fn build_msg_pk_c_binding_circuit() -> MsgPkCBindingCircuit {
    use plonky2_sha256::circuit::{make_circuits, Sha256Targets};

    let mut config = CircuitConfig::standard_recursion_zk_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Allocate SHA-256 message/digest constraint system for fixed MSG_BITS
    let Sha256Targets { message, digest } = make_circuits(&mut builder, MSG_BITS as u64);

    // Register digest bits as public inputs (MSB-first). The message bits remain private inputs.
    for db in &digest {
        builder.register_public_input(db.target);
    }

    let data = builder.build::<Cfg>();
    MsgPkCBindingCircuit {
        data,
        targets: MsgPkCBindingTargets { message, digest },
    }
}

/// Helper: decompose a byte Target into 8 MSB-first BoolTargets and enforce range/equality.
fn byte_to_bits_msb(builder: &mut CircuitBuilder<F, D>, byte: Target) -> [BoolTarget; 8] {
    // Allocate 8 boolean targets for bits 7..0 (MSB → LSB)
    let bits: [BoolTarget; 8] = [
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
    ];
    // Reconstruct the byte value from bits and constrain equality with `byte`
    let mut acc = builder.zero();
    for (i, b) in bits.iter().enumerate() {
        // weight = 1 << (7 - i)
        let w = 1u64 << (7 - i);
        let coeff = builder.constant(F::from_canonical_u64(w));
        let contrib = builder.mul(b.target, coeff);
        acc = builder.add(acc, contrib);
    }
    builder.connect(acc, byte);
    bits
}

/// Helper: constant 8 bits (MSB-first) for a given u8 value.
fn const_bits_msb(builder: &mut CircuitBuilder<F, D>, byte: u8) -> [BoolTarget; 8] {
    let mut bits: [BoolTarget; 8] = [
        builder.constant_bool(false),
        builder.constant_bool(false),
        builder.constant_bool(false),
        builder.constant_bool(false),
        builder.constant_bool(false),
        builder.constant_bool(false),
        builder.constant_bool(false),
        builder.constant_bool(false),
    ];
    for i in 0..8 {
        let bit = ((byte >> (7 - i)) & 1) == 1;
        bits[i] = builder.constant_bool(bit);
    }
    bits
}

/// Adds constraints that:
/// - Build a fixed-length message of 64 header bytes, '.' byte, and 1024 payload bytes
/// - Feed message bits to SHA-256 circuit
/// - Convert digest bits to a P256Scalar and assert equality with `expected_msg`
///
/// Returns the SHA-256 targets so caller may (optionally) expose the digest as public.
pub fn add_msg_hash_check(
    builder: &mut CircuitBuilder<F, D>,
    header_bytes: &[Target],   // length 64, ASCII codes 0..255
    payload_bytes: &[Target],  // length 1024, ASCII codes 0..255
    expected_msg: &NonNativeTarget<P256Scalar>,
) -> MsgPkCBindingTargets {
    assert_eq!(header_bytes.len(), MAX_HEADER);
    assert_eq!(payload_bytes.len(), MAX_PAYLOAD);

    use plonky2_sha256::circuit::{make_circuits, Sha256Targets};
    let Sha256Targets { message, digest } = make_circuits(builder, MSG_BITS as u64);

    // 0..63 header: reconstruct each byte from SHA message bits and enforce equality with header_bytes
    for i in 0..MAX_HEADER {
        let mut acc = builder.zero();
        for j in 0..8 {
            // SHA expects MSB→LSB per byte; message index is (i*8 + j)
            let bit = message[i * 8 + j].target;
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (7 - j)));
            let contrib = builder.mul(bit, coeff);
            acc = builder.add(acc, contrib);
        }
        builder.connect(acc, header_bytes[i]);
    }

    // Dot at byte index 64: reconstruct byte from bits and enforce equals '.' (46)
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

    // 65..(65+1023) payload
    let payload_base = (MAX_HEADER + 1) * 8;
    for i in 0..MAX_PAYLOAD {
        let mut acc = builder.zero();
        for j in 0..8 {
            let bit = message[payload_base + i * 8 + j].target;
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (7 - j)));
            let contrib = builder.mul(bit, coeff);
            acc = builder.add(acc, contrib);
        }
        builder.connect(acc, payload_bytes[i]);
    }

    // Pack digest bits (MSB-first) into 32-bit little-endian limbs and connect to expected_msg BigUint limbs
    let limb_count = expected_msg.value.limbs.len();
    debug_assert_eq!(limb_count * 32, 256, "Unexpected limb count for P256Scalar BigUintTarget");
    for limb_idx in 0..limb_count {
        let mut limb_acc = builder.zero();
        for k in 0..32 {
            // Global bit index from LSB-first perspective
            let global_k = limb_idx * 32 + k;
            // digest is MSB-first; select corresponding bit
            let bit = digest[255 - global_k].target;
            let coeff = builder.constant(F::from_canonical_u64(1u64 << k));
            let contrib = builder.mul(bit, coeff);
            limb_acc = builder.add(limb_acc, contrib);
        }
        builder.connect(limb_acc, expected_msg.value.limbs[limb_idx].0);
    }

    MsgPkCBindingTargets { message, digest }
}

/// Equality check for an 8-bit value against a constant (MSB-first bits).
fn eq_const_from_bits(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget; 8],
    constant: u8,
) -> BoolTarget {
    let mut eq = builder._true();
    for i in 0..8 {
        let bit_const = ((constant >> (7 - i)) & 1) == 1;
        let this_eq = if bit_const { bits_msb[i] } else { builder.not(bits_msb[i]) };
        eq = builder.and(eq, this_eq);
    }
    eq
}

/// Compare constant i < variable len (given as 8 MSB-first bits). Returns BoolTarget.
fn lt_const_from_bits(
    builder: &mut CircuitBuilder<F, D>,
    len_bits_msb: &[BoolTarget; 8],
    i_const: u8,
) -> BoolTarget {
    let mut eq_prefix = builder._true();
    let mut result = builder._false();
    for k in 0..8 {
        let a_k = ((i_const >> (7 - k)) & 1) == 1; // bit of constant i
        let b_k = len_bits_msb[k];                 // bit of len
        // If a_k == 0 and b_k == 1 and all higher bits equal => result = 1
        if !a_k {
            let t1 = builder.and(eq_prefix, b_k);
            result = builder.or(result, t1);
        }
        // Update eq_prefix: stays true only if a_k == b_k
        let eq_bit = if a_k { b_k } else { builder.not(b_k) };
        eq_prefix = builder.and(eq_prefix, eq_bit);
    }
    result
}

fn ge_const_from_bits(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget; 8],
    c: u8,
) -> BoolTarget {
    // a >= c  <=>  not (a < c)
    let lt = lt_const_from_bits(builder, bits_msb, c);
    builder.not(lt)
}

fn le_const_from_bits(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget; 8],
    c: u8,
) -> BoolTarget {
    // a <= c  <=>  a < c+1
    let c1 = c.saturating_add(1);
    lt_const_from_bits(builder, bits_msb, c1)
}

/// Decompose a Target (assumed 0..255) into 8 MSB-first BoolTargets and enforce equality.
fn target_to_bits8_msb(
    builder: &mut CircuitBuilder<F, D>,
    byte: Target,
) -> [BoolTarget; 8] {
    // Reuse byte_to_bits_msb but keep signature symmetry
    byte_to_bits_msb(builder, byte)
}

/// Decompose a Target (assumed 0..63) into 6 MSB-first BoolTargets and enforce equality.
fn target_to_bits6_msb(
    builder: &mut CircuitBuilder<F, D>,
    val: Target,
) -> [BoolTarget; 6] {
    let bits: [BoolTarget; 6] = [
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
        builder.add_virtual_bool_target_safe(),
    ];
    // range check to 6 bits not directly available; reconstruct value == sum(bits * 2^(5-i)) ensures 0..63
    let mut acc = builder.zero();
    for i in 0..6 {
        let coeff = builder.constant(F::from_canonical_u64(1u64 << (5 - i)));
        let contrib = builder.mul(bits[i].target, coeff);
        acc = builder.add(acc, contrib);
    }
    builder.connect(acc, val);
    bits
}

/// Compute Base64url sextet numeric value from ASCII code (Target), without strict class validation.
/// Implements the piecewise mapping:
/// A-Z: x-65
/// a-z: x-71
/// 0-9: x+4
/// '-' : 62
/// '_' : 63
/// '=' : 0
fn b64url_ascii_to_value(
    builder: &mut CircuitBuilder<F, D>,
    ascii: Target,
) -> Target {
    let ascii_bits = target_to_bits8_msb(builder, ascii);

    // Exact matches
    let c45 = builder.constant(F::from_canonical_u64(45)); // '-'
    let c95 = builder.constant(F::from_canonical_u64(95)); // '_'
    let c61 = builder.constant(F::from_canonical_u64(61)); // '='
    let is_dash = builder.is_equal(ascii, c45);
    let is_us = builder.is_equal(ascii, c95);
    let is_eq = builder.is_equal(ascii, c61);

    // Ranges
    let ge_A = ge_const_from_bits(builder, &ascii_bits, b'A');
    let le_Z = le_const_from_bits(builder, &ascii_bits, b'Z');
    let range_AZ = builder.and(ge_A, le_Z);
    let ge_a = ge_const_from_bits(builder, &ascii_bits, b'a');
    let le_z = le_const_from_bits(builder, &ascii_bits, b'z');
    let range_az = builder.and(ge_a, le_z);
    let ge_0 = ge_const_from_bits(builder, &ascii_bits, b'0');
    let le_9 = le_const_from_bits(builder, &ascii_bits, b'9');
    let range_09 = builder.and(ge_0, le_9);

    // Values per class
    let c65 = builder.constant(F::from_canonical_u64(65));
    let c71 = builder.constant(F::from_canonical_u64(71));
    let c4  = builder.constant(F::from_canonical_u64(4));
    let val_AZ = builder.sub(ascii, c65); // x-65
    let val_az = builder.sub(ascii, c71); // x-71
    let val_09 = builder.add(ascii, c4);  // x+4

    // Combine piecewise
    let mut out = builder.zero();
    // '=' contributes 0 (no-op)
    let t1 = builder.mul(val_AZ, range_AZ.target);
    out = builder.add(out, t1);
    let t2 = builder.mul(val_az, range_az.target);
    out = builder.add(out, t2);
    let t3 = builder.mul(val_09, range_09.target);
    out = builder.add(out, t3);
    let c62 = builder.constant(F::from_canonical_u64(62));
    let t4 = builder.mul(c62, is_dash.target);
    out = builder.add(out, t4);
    let c63 = builder.constant(F::from_canonical_u64(63));
    let t5 = builder.mul(c63, is_us.target);
    out = builder.add(out, t5);
    out
}

/// Decode 64 Base64url ASCII chars into 48 raw bytes.
fn decode_b64url_64_to_48(
    builder: &mut CircuitBuilder<F, D>,
    chars64: &[Target],
) -> Vec<Target> {
    debug_assert_eq!(chars64.len(), 64);
    let mut out = Vec::with_capacity(48);
    for _ in 0..48 { out.push(builder.add_virtual_target()); }

    for block in 0..16 { // 16 * 4 chars = 64
        let c0 = chars64[block*4 + 0];
        let c1 = chars64[block*4 + 1];
        let c2 = chars64[block*4 + 2];
        let c3 = chars64[block*4 + 3];

        let v0 = b64url_ascii_to_value(builder, c0);
        let v1 = b64url_ascii_to_value(builder, c1);
        let v2 = b64url_ascii_to_value(builder, c2);
        let v3 = b64url_ascii_to_value(builder, c3);

        let v0b = target_to_bits6_msb(builder, v0);
        let v1b = target_to_bits6_msb(builder, v1);
        let v2b = target_to_bits6_msb(builder, v2);
        let v3b = target_to_bits6_msb(builder, v3);

        // Repack to 3 bytes per block
        // b0: v0[5..0] -> bits 7..2 ; v1[5..4] -> bits 1..0
        let mut b0 = builder.zero();
        for b in 0..6 { // to bits 7..2
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (b + 2)));
            let contrib = builder.mul(v0b[5 - b].target, coeff);
            b0 = builder.add(b0, contrib);
        }
        // v1 bits 5..4 to 1..0
        for (off, bitidx) in [1u64, 0u64].iter().zip([5usize,4usize].iter()) {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << off));
            let contrib = builder.mul(v1b[*bitidx].target, coeff);
            b0 = builder.add(b0, contrib);
        }

        // b1: v1[3..0] -> bits 7..4 ; v2[5..2] -> bits 3..0
        let mut b1 = builder.zero();
        for (i, bitidx) in (0..4).zip((0..4).rev()) { // v1[3..0]
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (4 + i)));
            let contrib = builder.mul(v1b[bitidx].target, coeff);
            b1 = builder.add(b1, contrib);
        }
        for (i, bitidx) in (0..4).zip((2..6).rev()) { // v2[5..2]
            let coeff = builder.constant(F::from_canonical_u64(1u64 << i));
            let contrib = builder.mul(v2b[bitidx].target, coeff);
            b1 = builder.add(b1, contrib);
        }

        // b2: v2[1..0] -> bits 7..6 ; v3[5..0] -> bits 5..0
        let mut b2 = builder.zero();
        for (i, bitidx) in (6..8).zip((0..2).rev()) { // v2[1..0]
            let coeff = builder.constant(F::from_canonical_u64(1u64 << i));
            let contrib = builder.mul(v2b[bitidx].target, coeff);
            b2 = builder.add(b2, contrib);
        }
        for i in 0..6 { // v3[5..0]
            let coeff = builder.constant(F::from_canonical_u64(1u64 << i));
            let contrib = builder.mul(v3b[5 - i].target, coeff);
            b2 = builder.add(b2, contrib);
        }

        let o0 = block*3 + 0;
        let o1 = block*3 + 1;
        let o2 = block*3 + 2;
        builder.range_check(b0, 8); // enforce byte range
        builder.range_check(b1, 8);
        builder.range_check(b2, 8);
        builder.connect(out[o0], b0);
        builder.connect(out[o1], b1);
        builder.connect(out[o2], b2);
    }
    out
}

/// Decode 44 Base64url ASCII chars into 33 raw bytes.
fn decode_b64url_44_to_33(
    builder: &mut CircuitBuilder<F, D>,
    chars44: &[Target],
) -> Vec<Target> {
    debug_assert_eq!(chars44.len(), 44);
    let mut out = Vec::with_capacity(33);
    for _ in 0..33 { out.push(builder.add_virtual_target()); }
    for block in 0..11 { // 11 * 4 = 44
        let c0 = chars44[block*4 + 0];
        let c1 = chars44[block*4 + 1];
        let c2 = chars44[block*4 + 2];
        let c3 = chars44[block*4 + 3];
        let v0 = b64url_ascii_to_value(builder, c0);
        let v1 = b64url_ascii_to_value(builder, c1);
        let v2 = b64url_ascii_to_value(builder, c2);
        let v3 = b64url_ascii_to_value(builder, c3);
        let v0b = target_to_bits6_msb(builder, v0);
        let v1b = target_to_bits6_msb(builder, v1);
        let v2b = target_to_bits6_msb(builder, v2);
        let v3b = target_to_bits6_msb(builder, v3);
        let mut b0 = builder.zero();
        for b in 0..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (b + 2)));
            let contrib = builder.mul(v0b[5 - b].target, coeff);
            b0 = builder.add(b0, contrib);
        }
        for (off, bitidx) in [1u64, 0u64].iter().zip([5usize,4usize].iter()) {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << off));
            let contrib = builder.mul(v1b[*bitidx].target, coeff);
            b0 = builder.add(b0, contrib);
        }
        let mut b1 = builder.zero();
        for (i, bitidx) in (0..4).zip((0..4).rev()) {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (4 + i)));
            let contrib = builder.mul(v1b[bitidx].target, coeff);
            b1 = builder.add(b1, contrib);
        }
        for (i, bitidx) in (0..4).zip((2..6).rev()) {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << i));
            let contrib = builder.mul(v2b[bitidx].target, coeff);
            b1 = builder.add(b1, contrib);
        }
        let mut b2 = builder.zero();
        for (i, bitidx) in (6..8).zip((0..2).rev()) {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << i));
            let contrib = builder.mul(v2b[bitidx].target, coeff);
            b2 = builder.add(b2, contrib);
        }
        for i in 0..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << i));
            let contrib = builder.mul(v3b[5 - i].target, coeff);
            b2 = builder.add(b2, contrib);
        }
        let o0 = block*3 + 0;
        let o1 = block*3 + 1;
        let o2 = block*3 + 2;
        builder.range_check(b0, 8);
        builder.range_check(b1, 8);
        builder.range_check(b2, 8);
        builder.connect(out[o0], b0);
        builder.connect(out[o1], b1);
        builder.connect(out[o2], b2);
    }
    out
}

/// Select payload byte at dynamic index (0..MAX_PAYLOAD-1) via one-hot equality over constants.
fn select_payload_byte(
    builder: &mut CircuitBuilder<F, D>,
    payload: &[Target],
    idx: Target,
) -> Target {
    let mut acc = builder.zero();
    for j in 0..MAX_PAYLOAD {
        let c_j = builder.constant(F::from_canonical_u64(j as u64));
        let eq = builder.is_equal(idx, c_j);
        let contrib = builder.mul(payload[j], eq.target);
        acc = builder.add(acc, contrib);
    }
    // acc now equals payload[idx]
    acc
}

/// Build the outer 64-char Base64url slice with '=' padding when i >= len.
fn build_aligned_outer_slice(
    builder: &mut CircuitBuilder<F, D>,
    payload: &[Target],
    off: Target,
    len: Target, // 0..64
) -> Vec<Target> {
    // Decompose len into 8 bits (MSB first) to build lt(i, len)
    let len_bits = target_to_bits8_msb(builder, len);
    let mut out = Vec::with_capacity(64);
    for i in 0..64 {
        let c_i = builder.constant(F::from_canonical_u64(i as u64));
        let idx = builder.add(off, c_i);
        let selected = select_payload_byte(builder, payload, idx);
        let lt = lt_const_from_bits(builder, &len_bits, i as u8); // i < len ?
        let eq_val = builder.mul(selected, lt.target);
        // pad '=' (61) when i >= len
        let not_lt = builder.not(lt);
        let c_eq = builder.constant(F::from_canonical_u64(61));
        let pad = builder.mul(c_eq, not_lt.target);
        let ch = builder.add(eq_val, pad);
        out.push(ch);
    }
    out
}

/// Convert 32 big-endian bytes to LE 8×u32 limbs and then to NonNativeTarget<P256Base>.
fn bytes32_be_to_nonnative_p256base(
    builder: &mut CircuitBuilder<F, D>,
    bytes_be: &[Target],
) -> NonNativeTarget<P256Base> {
    debug_assert_eq!(bytes_be.len(), 32);
    // Build 8 limbs (u32) in LE order; limb 0 is least significant 32 bits = bytes_be[28..32]
    let mut limbs_le_u32: Vec<Target> = Vec::with_capacity(8);
    for limb_idx in 0..8 {
        let start = 32 - (limb_idx + 1) * 4;
        let mut limb = builder.zero();
        for k in 0..4 {
            let byte = bytes_be[start + k];
            let shift = 8 * (3 - k) as u64; // big-endian within limb
            let coeff = builder.constant(F::from_canonical_u64(1u64 << shift));
            let contrib = builder.mul(byte, coeff);
            limb = builder.add(limb, contrib);
        }
        builder.range_check(limb, 32);
        limbs_le_u32.push(limb);
    }
    let big = BigUintTarget::from_target_vec(&limbs_le_u32);
    builder.reduce::<P256Base>(&big)
}

/// Full pk_c extraction and comparison from payloadB64 using aligned Base64url slices.
pub fn add_pkc_extract_and_check(
    builder: &mut CircuitBuilder<F, D>,
    payload_b64: &[Target],
    off_x_b64: Target,
    len_x_b64: Target,
    drop_x: Target,
    len_x_inner: Target,
    off_y_b64: Target,
    len_y_b64: Target,
    drop_y: Target,
    len_y_inner: Target,
    pk_c: &plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
) {
    // Outer slices X and Y (64 chars each with '=' padding according to len)
    let x_outer = build_aligned_outer_slice(builder, payload_b64, off_x_b64, len_x_b64);
    let y_outer = build_aligned_outer_slice(builder, payload_b64, off_y_b64, len_y_b64);

    // Decode outer slices to 48 bytes (JSON ASCII window)
    let x_dec_out = decode_b64url_64_to_48(builder, &x_outer);
    let y_dec_out = decode_b64url_64_to_48(builder, &y_outer);

    // Build inner ASCII (44) from decoded outer using drop and length; pad '=' when len==43 at position len
    let len_x_bits = target_to_bits8_msb(builder, len_x_inner);
    let len_y_bits = target_to_bits8_msb(builder, len_y_inner);
    let is_x_44 = eq_const_from_bits(builder, &len_x_bits, 44);
    let is_y_44 = eq_const_from_bits(builder, &len_y_bits, 44);
    let is_x_43 = builder.not(is_x_44);
    let is_y_43 = builder.not(is_y_44);

    let mut x_inner: Vec<Target> = Vec::with_capacity(44);
    let mut y_inner: Vec<Target> = Vec::with_capacity(44);

    for i in 0..44 {
        // idx = drop + i
        let c_i = builder.constant(F::from_canonical_u64(i as u64));
        let idx_x = builder.add(drop_x, c_i);
        let c_i2 = builder.constant(F::from_canonical_u64(i as u64));
        let idx_y = builder.add(drop_y, c_i2);
        // select from 48-byte decoded outer window
        let mut sel_x = builder.zero();
        let mut sel_y = builder.zero();
        for j in 0..48 {
            let c_j = builder.constant(F::from_canonical_u64(j as u64));
            let eqx = builder.is_equal(idx_x, c_j);
            let c_j2 = builder.constant(F::from_canonical_u64(j as u64));
            let eqy = builder.is_equal(idx_y, c_j2);
            let contrib_x = builder.mul(x_dec_out[j], eqx.target);
            sel_x = builder.add(sel_x, contrib_x);
            let contrib_y = builder.mul(y_dec_out[j], eqy.target);
            sel_y = builder.add(sel_y, contrib_y);
        }
        // lt_i_len: i < len?
        let lt_x = lt_const_from_bits(builder, &len_x_bits, i as u8);
        let lt_y = lt_const_from_bits(builder, &len_y_bits, i as u8);
        let val_x = builder.mul(sel_x, lt_x.target);
        let val_y = builder.mul(sel_y, lt_y.target);

        // '=' padding when len==43 and i == len
        let eq_i_len_x = eq_const_from_bits(builder, &len_x_bits, i as u8);
        let eq_i_len_y = eq_const_from_bits(builder, &len_y_bits, i as u8);
        let c61 = builder.constant(F::from_canonical_u64(61));
        let pad_x_sel = builder.and(is_x_43, eq_i_len_x);
        let pad_x = builder.mul(c61, pad_x_sel.target);
        let c61b = builder.constant(F::from_canonical_u64(61));
        let pad_y_sel = builder.and(is_y_43, eq_i_len_y);
        let pad_y = builder.mul(c61b, pad_y_sel.target);
        x_inner.push(builder.add(val_x, pad_x));
        y_inner.push(builder.add(val_y, pad_y));
    }

    // Decode inner (44 chars) to 33 bytes
    let x_bytes33 = decode_b64url_44_to_33(builder, &x_inner);
    let y_bytes33 = decode_b64url_44_to_33(builder, &y_inner);

    // Select 32 bytes according to len: 43 -> keep [0..32), 44 -> drop first byte
    let mut x_bytes32: Vec<Target> = Vec::with_capacity(32);
    let mut y_bytes32: Vec<Target> = Vec::with_capacity(32);
    for i in 0..32 {
        let bx43 = x_bytes33[i];
        let bx44 = x_bytes33[i + 1];
        let by43 = y_bytes33[i];
        let by44 = y_bytes33[i + 1];
        let x_c1 = builder.mul(bx43, is_x_43.target);
        let x_c2 = builder.mul(bx44, is_x_44.target);
        let x_val = builder.add(x_c1, x_c2);
        let y_c1 = builder.mul(by43, is_y_43.target);
        let y_c2 = builder.mul(by44, is_y_44.target);
        let y_val = builder.add(y_c1, y_c2);
        x_bytes32.push(x_val);
        y_bytes32.push(y_val);
    }

    // Convert to nonnative and compare against pk_c
    let x_nn = bytes32_be_to_nonnative_p256base(builder, &x_bytes32);
    let y_nn = bytes32_be_to_nonnative_p256base(builder, &y_bytes32);
    builder.connect_nonnative(&pk_c.x, &x_nn);
    builder.connect_nonnative(&pk_c.y, &y_nn);
}
