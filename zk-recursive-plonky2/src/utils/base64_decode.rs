//! Base64url decoding gadgets for extracting coordinates from payload ASCII.
//!
//! Provides helpers to:
//!  - Build aligned 64-char outer slices from a payload (with '=' padding)
//!  - Decode Base64url 64→48 bytes and 44→33 bytes
//!  - Build inner 44-char slices (43 or 44 significant chars; normalize to '=')
//!  - Select the correct 32-byte window based on the last inner char
//!  - Convert 32 big-endian bytes to 8×u32 little-endian limbs
//!  - Enforce Base64url character validity and range constraints

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub const MAX_PAYLOAD: usize = 1024;

/// Extracted limbs for a coordinate pair.
pub struct ExtractedPkLimbs {
    pub x_limbs: [Target; 8], // 8×u32 little-endian words from 32 big-endian bytes
    pub y_limbs: [Target; 8],
}

/// Add constraints to extract x,y (as 8×u32 LE limbs) from payload_b64 ASCII window.
/// The parameters are provided as Targets to keep this gadget reusable within circuits.
pub fn add_pk_binding_extract<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    payload_b64: &[Target; MAX_PAYLOAD],
    off_x_b64: Target,
    len_x_b64: Target,
    drop_x: Target,
    len_x_inner: Target,
    off_y_b64: Target,
    len_y_b64: Target,
    drop_y: Target,
    len_y_inner: Target,
) -> ExtractedPkLimbs {
    // Outer slices X and Y (64 chars each with '=' padding)
    let x_outer = build_aligned_outer_slice(builder, payload_b64, off_x_b64, len_x_b64);
    let y_outer = build_aligned_outer_slice(builder, payload_b64, off_y_b64, len_y_b64);

    // Decode outer slices to 48 bytes (JSON ASCII window)
    let x_dec_out = decode_b64url_64_to_48(builder, &x_outer);
    let y_dec_out = decode_b64url_64_to_48(builder, &y_outer);

    // Build inner ASCII (44) from decoded outer using drop and length; pad '=' when len==43 at i==len
    let (x_inner, x_last_is_eq) = build_inner_44(builder, &x_dec_out, drop_x, len_x_inner);
    let (y_inner, y_last_is_eq) = build_inner_44(builder, &y_dec_out, drop_y, len_y_inner);

    // Decode inner to 33 bytes
    let x_bytes33 = decode_b64url_coord_44_to_33(builder, &x_inner);
    let y_bytes33 = decode_b64url_coord_44_to_33(builder, &y_inner);

    // Build 32-byte sequences based on last '='
    let mut x_bytes32: Vec<Target> = Vec::with_capacity(32);
    let mut y_bytes32: Vec<Target> = Vec::with_capacity(32);
    for i in 0..32 {
        // x: choose i or i+1 based on last_is_eq
        let xi = x_bytes33[i];
        let xi1 = x_bytes33[i + 1];
        let use_i1 = builder.not(x_last_is_eq);
        let dx = builder.sub(xi1, xi);
        let selx = builder.mul(dx, use_i1.target);
        let outx = builder.add(xi, selx);
        x_bytes32.push(outx);

        // y
        let yi = y_bytes33[i];
        let yi1 = y_bytes33[i + 1];
        let use_i1y = builder.not(y_last_is_eq);
        let dy = builder.sub(yi1, yi);
        let sely = builder.mul(dy, use_i1y.target);
        let outy = builder.add(yi, sely);
        y_bytes32.push(outy);
    }

    // Convert to 8×u32 LE limbs
    let x_limbs_v = bytes32_be_to_le_u32_limbs(builder, &x_bytes32);
    let y_limbs_v = bytes32_be_to_le_u32_limbs(builder, &y_bytes32);
    let x_limbs: [Target; 8] = x_limbs_v.try_into().expect("expected 8 limbs");
    let y_limbs: [Target; 8] = y_limbs_v.try_into().expect("expected 8 limbs");

    ExtractedPkLimbs { x_limbs, y_limbs }
}

// === Helpers ===

fn bits_msb_from_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    t: Target,
    nbits: usize,
) -> Vec<BoolTarget> {
    let bits_le = builder.split_le_base::<2>(t, nbits);
    bits_le
        .into_iter()
        .rev()
        .map(BoolTarget::new_unsafe)
        .collect()
}

fn bits_le_from_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    t: Target,
    nbits: usize,
) -> Vec<BoolTarget> {
    let bits_le = builder.split_le_base::<2>(t, nbits);
    bits_le.into_iter().map(BoolTarget::new_unsafe).collect()
}

fn binary_mux<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    cond: BoolTarget,
) -> Target {
    let diff = builder.sub(b, a);
    let sel = builder.mul(diff, cond.target);
    builder.add(a, sel)
}

fn binary_select<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    vals: Vec<Target>,
    bits_le: &[BoolTarget],
) -> Target {
    let mut curr = vals;
    for bit in bits_le {
        let mut next: Vec<Target> = Vec::with_capacity((curr.len() + 1) / 2);
        let mut i = 0usize;
        while i + 1 < curr.len() {
            let a = curr[i];
            let b = curr[i + 1];
            let sel = binary_mux(builder, a, b, *bit);
            next.push(sel);
            i += 2;
        }
        if i < curr.len() {
            next.push(curr[i]);
        }
        curr = next;
    }
    curr[0]
}

fn eq_const_from_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget],
    c: u32,
) -> BoolTarget {
    let n = bits_msb.len();
    let mut eq = builder._true();
    for i in 0..n {
        let bit_const = ((c >> (n - 1 - i)) & 1) == 1;
        let this_eq = if bit_const { bits_msb[i] } else { builder.not(bits_msb[i]) };
        eq = builder.and(eq, this_eq);
    }
    eq
}

fn lt_const_from_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget],
    i_const: u32,
) -> BoolTarget {
    let n = bits_msb.len();
    let mut eq_prefix = builder._true();
    let mut result = builder._false();
    for k in 0..n {
        let a_k_one = ((i_const >> (n - 1 - k)) & 1) == 1; // bit of const i
        let b_k = bits_msb[k];                               // bit of value
        if !a_k_one {
            let t1 = builder.and(eq_prefix, b_k);
            result = builder.or(result, t1);
        }
        let eq_bit = if a_k_one { b_k } else { builder.not(b_k) };
        eq_prefix = builder.and(eq_prefix, eq_bit);
    }
    result
}

fn ge_const_from_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget],
    c: u32,
) -> BoolTarget {
    if c == 0 {
        builder._true()
    } else {
        lt_const_from_bits(builder, bits_msb, c - 1)
    }
}

fn le_const_from_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_msb: &[BoolTarget],
    c: u32,
) -> BoolTarget {
    let gt_c = lt_const_from_bits(builder, bits_msb, c);
    builder.not(gt_c)
}

fn b64url_ascii_to_value<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    ascii: Target,
) -> Target {
    // Explicit matches for '-', '_', '='
    let c45 = builder.constant(F::from_canonical_u64(45)); // '-'
    let c95 = builder.constant(F::from_canonical_u64(95)); // '_'
    let c61 = builder.constant(F::from_canonical_u64(61)); // '='
    let is_dash = builder.is_equal(ascii, c45);
    let is_us = builder.is_equal(ascii, c95);
    let is_eq = builder.is_equal(ascii, c61);

    // Ranges using bits (A–Z, a–z, 0–9)
    let ascii_bits = bits_msb_from_target(builder, ascii, 8);
    let range_AZ = {
        let ge_A = ge_const_from_bits(builder, &ascii_bits, b'A' as u32);
        let le_Z = le_const_from_bits(builder, &ascii_bits, b'Z' as u32);
        builder.and(ge_A, le_Z)
    };
    let range_az = {
        let ge_a = ge_const_from_bits(builder, &ascii_bits, b'a' as u32);
        let le_z = le_const_from_bits(builder, &ascii_bits, b'z' as u32);
        builder.and(ge_a, le_z)
    };
    let range_09 = {
        let ge_0 = ge_const_from_bits(builder, &ascii_bits, b'0' as u32);
        let le_9 = le_const_from_bits(builder, &ascii_bits, b'9' as u32);
        builder.and(ge_0, le_9)
    };

    // Enforce validity: char must belong to one Base64url class
    let class1 = builder.or(range_AZ, range_az);
    let class2 = builder.or(range_09, is_dash);
    let class3 = builder.or(is_us, is_eq);
    let valid_left = builder.or(class1, class2);
    let is_valid = builder.or(valid_left, class3);
    builder.assert_one(is_valid.target);

    // Sextet values per class
    let c65 = builder.constant(F::from_canonical_u64(65));
    let c71 = builder.constant(F::from_canonical_u64(71));
    let c4 = builder.constant(F::from_canonical_u64(4));
    let val_AZ = builder.sub(ascii, c65); // x-65
    let val_az = builder.sub(ascii, c71); // x-71
    let val_09 = builder.add(ascii, c4);  // x+4

    let mut out = builder.zero();
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
    let _ = is_eq; // '=' contributes 0 (padding)
    out
}

fn decode_b64url_64_to_48<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    chars64: &[Target],
) -> Vec<Target> {
    assert_eq!(chars64.len(), 64);
    let mut out_vec: Vec<Target> = Vec::with_capacity(48);

    for block in 0..16 {
        let c0 = chars64[block * 4 + 0];
        let c1 = chars64[block * 4 + 1];
        let c2 = chars64[block * 4 + 2];
        let c3 = chars64[block * 4 + 3];
        let v0 = b64url_ascii_to_value(builder, c0);
        let v1 = b64url_ascii_to_value(builder, c1);
        let v2 = b64url_ascii_to_value(builder, c2);
        let v3 = b64url_ascii_to_value(builder, c3);

        let v0_le = builder.split_le_base::<2>(v0, 6);
        let v1_le = builder.split_le_base::<2>(v1, 6);
        let v2_le = builder.split_le_base::<2>(v2, 6);
        let v3_le = builder.split_le_base::<2>(v3, 6);

        // b0 = (v0 << 2) | (v1 >> 4)
        let mut b0 = builder.zero();
        for k in 0..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k + 2)));
            let contrib = builder.mul(v0_le[k], coeff);
            b0 = builder.add(b0, contrib);
        }
        for (k, pos) in [(4usize, 0u64), (5usize, 1u64)].iter() {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << pos));
            let contrib = builder.mul(v1_le[*k], coeff);
            b0 = builder.add(b0, contrib);
        }

        // b1 = ((v1 & 0x0f) << 4) | (v2 >> 2)
        let mut b1 = builder.zero();
        for k in 0..4 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k + 4)));
            let contrib = builder.mul(v1_le[k], coeff);
            b1 = builder.add(b1, contrib);
        }
        for k in 2..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k - 2)));
            let contrib = builder.mul(v2_le[k], coeff);
            b1 = builder.add(b1, contrib);
        }

        // b2 = ((v2 & 0x03) << 6) | v3
        let mut b2 = builder.zero();
        for k in 0..2 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k + 6)));
            let contrib = builder.mul(v2_le[k], coeff);
            b2 = builder.add(b2, contrib);
        }
        for k in 0..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << k));
            let contrib = builder.mul(v3_le[k], coeff);
            b2 = builder.add(b2, contrib);
        }

        out_vec.push(b0);
        out_vec.push(b1);
        out_vec.push(b2);
    }
    out_vec
}

fn select_payload_byte<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    payload: &[Target],
    idx: Target,
) -> Target {
    // Binary-select over 1024 (=2^10) using split_le_base
    let bits_le = bits_le_from_target(builder, idx, 10);
    let vals = payload.to_vec();
    binary_select(builder, vals, &bits_le)
}

fn build_aligned_outer_slice<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    payload: &[Target; MAX_PAYLOAD],
    off: Target,
    len: Target,
) -> Vec<Target> {
    // Build 64-char window: copy up to `len` chars starting at `off`, pad the rest with '='.
    let len_bits = bits_msb_from_target(builder, len, 8);
    // Enforce len <= 64
    let len_le_64 = le_const_from_bits(builder, &len_bits, 64);
    builder.assert_one(len_le_64.target);
    let mut out = Vec::with_capacity(64);
    for i in 0..64 {
        let c_i = builder.constant(F::from_canonical_u64(i as u64));
        let idx = builder.add(off, c_i);
        let selected = select_payload_byte(builder, payload, idx);
        let lt = lt_const_from_bits(builder, &len_bits, i as u32);
        let eq_val = builder.mul(selected, lt.target);
        let not_lt = builder.not(lt);
        let c_eq = builder.constant(F::from_canonical_u64(61)); // '='
        let pad = builder.mul(c_eq, not_lt.target);
        let ch = builder.add(eq_val, pad);
        out.push(ch);
    }
    out
}

fn build_inner_44<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    decoded48: &[Target],
    drop_val: Target,
    len_inner: Target,
) -> (Vec<Target>, BoolTarget) {
    // Enforce len_inner ∈ {43,44} and drop ranges:
    let len_bits = bits_msb_from_target(builder, len_inner, 8);
    let is_44 = eq_const_from_bits(builder, &len_bits, 44);
    let is_43 = eq_const_from_bits(builder, &len_bits, 43);
    let ok_len = builder.or(is_44, is_43);
    builder.assert_one(ok_len.target);

    let drop_bits = bits_msb_from_target(builder, drop_val, 6);
    let d_le_4 = le_const_from_bits(builder, &drop_bits, 4);
    let d_le_5 = le_const_from_bits(builder, &drop_bits, 5);
    let ok_d_44 = builder.and(is_44, d_le_4);
    let ok_d_43 = builder.and(is_43, d_le_5);
    let ok_drop = builder.or(ok_d_44, ok_d_43);
    builder.assert_one(ok_drop.target);

    // Build inner 44 chars
    let mut inner: Vec<Target> = Vec::with_capacity(44);
    let win64 = pad_to_pow2(builder, decoded48, 64);
    for i in 0..44 {
        let c_i = builder.constant(F::from_canonical_u64(i as u64));
        let idx = builder.add(drop_val, c_i);
        let bits = bits_le_from_target(builder, idx, 6);
        let sel = binary_select(builder, win64.clone(), &bits);
        // '=' padding when len==43 and i == len
        let eq_i_len = eq_const_from_bits(builder, &len_bits, i as u32);
        let c61 = builder.constant(F::from_canonical_u64(61));
        let pad_sel = builder.and(is_43, eq_i_len);
        let pad = builder.mul(c61, pad_sel.target);
        let d = builder.sub(pad, sel);
        let tp = builder.mul(d, pad_sel.target);
        let out = builder.add(sel, tp);
        inner.push(out);
    }

    // Last char equals '='?
    let c61 = builder.constant(F::from_canonical_u64(61));
    let last_is_eq = builder.is_equal(inner[43], c61);
    (inner, last_is_eq)
}

fn pad_to_pow2<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
    pow2_len: usize,
) -> Vec<Target> {
    let mut out = values.to_vec();
    while out.len() < pow2_len {
        out.push(builder.zero());
    }
    out
}

fn decode_b64url_coord_44_to_33<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    chars44: &[Target],
) -> Vec<Target> {
    assert_eq!(chars44.len(), 44);
    let mut out_vec: Vec<Target> = Vec::with_capacity(33);

    for block in 0..11 { // 11 * 4 = 44 chars -> 33 bytes
        let c0 = chars44[block * 4 + 0];
        let c1 = chars44[block * 4 + 1];
        let c2 = chars44[block * 4 + 2];
        let c3 = chars44[block * 4 + 3];
        let v0 = b64url_ascii_to_value(builder, c0);
        let v1 = b64url_ascii_to_value(builder, c1);
        let v2 = b64url_ascii_to_value(builder, c2);
        let v3 = b64url_ascii_to_value(builder, c3);

        let v0_le = builder.split_le_base::<2>(v0, 6);
        let v1_le = builder.split_le_base::<2>(v1, 6);
        let v2_le = builder.split_le_base::<2>(v2, 6);
        let v3_le = builder.split_le_base::<2>(v3, 6);

        // Byte 0
        let mut b0 = builder.zero();
        for k in 0..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k + 2)));
            let contrib = builder.mul(v0_le[k], coeff);
            b0 = builder.add(b0, contrib);
        }
        for (k, pos) in [(4usize, 0u64), (5usize, 1u64)].iter() {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << pos));
            let contrib = builder.mul(v1_le[*k], coeff);
            b0 = builder.add(b0, contrib);
        }
        // Byte 1
        let mut b1 = builder.zero();
        for k in 0..4 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k + 4)));
            let contrib = builder.mul(v1_le[k], coeff);
            b1 = builder.add(b1, contrib);
        }
        for k in 2..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k - 2)));
            let contrib = builder.mul(v2_le[k], coeff);
            b1 = builder.add(b1, contrib);
        }
        // Byte 2
        let mut b2 = builder.zero();
        for k in 0..2 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (k + 6)));
            let contrib = builder.mul(v2_le[k], coeff);
            b2 = builder.add(b2, contrib);
        }
        for k in 0..6 {
            let coeff = builder.constant(F::from_canonical_u64(1u64 << k));
            let contrib = builder.mul(v3_le[k], coeff);
            b2 = builder.add(b2, contrib);
        }

        out_vec.push(b0);
        out_vec.push(b1);
        out_vec.push(b2);
    }
    debug_assert_eq!(out_vec.len(), 33);
    out_vec
}

fn bytes32_be_to_le_u32_limbs<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bytes_be: &[Target],
) -> Vec<Target> {
    assert_eq!(bytes_be.len(), 32);
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
        limbs_le_u32.push(limb);
    }
    limbs_le_u32
}
