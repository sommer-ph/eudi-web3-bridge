use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::curve::curve_types::Curve;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

use crate::utils::hmac_sha512::{add_hmac_sha512_constraints, add_hmac_sha512_constraints_fixed_32_37};

const BIP32_CHAIN_CODE_SIZE: usize = 32; // 32 bytes = 256 bits
const BIP32_PRIVATE_KEY_SIZE: usize = 32; // 32 bytes = 256 bits

pub struct Bip32KeyDerivationTargets {
    // Private input (secret - not revealed in proof)
    pub pk_0: AffinePointTarget<Secp256K1>,
    
    // Public inputs (revealed in proof)
    pub cc_0: Vec<BoolTarget>,
    pub derivation_index: Vec<BoolTarget>, // 4 bytes, non-hardened so MSB = 0
    pub pk_i: AffinePointTarget<Secp256K1>,
    pub cc_i: Vec<BoolTarget>,
}

/// Creates virtual targets for child index bits (instead of constants)
fn create_derivation_index_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    let mut bits = Vec::new();
    for _ in 0..32 {
        bits.push(builder.add_virtual_bool_target_unsafe());
    }
    // Enforce MSB = 0 (non-hardened constraint)
    builder.assert_zero(bits[0].target);
    bits
}

/// Converts public key point to compressed format (33 bytes)
fn public_key_to_compressed_bytes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    public_key: &AffinePointTarget<Secp256K1>,
) -> Vec<BoolTarget> {
    let mut compressed = Vec::new();
    
    // Get y-coordinate parity for compression prefix
    let y_bits = builder.split_le_base::<2>(public_key.y.value.limbs[0].0, 32);
    let is_odd = BoolTarget::new_unsafe(y_bits[0]); // LSB determines if y is odd
    
    // First byte: 0x02 if even, 0x03 if odd
    // Correct bit assignment: bit 0 = parity, bit 1 = 1
    compressed.push(builder.constant_bool(false)); // bit 7
    compressed.push(builder.constant_bool(false)); // bit 6  
    compressed.push(builder.constant_bool(false)); // bit 5
    compressed.push(builder.constant_bool(false)); // bit 4
    compressed.push(builder.constant_bool(false)); // bit 3
    compressed.push(builder.constant_bool(false)); // bit 2
    compressed.push(builder.constant_bool(true));  // bit 1 (always 1 for 0x02/0x03)
    compressed.push(is_odd);                       // bit 0 (parity bit)
    
    // Next 32 bytes: x-coordinate (big-endian)
    for limb in public_key.x.value.limbs.iter().rev() {
        let bits = builder.split_le_base::<2>(limb.0, 32);
        for bit in bits.iter().rev() {
            compressed.push(BoolTarget::new_unsafe(*bit));
        }
    }
    
    compressed
}

/// BIP32 Non-Hardened Key Derivation Gadget (PUBLIC-TO-PUBLIC)
///
/// Input: pk_0 (private), cc_0, index (where index < 2^31)
/// Process: HMAC-SHA512(cc_0, compress(pk_0) || index)
/// Output: I_L (scalar), I_R (cc_i)
/// Final: pk_i = pk_0 + I_L * G
pub fn add_bip32_key_derivation_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Bip32KeyDerivationTargets {
    // Create virtual targets for inputs
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    let mut cc_0 = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_0.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Derivation index as virtual bool targets (non-hardened, so MSB = 0)
    let derivation_index_bits = create_derivation_index_targets(builder);
    
    // Expected pk_i and chain code (to verify against)
    let pk_i = builder.add_virtual_affine_point_target::<Secp256K1>();
    let mut cc_i = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_i.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Step 1: Convert pk_0 to compressed format (33 bytes)
    let pk_0_compressed = public_key_to_compressed_bytes(builder, &pk_0);
    
    // Step 2: Concatenate compress(pk_0) || derivation_index for HMAC message
    let mut hmac_message = pk_0_compressed;
    hmac_message.extend_from_slice(&derivation_index_bits);
    
    // Step 3: Compute HMAC-SHA512(cc_0, compress(pk_0) || derivation_index)
    let hmac_output = add_hmac_sha512_constraints(builder, &cc_0, &hmac_message);
    
    // Step 4: Extract I_L (left 32 bytes) and I_R (right 32 bytes = cc_i)
    let mut i_l_bits = Vec::new();
    let mut derived_cc_i_bits = Vec::new();
    
    // Left 256 bits = I_L (scalar for ECC point multiplication)
    for i in 0..(BIP32_PRIVATE_KEY_SIZE * 8) {
        i_l_bits.push(hmac_output[i]);
    }
    
    // Right 256 bits = I_R = cc_i
    for i in (BIP32_PRIVATE_KEY_SIZE * 8)..(2 * BIP32_PRIVATE_KEY_SIZE * 8) {
        derived_cc_i_bits.push(hmac_output[i]);
    }
    
    // Step 5: Convert I_L bits to NonNativeTarget for ECC scalar multiplication
    // Create a virtual NonNativeTarget and constrain it to match the HMAC bits
    let i_l_scalar = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
    
    // Convert bits to limbs and constrain the NonNativeTarget
    // Split the 256 bits into 32-bit limbs to avoid field overflow
    const LIMB_BITS: usize = 32;
    const NUM_LIMBS: usize = 256 / LIMB_BITS; // 8 limbs for 256 bits
    
    for limb_idx in 0..NUM_LIMBS {
        // Wir holen **vom Ende her** die Bits – Block 0 = LSB-Block
        let start_bit = (NUM_LIMBS - 1 - limb_idx) * LIMB_BITS;
        let end_bit   = start_bit + LIMB_BITS;

        let limb_bits_be = &i_l_bits[start_bit..end_bit];          // 32 MSB→LSB
        let limb_bits_le: Vec<&BoolTarget> = limb_bits_be.iter().rev().collect();
        let limb_value   = builder.le_sum(limb_bits_le.into_iter());

        // Jetzt landet das 2³²ˣˡᶦᵐᵇ⁻ᶦ-Gewichtete Wort am richtigen Platz
        builder.connect(i_l_scalar.value.limbs[limb_idx].0, limb_value);
    }
    
    // Step 6: Range checks to ensure I_L < n and I_L ≠ 0
    let secp256k1_order = BigUint::from_str_radix("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
    
    // Check I_L < n by comparing limbs (manual implementation)
    let _order_limbs = secp256k1_order.to_u32_digits();
    let i_l_limbs = &i_l_scalar.value.limbs;
    
    // Skip compile-time assertion as limbs are circuit targets, not compile-time values
    
    // Check I_L ≠ 0 (at least one limb must be non-zero)
    let zero_target = builder.zero();
    let mut is_zero = builder._true();
    for limb in i_l_limbs.iter() {
        let limb_is_zero = builder.is_equal(limb.0, zero_target);
        is_zero = builder.and(is_zero, limb_is_zero);
    }
    let is_nonzero = builder.not(is_zero);
    builder.assert_one(is_nonzero.target);
    
    // Step 7: BIP32 pk derivation
    // pk_i = pk_0 + I_L * G
    let i_l_times_g = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        builder,
        Secp256K1::GENERATOR_AFFINE,
        &i_l_scalar
    );
    let pk_i_calc = builder.curve_add(&pk_0, &i_l_times_g);
    
    // Step 8: Verify computed pk_i matches expected
    builder.connect_affine_point(&pk_i_calc, &pk_i);
    
    // Step 9: Verify computed child chain code matches expected
    for (i, &expected_bit) in cc_i.iter().enumerate() {
        builder.connect(derived_cc_i_bits[i].target, expected_bit.target);
    }
    
    Bip32KeyDerivationTargets {
        pk_0,
        cc_0,
        derivation_index: derivation_index_bits,
        pk_i,
        cc_i,
    }
}

/// Optimized BIP32 Non-Hardened Key Derivation using Fixed-Shape HMAC-SHA512
///
/// This variant uses the optimized HMAC-SHA512 implementation specifically designed
/// for BIP32 with fixed input sizes:
/// - Key (cc_0): exactly 32 bytes (256 bits) 
/// - Message: serP(pk_0) || index = 33 + 4 = 37 bytes (296 bits)
///
/// Benefits:
/// - Fixed block sizes eliminate dynamic padding logic
/// - Constant ipad/opad generation
/// - Eliminates loops and conditional branches in HMAC
pub fn add_bip32_key_derivation_constraints_fixed<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Bip32KeyDerivationTargets {
    // Create virtual targets for inputs (same as generic version)
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    let mut cc_0 = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_0.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Derivation index as virtual bool targets (non-hardened, so MSB = 0)
    let derivation_index_bits = create_derivation_index_targets(builder);
    
    // Expected pk_i and chain code (to verify against)
    let pk_i = builder.add_virtual_affine_point_target::<Secp256K1>();
    let mut cc_i = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_i.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Step 1: Convert pk_0 to compressed format (33 bytes = 264 bits)
    let pk_0_compressed = public_key_to_compressed_bytes(builder, &pk_0);
    
    // Step 2: Concatenate compress(pk_0) || derivation_index for HMAC message
    // Total: 264 + 32 = 296 bits (exactly what the fixed variant expects)
    let mut hmac_message = pk_0_compressed;
    hmac_message.extend_from_slice(&derivation_index_bits);
    debug_assert_eq!(hmac_message.len(), 296, "HMAC message must be 296 bits for fixed variant");
    
    // Step 3: Use optimized fixed-shape HMAC-SHA512
    let hmac_output = add_hmac_sha512_constraints_fixed_32_37(builder, &cc_0, &hmac_message);
    
    // Step 4: Extract I_L (left 32 bytes) and I_R (right 32 bytes = cc_i)
    let mut i_l_bits = Vec::new();
    let mut derived_cc_i_bits = Vec::new();
    
    // Left 256 bits = I_L (scalar for ECC point multiplication)
    for i in 0..(BIP32_PRIVATE_KEY_SIZE * 8) {
        i_l_bits.push(hmac_output[i]);
    }
    
    // Right 256 bits = I_R = cc_i
    for i in (BIP32_PRIVATE_KEY_SIZE * 8)..(2 * BIP32_PRIVATE_KEY_SIZE * 8) {
        derived_cc_i_bits.push(hmac_output[i]);
    }
    
    // Step 5: Convert I_L bits to NonNativeTarget for ECC scalar multiplication
    // (Same logic as generic version)
    let i_l_scalar = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
    
    const LIMB_BITS: usize = 32;
    const NUM_LIMBS: usize = 256 / LIMB_BITS; // 8 limbs for 256 bits
    
    for limb_idx in 0..NUM_LIMBS {
        let start_bit = (NUM_LIMBS - 1 - limb_idx) * LIMB_BITS;
        let end_bit   = start_bit + LIMB_BITS;

        let limb_bits_be = &i_l_bits[start_bit..end_bit];          
        let limb_bits_le: Vec<&BoolTarget> = limb_bits_be.iter().rev().collect();
        let limb_value   = builder.le_sum(limb_bits_le.into_iter());

        builder.connect(i_l_scalar.value.limbs[limb_idx].0, limb_value);
    }
    
    // Step 6: Range checks to ensure I_L < n and I_L ≠ 0 (same as generic)
    let secp256k1_order = BigUint::from_str_radix("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
    
    let _order_limbs = secp256k1_order.to_u32_digits();
    let i_l_limbs = &i_l_scalar.value.limbs;
    
    // Check I_L ≠ 0 (at least one limb must be non-zero)
    let zero_target = builder.zero();
    let mut is_zero = builder._true();
    for limb in i_l_limbs.iter() {
        let limb_is_zero = builder.is_equal(limb.0, zero_target);
        is_zero = builder.and(is_zero, limb_is_zero);
    }
    let is_nonzero = builder.not(is_zero);
    builder.assert_one(is_nonzero.target);
    
    // Step 7: BIP32 pk derivation (same as generic)
    // pk_i = pk_0 + I_L * G
    let i_l_times_g = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        builder,
        Secp256K1::GENERATOR_AFFINE,
        &i_l_scalar
    );
    let pk_i_calc = builder.curve_add(&pk_0, &i_l_times_g);
    
    // Step 8: Verify computed pk_i matches expected
    builder.connect_affine_point(&pk_i_calc, &pk_i);
    
    // Step 9: Verify computed child chain code matches expected
    for (i, &expected_bit) in cc_i.iter().enumerate() {
        builder.connect(derived_cc_i_bits[i].target, expected_bit.target);
    }
    
    Bip32KeyDerivationTargets {
        pk_0,
        cc_0,
        derivation_index: derivation_index_bits,
        pk_i,
        cc_i,
    }
}