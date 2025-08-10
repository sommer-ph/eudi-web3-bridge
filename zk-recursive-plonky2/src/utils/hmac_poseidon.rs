use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::hash::poseidon::PoseidonHash;

// Debug mode - set to true to expose intermediate values as public inputs
const DEBUG_TAP: bool = true;

/// Minimal debug helper functions
fn tap_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) {
    if DEBUG_TAP {
        for b in bits {
            builder.register_public_input(b.target);
        }
    }
}

fn tap_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    targets: &[Target],
) {
    if DEBUG_TAP {
        for &t in targets {
            builder.register_public_input(t);
        }
    }
}

/// Pack bits (LSB first in `bits`) in 63-bit LE into one Goldilocks field target.
/// Using 63 bits to avoid field overflow (Goldilocks field modulus is 2^64 - 2^32 + 1).
fn pack_63_le<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget], // len <= 63, bits[0] = LSB, bits[62] = MSB
) -> Target {
    debug_assert!(bits.len() <= 63);
    // little-endian sum: bits[0] * 2^0 + bits[1] * 2^1 + ... + bits[62] * 2^62
    builder.le_sum(bits.iter().cloned())
}

/// Pack arbitrary-length bitstring to Goldilocks words of 63 bits (pad last with zeros).
fn pack_bits_to_words63<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) -> Vec<Target> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bits.len() {
        let end = (i + 63).min(bits.len());
        let mut chunk = bits[i..end].to_vec();
        if chunk.len() < 63 {
            // pad with zeros on high-order side (MSB positions in LE word)
            let pad = (0..(63 - chunk.len())).map(|_| builder.constant_bool(false));
            chunk.extend(pad);
        }
        out.push(pack_63_le(builder, &chunk));
        i += 63;
    }
    out
}

/// Split a Goldilocks word to 63 output bits (LE)
fn split_word63_le<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    t: Target,
) -> Vec<BoolTarget> {
    // base=2, 63 bits (to avoid field overflow)
    let bits = builder.split_le_base::<2>(t, 63);
    bits.into_iter().map(BoolTarget::new_unsafe).collect()
}

/// Returns 512 output bits: IL || IR (each 256 bits).
/// 
/// This is a Poseidon-based replacement for HMAC-SHA512 in BIP32 key derivation.
/// Instead of SHA-512, we use two Poseidon hashes with different domain separation.
/// Each Poseidon digest gives 4 field outputs (~252 bits). Two independent digests => 504 bits, padded to 512.
///
/// We pack key_bits (256 bit = 5 words) and msg_bits (296 bit = 5 words) into 63-bit field elements,
/// add a domain separator (1 word) at the front and hash: DS + 5 + 5 = 11 words total input per hash.
pub fn add_hmac_poseidon_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key_bits_256: &[BoolTarget],
    msg_bits_296: &[BoolTarget],
) -> Vec<BoolTarget> {
    debug_assert_eq!(key_bits_256.len(), 256);
    debug_assert_eq!(msg_bits_296.len(), 296);

    // Pack inputs into field targets (63-bit words).
    let key_words = pack_bits_to_words63(builder, key_bits_256); // 5 words (256/63 = 4.06, rounded up)
    let msg_words = pack_bits_to_words63(builder, msg_bits_296); // 5 words (296/63 = 4.69, rounded up)
    
    // DEBUG: Tap the 63-bit words 
    tap_targets(builder, &key_words);           // 5 x 63-bit key words
    tap_targets(builder, &msg_words);           // 5 x 63-bit msg words

    // Domain separation constants (small field scalars).
    // You can pick any distinct constants; keep them stable in generator & circuit.
    let ds1 = builder.constant(F::from_canonical_u64(0xD501));
    let ds2 = builder.constant(F::from_canonical_u64(0xD502));

    // H1 = Poseidon( DS1 || key || msg )
    let mut in1 = vec![ds1];
    in1.extend(&key_words);
    in1.extend(&msg_words);
    let h1 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(in1); // HashOutTarget (4 words)

    // H2 = Poseidon( DS2 || key || msg )
    let mut in2 = vec![ds2];
    in2.extend(&key_words);
    in2.extend(&msg_words);
    let h2 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(in2);
    
    // DEBUG: Tap Poseidon hash outputs (4+4 field elements)
    tap_targets(builder, &h1.elements);         // H1: 4 field elements
    tap_targets(builder, &h2.elements);         // H2: 4 field elements

    // Concatenate bits: H1 (4 words) || H2 (4 words) => 8 * 63 = 504 bits
    let mut all_bits = Vec::with_capacity(504);
    for w in h1.elements.into_iter().chain(h2.elements.into_iter()) {
        all_bits.extend(split_word63_le(builder, w));
    }
    
    // DEBUG: Tap the 504 bits from hash conversion (8x63 bits)
    tap_bits(builder, &all_bits);
    
    // Split into I_L (256 bits) and I_R (256 bits) for BIP32 compatibility
    let mut out_bits = Vec::with_capacity(512);
    
    // I_L: Take first 256 bits
    for i in 0..256 {
        if i < all_bits.len() {
            out_bits.push(all_bits[i]);
        } else {
            out_bits.push(builder.constant_bool(false));
        }
    }
    
    // I_R: Take next 248 bits and pad to 256 bits
    for i in 256..512 {
        let source_idx = i - 256;
        if source_idx + 256 < all_bits.len() {
            out_bits.push(all_bits[source_idx + 256]);
        } else {
            out_bits.push(builder.constant_bool(false));
        }
    }
    
    out_bits
}