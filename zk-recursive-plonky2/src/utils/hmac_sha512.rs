use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_sha512::gadgets::sha512::sha512_circuit_with_preprocessed_input;

const HMAC_BLOCK_SIZE: usize = 1024; // SHA-512 block size in bits
const HMAC_OUTPUT_SIZE: usize = 512; // SHA-512 output size in bits
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

pub struct HmacSha512Targets {
    pub key: Vec<BoolTarget>,
    pub message: Vec<BoolTarget>,
    pub output: Vec<BoolTarget>,
}

/// Converts a byte value to 8 boolean targets
fn byte_to_bool_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    byte_val: u8,
) -> Vec<BoolTarget> {
    let mut bits = Vec::new();
    for i in (0..8).rev() {
        let bit = (byte_val >> i) & 1;
        bits.push(builder.constant_bool(bit == 1));
    }
    bits
}

/// XOR two vectors of BoolTargets bit by bit
fn xor_bool_vectors<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &[BoolTarget],
    b: &[BoolTarget],
) -> Vec<BoolTarget> {
    assert_eq!(a.len(), b.len(), "Vectors must have same length for XOR");
    a.iter()
        .zip(b.iter())
        .map(|(&bit_a, &bit_b)| {
            // Efficient XOR: a ⊕ b = a + b - 2ab with boolean constraint
            let sum = builder.add(bit_a.target, bit_b.target);
            let product = builder.mul(bit_a.target, bit_b.target);
            let two_product = builder.mul_const(plonky2::field::types::Field::TWO, product);
            let xor_target = builder.sub(sum, two_product);
            let xor_bool = BoolTarget::new_unsafe(xor_target);
            builder.assert_bool(xor_bool); // Critical: Ensures XOR result is {0,1}
            xor_bool
        })
        .collect()
}

/// Pad or truncate key to exactly HMAC_BLOCK_SIZE bits
fn prepare_key<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: &[BoolTarget],
    key_len_bits: usize,
) -> Vec<BoolTarget> {
    let mut prepared_key = Vec::new();
    
    if key_len_bits > HMAC_BLOCK_SIZE {
        // If key is longer than block size, hash it first using the gadget
        // Create padded input for SHA512
        let mut padded_key = key.to_vec();
        
        // SHA512 padding
        padded_key.push(builder.constant_bool(true));
        while (padded_key.len() % 1024) != 896 {
            padded_key.push(builder.constant_bool(false));
        }
        
        // Append length as 128 bits
        let keylen: u128 = key_len_bits as u128;
        for i in (0..128).rev() {
            let bit = ((keylen >> i) & 1) == 1;
            padded_key.push(builder.constant_bool(bit));
        }
        
        // Hash the key directly (padded_key is already properly padded)
        let key_hash = sha512_circuit_with_preprocessed_input(builder, &padded_key);
        
        // Use the hash as the key (512 bits)
        prepared_key.extend_from_slice(&key_hash);
        // Pad with zeros to reach HMAC_BLOCK_SIZE
        for _ in HMAC_OUTPUT_SIZE..HMAC_BLOCK_SIZE {
            prepared_key.push(builder.constant_bool(false));
        }
    } else {
        // Use key as-is and pad with zeros
        prepared_key.extend_from_slice(key);
        for _ in key_len_bits..HMAC_BLOCK_SIZE {
            prepared_key.push(builder.constant_bool(false));
        }
    }
    
    prepared_key
}

/// Apply SHA512 padding to make input length a multiple of 1024 bits
fn apply_sha512_padding<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[BoolTarget],
) -> Vec<BoolTarget> {
    let mut padded = input.to_vec();
    let original_bit_length = input.len();
    
    // Step 1: Append single '1' bit
    padded.push(builder.constant_bool(true));
    
    // Step 2: Append zeros until length ≡ 896 (mod 1024)
    // This leaves 128 bits for the length field
    while (padded.len() % 1024) != 896 {
        padded.push(builder.constant_bool(false));
    }
    
    // Step 3: Append original length as 128-bit big-endian integer
    // SHA512 uses 128 bits for length (vs 64 bits for SHA256)
    let bitlen: u128 = original_bit_length as u128;
    for i in (0..128).rev() {
        let bit = ((bitlen >> i) & 1) == 1;
        padded.push(builder.constant_bool(bit));
    }
    
    // Verify final length is multiple of 1024
    assert!(padded.len() % 1024 == 0, "Padded length must be multiple of 1024 bits");
    
    padded
}

/// HMAC-SHA512 Gadget
/// Adds HMAC-SHA512 constraints to an existing circuit builder.
/// HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
/// where:
/// - K is the key padded to block size
/// - m is the message
/// - ipad = 0x36 repeated
/// - opad = 0x5C repeated
/// - H is SHA-512
/// - || denotes concatenation
/// - ⊕ denotes XOR
pub fn add_hmac_sha512_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: &[BoolTarget],
    message: &[BoolTarget],
) -> Vec<BoolTarget> {
    // Step 1: Prepare the key (pad/truncate to block size)
    let prepared_key = prepare_key(builder, key, key.len());

    // Step 2: Create ipad (0x36 repeated for block size) - optimized
    let ipad_byte_targets = byte_to_bool_targets(builder, IPAD);
    let mut ipad = Vec::new();
    for _ in 0..(HMAC_BLOCK_SIZE / 8) {
        ipad.extend_from_slice(&ipad_byte_targets);
    }

    // Step 3: Create opad (0x5C repeated for block size) - optimized  
    let opad_byte_targets = byte_to_bool_targets(builder, OPAD);
    let mut opad = Vec::new();
    for _ in 0..(HMAC_BLOCK_SIZE / 8) {
        opad.extend_from_slice(&opad_byte_targets);
    }

    // Step 4: Compute K ⊕ ipad
    let key_xor_ipad = xor_bool_vectors(builder, &prepared_key, &ipad);

    // Step 5: Compute K ⊕ opad  
    let key_xor_opad = xor_bool_vectors(builder, &prepared_key, &opad);

    // Step 6: Concatenate (K ⊕ ipad) || message
    let mut inner_input = key_xor_ipad;
    inner_input.extend_from_slice(&message);

    // Step 7: Apply SHA512 padding to inner input and compute inner hash
    let padded_inner_input = apply_sha512_padding(builder, &inner_input);
    let inner_hash = sha512_circuit_with_preprocessed_input(builder, &padded_inner_input);

    // Step 8: Concatenate (K ⊕ opad) || inner_hash
    let mut outer_input = key_xor_opad;
    outer_input.extend_from_slice(&inner_hash);

    // Step 9: Apply SHA512 padding to outer input and compute final HMAC
    let padded_outer_input = apply_sha512_padding(builder, &outer_input);
    sha512_circuit_with_preprocessed_input(builder, &padded_outer_input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use hmac::{Hmac, Mac};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    fn array_to_bits(bytes: &[u8]) -> Vec<bool> {
        let mut bits = Vec::new();
        for &byte in bytes.iter() {
            for i in (0..8).rev() {
                let bit = (byte >> i) & 1;
                bits.push(bit == 1);
            }
        }
        bits
    }

    #[test]
    #[ignore]
    fn test_hmac_sha512_circuit() -> Result<()> {
        let key = b"test_key_for_hmac_sha512";
        let message = b"test_message_for_hmac";

        // Reference implementation
        let mut hmac = HmacSha512::new_from_slice(key)?;
        hmac.update(message);
        let expected_hmac = hmac.finalize().into_bytes();

        // Circuit implementation  
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let key_bits = key.len() * 8;
        let message_bits = message.len() * 8;
        
        let key_targets: Vec<BoolTarget> = (0..key_bits).map(|_| builder.add_virtual_bool_target_unsafe()).collect();
        let message_targets: Vec<BoolTarget> = (0..message_bits).map(|_| builder.add_virtual_bool_target_unsafe()).collect();
        let hmac_output = add_hmac_sha512_constraints(&mut builder, &key_targets, &message_targets);

        // Set up witness
        let mut pw = PartialWitness::<F>::new();
        
        let key_bit_values = array_to_bits(key);
        let message_bit_values = array_to_bits(message);
        
        for (i, &bit) in key_bit_values.iter().enumerate() {
            let _ = pw.set_bool_target(key_targets[i], bit);
        }
        
        for (i, &bit) in message_bit_values.iter().enumerate() {
            let _ = pw.set_bool_target(message_targets[i], bit);
        }

        // Constrain output to expected value
        let expected_bits = array_to_bits(&expected_hmac);
        for (i, &expected_bit) in expected_bits.iter().enumerate() {
            if expected_bit {
                builder.assert_one(hmac_output[i].target);
            } else {
                builder.assert_zero(hmac_output[i].target);
            }
        }

        println!("Building HMAC-SHA512 circuit with {} gates", builder.num_gates());
        let data = builder.build::<Cfg>();
        
        println!("Generating proof...");
        let proof = data.prove(pw)?;
        
        println!("Verifying proof...");
        data.verify(proof)?;
        
        println!("HMAC-SHA512 circuit test passed!");
        Ok(())
    }
}