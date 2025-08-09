use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2_ecdsa::{
    curve::{
        ecdsa::{sign_message, ECDSASecretKey},
        p256::P256,
        secp256k1::Secp256K1,
    },
    field::p256_scalar::P256Scalar,
};
use serde::Serialize;
use std::{fs, path::PathBuf};
use num_traits::Num;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::Hasher;

type HmacSha512 = Hmac<Sha512>;

#[derive(Parser)]
struct Args {
    /// Use Poseidon for BIP32 derivation (default is SHA-512)
    #[arg(long)]
    poseidon: bool,
}

#[derive(Serialize)]
struct Point {
    x: String,
    y: String,
}

#[derive(Serialize)]
struct Signature {
    r: String,
    s: String,
}

#[derive(Serialize)]
struct FullInput {
    // Inner circuit fields (EUDI + secp256k1) - using static pk for ECDSA
    pk_issuer: Point,  // Fixed static public key from sig_verify_static
    msg: String,
    signature: Signature,
    pk_c: Point,
    sk_c: String,
    sk_0: String,
    pk_0: Point,
    
    // Outer circuit BIP32 fields
    cc_0: String,
    derivation_index: u32,
    pk_i: Point, 
    cc_i: String,
}

/// 64-character hex representation (big-endian) of a field element
fn to_hex<F: PrimeField>(x: &F) -> String {
    let mut s = x.to_canonical_biguint().to_str_radix(16);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    format!("0x{s}")
}

/// Same for BigUint (coordinate points)
fn to_hex_biguint(b: &BigUint) -> String {
    let mut s = b.to_str_radix(16);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    format!("0x{s}")
}

/// Convert byte array to hex string (32 bytes = 64 hex chars)
fn bytes_to_hex(bytes: &[u8]) -> String {
    let hex_str = hex::encode(bytes);
    format!("0x{}", hex_str)
}

/// Pack bits (LSB first) into 63-bit words for Poseidon to avoid field overflow
fn pack_bits_to_words63(bits: &[bool]) -> Vec<u64> {
    let mut words = Vec::new();
    let mut i = 0;
    
    while i < bits.len() {
        let end = (i + 63).min(bits.len());
        let mut word = 0u64;
        
        for (bit_idx, &bit) in bits[i..end].iter().enumerate() {
            if bit {
                word |= 1u64 << bit_idx;
            }
        }
        words.push(word);
        i += 63;
    }
    words
}

/// Convert bytes to little-endian bits
fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new();
    for &byte in bytes {
        for i in 0..8 {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}


/// HMAC-Poseidon implementation compatible with circuit
/// Returns 512 bits (64 bytes) like HMAC-SHA512, with proper bit handling
fn hmac_poseidon(key_bits_256: &[bool], msg_bits_296: &[bool]) -> Vec<u8> {
    // Pack inputs into field elements (63-bit words to avoid field overflow)
    let key_words = pack_bits_to_words63(key_bits_256); // 5 words (256/63 = 4.06, rounded up)
    let msg_words = pack_bits_to_words63(msg_bits_296); // 5 words (296/63 = 4.69, rounded up)
    
    // Domain separation constants (same as in circuit)
    let ds1 = GoldilocksField::from_canonical_u64(0xD501);
    let ds2 = GoldilocksField::from_canonical_u64(0xD502);
    
    // Convert words to field elements
    let mut in1 = vec![ds1];
    in1.extend(key_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w)));
    in1.extend(msg_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w)));
    
    let mut in2 = vec![ds2];
    in2.extend(key_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w)));
    in2.extend(msg_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w)));
    
    // Hash with Poseidon
    let h1 = PoseidonHash::hash_no_pad(&in1);
    let h2 = PoseidonHash::hash_no_pad(&in2);
    
    // Convert to bits and split like in circuit: first 256 bits for I_L, next 256 bits for I_R
    let mut all_bits = Vec::new();
    
    // Each field element contributes 63 bits (to match circuit implementation)
    for element in h1.elements.iter().chain(h2.elements.iter()) {
        let as_u64 = element.0;
        // Take only 63 bits to match circuit
        for i in 0..63 {
            all_bits.push((as_u64 >> i) & 1 == 1);
        }
    }
    
    // We now have 8 * 63 = 504 bits, need to construct 512 bits (256 + 256)
    let mut result_bits = vec![false; 512];
    
    // I_L: Take first 256 bits
    for i in 0..256 {
        if i < all_bits.len() {
            result_bits[i] = all_bits[i];
        }
    }
    
    // I_R: Take next 248 bits and pad to 256 bits
    for i in 256..512 {
        let source_idx = i - 256;
        if source_idx + 256 < all_bits.len() {
            result_bits[i] = all_bits[source_idx + 256];
        }
        // else: already false (padding)
    }
    
    // Convert bits back to bytes
    let mut result_bytes = Vec::new();
    for chunk in result_bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1u8 << i;
            }
        }
        result_bytes.push(byte);
    }
    
    result_bytes
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Use SHA-512 by default, Poseidon if flag is set
    let use_poseidon = args.poseidon;
    let derive_mode = if use_poseidon { "Poseidon" } else { "SHA-512" };
    
    // Fixed values
    let derivation_index = 0u32;
    let output_path = PathBuf::from("inputs/input.json");

    println!("Generating full input with derivation index: {} using {} for BIP32", 
             derivation_index, derive_mode);

    // ---------- 1. EUDI P-256 Data (Inner Part) - Using Static PK ----------
    
    // Use the fixed private key from sig_verify_static specification 
    let sk_issuer_fixed = "46012408107196755923706193987463047920137073659172279781266729514345066549384";
    let sk_issuer_val = P256Scalar::from_noncanonical_biguint(
        BigUint::from_str_radix(sk_issuer_fixed, 10)?
    );
    let sk_issuer = ECDSASecretKey::<P256>(sk_issuer_val);
    let pk_issuer = sk_issuer.to_public().0;

    // Verify that the public key matches the expected fixed coordinates from sig_verify_static
    let expected_x = "66432692286261411630769223098970693805397596870633670159153355502222145619968";
    let expected_y = "63182586149833488067701290985084360701345487374231728189741684364091950142361";
    let expected_x_big = BigUint::from_str_radix(expected_x, 10)?;
    let expected_y_big = BigUint::from_str_radix(expected_y, 10)?;
    assert_eq!(pk_issuer.x.to_canonical_biguint(), expected_x_big);
    assert_eq!(pk_issuer.y.to_canonical_biguint(), expected_y_big);
    
    println!("Using fixed issuer public key from sig_verify_static:");
    println!("  x: {}", expected_x);
    println!("  y: {}", expected_y);

    let msg = P256Scalar::rand();
    let mut sig = sign_message(msg, sk_issuer);

    // Low-s normalization for P-256
    const N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    let n = BigUint::from_str_radix(N_HEX, 16).unwrap();
    let n_half = &n >> 1;

    let s_big = sig.s.to_canonical_biguint();
    if s_big > n_half {
        let s_low = &n - s_big;
        sig.s = P256Scalar::from_noncanonical_biguint(s_low);
    }

    // EUDI Credential Key (P-256)
    let sk_c_scalar = P256Scalar::rand();
    let sk_c = ECDSASecretKey::<P256>(sk_c_scalar);
    let pk_c = sk_c.to_public().0;

    // ---------- 2. secp256k1 Parent Key (Inner + Outer Part) ----------
    let sk_0_scalar = Secp256K1Scalar::rand();
    let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_scalar);
    let pk_0_point = sk_0.to_public().0;

    // ---------- 3. BIP32 Key Derivation (Outer Part) ----------
    
    // Generate parent chain code (32 random bytes)
    let parent_chain_code: [u8; 32] = (0..32)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // BIP32 Non-Hardened Key Derivation: child_pk = parent_pk + I_L * G
    println!("Computing BIP32 derivation for index {}", derivation_index);
    
    // Convert parent private key for k256 computation
    let parent_key_bytes = sk_0_scalar.to_canonical_biguint().to_bytes_be();
    let mut key_array = [0u8; 32];
    let len = parent_key_bytes.len().min(32);
    key_array[32-len..].copy_from_slice(&parent_key_bytes[..len]);
    let parent_k256_secret = SecretKey::from_bytes((&key_array).into())?;
    let parent_k256_public = parent_k256_secret.public_key();
    let parent_pubkey_compressed = parent_k256_public.to_encoded_point(true);
    
    // Create HMAC input: compressed_parent_pubkey || child_index
    let mut hmac_input = parent_pubkey_compressed.as_bytes().to_vec();
    hmac_input.extend_from_slice(&derivation_index.to_be_bytes());
    
    // Compute HMAC result using selected method
    let hmac_result = if use_poseidon {
        // Convert inputs to bits for Poseidon
        let key_bits = bytes_to_bits_le(&parent_chain_code); // 256 bits
        let msg_bits = bytes_to_bits_le(&hmac_input); // 33 bytes = 264 bits, but circuit expects 296
        
        // Pad message to 296 bits (37 bytes) to match circuit expectations
        let mut padded_msg_bits = msg_bits;
        while padded_msg_bits.len() < 296 {
            padded_msg_bits.push(false);
        }
        
        println!("Using HMAC-Poseidon with {} key bits and {} msg bits", 
                 key_bits.len(), padded_msg_bits.len());
        
        hmac_poseidon(&key_bits, &padded_msg_bits)
    } else {
        // Traditional HMAC-SHA512
        let mut hmac = HmacSha512::new_from_slice(&parent_chain_code)?;
        hmac.update(&hmac_input);
        hmac.finalize().into_bytes().to_vec()
    };
    
    // Extract I_L (left 32 bytes) and child chain code (right 32 bytes)
    let il_bytes = &hmac_result[0..32];
    let child_chain_code_bytes = &hmac_result[32..64];
    
    // Convert I_L to scalar
    let il_scalar = Secp256K1Scalar::from_noncanonical_biguint(
        BigUint::from_bytes_be(il_bytes)
    );
    
    // Verify I_L != 0 and I_L < secp256k1_order (security check)
    if il_scalar.to_canonical_biguint() == BigUint::from(0u32) {
        return Err(anyhow::anyhow!("BIP32 derivation failed: I_L = 0"));
    }
    
    let secp256k1_order = BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
    ).unwrap();
    if il_scalar.to_canonical_biguint() >= secp256k1_order {
        return Err(anyhow::anyhow!("BIP32 derivation failed: I_L >= n"));
    }
    
    // Compute child public key: child_pk = parent_pk + I_L * G
    let il_secret_key = ECDSASecretKey::<Secp256K1>(il_scalar);
    let il_point = il_secret_key.to_public().0;
    let child_public_key = (pk_0_point.to_projective() + il_point.to_projective()).to_affine();
    
    println!("BIP32 derivation successful:");
    println!("  Parent chain code: {}", bytes_to_hex(&parent_chain_code));
    println!("  Child index: {}", derivation_index);
    println!("  Child chain code: {}", bytes_to_hex(child_chain_code_bytes));
    println!("  I_L: {}", to_hex(&il_scalar));

    // ---------- 4. Generate Output JSON ----------
    let json = FullInput {
        // Inner circuit fields (EUDI P-256) - using static pk
        pk_issuer: Point {
            x: to_hex(&pk_issuer.x),
            y: to_hex(&pk_issuer.y),
        },
        msg: to_hex(&msg),
        signature: Signature {
            r: to_hex(&sig.r),
            s: to_hex(&sig.s),
        },
        pk_c: Point {
            x: to_hex(&pk_c.x),
            y: to_hex(&pk_c.y),
        },
        sk_c: to_hex(&sk_c_scalar),
        
        // secp256k1 parent key (connects inner and outer)
        sk_0: to_hex(&sk_0_scalar),
        pk_0: Point {
            x: to_hex_biguint(&pk_0_point.x.to_canonical_biguint()),
            y: to_hex_biguint(&pk_0_point.y.to_canonical_biguint()),
        },
        
        // BIP32 derivation data (outer circuit)
        cc_0: bytes_to_hex(&parent_chain_code),
        derivation_index: derivation_index,
        pk_i: Point {
            x: to_hex_biguint(&child_public_key.x.to_canonical_biguint()),
            y: to_hex_biguint(&child_public_key.y.to_canonical_biguint()),
        },
        cc_i: bytes_to_hex(child_chain_code_bytes),
    };

    fs::write(&output_path, serde_json::to_string_pretty(&json)?)?;
    println!("\nUnified input JSON written to {:?}", output_path);
    println!("Note: Uses static public key from sig_verify_static for ECDSA signature verification");
    Ok(())
}