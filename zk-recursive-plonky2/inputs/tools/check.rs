use anyhow::Result;
use hex::FromHex;
use k256::{ecdsa::SigningKey as K256Secret, PublicKey as K256Public, elliptic_curve::sec1::ToEncodedPoint};
use p256::{
    ecdsa::{Signature, VerifyingKey as P256Public, SigningKey as P256Secret, signature::hazmat::PrehashVerifier},
    PublicKey as P256PublicKey,
};
use serde::Deserialize;
use std::{fs, path::PathBuf, env};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::config::Hasher;

type HmacSha512 = Hmac<Sha512>;

#[derive(Deserialize)]
struct Point { x: String, y: String }

#[derive(Deserialize)]
struct Sig { r: String, s: String }

#[derive(Deserialize)]
struct Input {
    // Inner circuit fields (EUDI P-256)
    pk_issuer: Point,
    msg: String,
    signature: Sig,
    pk_c: Point,
    sk_c: String,
    sk_0: String,
    pk_0: Point,
    
    // Outer circuit BIP32 fields
    cc_0: String,         // Parent chain code
    derivation_index: u32, // Child index (non-hardened)
    pk_i: Point,          // Child public key  
    cc_i: String,         // Child chain code
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn hex_to_bytes_32(s: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(s);
    if bytes.len() != 32 {
        panic!("Expected 32 bytes, got {}", bytes.len());
    }
    bytes.try_into().unwrap()
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
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/input.json"))?
    )?;

    // Check if --poseidon flag was used (default is SHA-512)
    let args: Vec<String> = env::args().collect();
    let use_poseidon = args.contains(&"--poseidon".to_string());
    
    let derive_mode = if use_poseidon { "Poseidon" } else { "SHA-512" };

    println!("=== CHECKING UNIFIED INPUT DATA ===");
    println!("Using {} for BIP32 derivation verification", derive_mode);

    // ---------- 1. Check P-256 EUDI Signature (Inner Part) - Static PK Verification ----------
    println!("\n1. Verifying P-256 EUDI signature with static public key...");
    
    // Verify that pk_issuer matches the expected static public key from sig_verify_static
    let expected_x = "66432692286261411630769223098970693805397596870633670159153355502222145619968";
    let expected_y = "63182586149833488067701290985084360701345487374231728189741684364091950142361";
    
    // Convert given pk_issuer to decimal strings for comparison
    let x_issuer_bytes = hex_to_bytes(&json.pk_issuer.x);
    let y_issuer_bytes = hex_to_bytes(&json.pk_issuer.y);
    let x_issuer_big = BigUint::from_bytes_be(&x_issuer_bytes);
    let y_issuer_big = BigUint::from_bytes_be(&y_issuer_bytes);
    let x_issuer_decimal = x_issuer_big.to_str_radix(10);
    let y_issuer_decimal = y_issuer_big.to_str_radix(10);
    
    assert_eq!(x_issuer_decimal, expected_x, "pk_issuer.x does not match static public key");
    assert_eq!(y_issuer_decimal, expected_y, "pk_issuer.y does not match static public key");
    println!("Public key matches static public key from sig_verify_static");
    
    // SEC1 uncompressed format: 0x04 + x + y
    let mut pk_issuer_bytes = vec![0x04];
    pk_issuer_bytes.extend_from_slice(&x_issuer_bytes);
    pk_issuer_bytes.extend_from_slice(&y_issuer_bytes);
    let pk_issuer = P256PublicKey::from_sec1_bytes(&pk_issuer_bytes)?;
    let vk = P256Public::from(pk_issuer);
    let sig_bytes = [hex_to_bytes(&json.signature.r), hex_to_bytes(&json.signature.s)].concat();
    let sig = Signature::from_slice(&sig_bytes)?;
    let msg_bytes = hex_to_bytes(&json.msg);

    vk.verify_prehash(&msg_bytes, &sig)
        .map_err(|_| anyhow::anyhow!("P-256 signature invalid"))?;
    println!("P-256 signature matches static pk_issuer and msg");

    // ---------- 2. Check P-256 EUDI Key Derivation (Inner Part) ----------
    println!("\n2. Verifying P-256 EUDI keypair...");
    let sk_c_bytes = hex_to_bytes(&json.sk_c);
    let sk_c = P256Secret::from_slice(&sk_c_bytes)?;
    let pk_c_calc = P256PublicKey::from(sk_c.verifying_key());

    let x_c_bytes = hex_to_bytes(&json.pk_c.x);
    let y_c_bytes = hex_to_bytes(&json.pk_c.y);
    let mut pk_c_bytes = vec![0x04];
    pk_c_bytes.extend_from_slice(&x_c_bytes);
    pk_c_bytes.extend_from_slice(&y_c_bytes);
    let pk_c_given = P256PublicKey::from_sec1_bytes(&pk_c_bytes)?;

    assert_eq!(pk_c_calc, pk_c_given, "pk_c does not match sk_c");
    println!("P-256 keypair (sk_c / pk_c) is consistent");

    // ---------- 3. Check secp256k1 Parent Keypair (Inner + Outer Connection) ----------
    println!("\n3. Verifying secp256k1 parent keypair...");
    let sk_0_bytes = hex_to_bytes(&json.sk_0);
    let sk_0 = K256Secret::from_slice(&sk_0_bytes)?;
    let pk_0_calc = K256Public::from(sk_0.verifying_key());

    let x_0_bytes = hex_to_bytes(&json.pk_0.x);
    let y_0_bytes = hex_to_bytes(&json.pk_0.y);
    let mut pk_0_bytes = vec![0x04];
    pk_0_bytes.extend_from_slice(&x_0_bytes);
    pk_0_bytes.extend_from_slice(&y_0_bytes);
    let pk_0_given = K256Public::from_sec1_bytes(&pk_0_bytes)?;

    assert_eq!(pk_0_calc, pk_0_given, "pk_0 does not match sk_0");
    println!("secp256k1 parent keypair (sk_0 / pk_0) is consistent");

    // ---------- 4. Check BIP32 Non-Hardened Derivation (Outer Part) ----------
    println!("\n4. Verifying BIP32 non-hardened key derivation...");
    
    // Ensure derivation index is non-hardened
    if json.derivation_index >= 0x80000000 {
        return Err(anyhow::anyhow!("Derivation index {} is hardened (>= 2^31)", json.derivation_index));
    }
    println!("Derivation index {} is non-hardened", json.derivation_index);
    
    // Get parent chain code and compressed public key
    let parent_chain_code = hex_to_bytes_32(&json.cc_0);
    let parent_pubkey_compressed = pk_0_calc.to_encoded_point(true);
    
    // Create HMAC input: compressed_parent_pubkey || child_index
    let mut hmac_input = parent_pubkey_compressed.as_bytes().to_vec();
    hmac_input.extend_from_slice(&json.derivation_index.to_be_bytes());
    
    // Compute HMAC result using detected method
    let hmac_result = if use_poseidon {
        // Convert inputs to bits for Poseidon
        let key_bits = bytes_to_bits_le(&parent_chain_code); // 256 bits
        let msg_bits = bytes_to_bits_le(&hmac_input); // 33 bytes = 264 bits, but circuit expects 296
        
        // Pad message to 296 bits (37 bytes) to match circuit expectations
        let mut padded_msg_bits = msg_bits;
        while padded_msg_bits.len() < 296 {
            padded_msg_bits.push(false);
        }
        
        println!("Verifying with HMAC-Poseidon: {} key bits, {} msg bits", 
                 key_bits.len(), padded_msg_bits.len());
        
        hmac_poseidon(&key_bits, &padded_msg_bits)
    } else {
        // Traditional HMAC-SHA512
        let mut hmac = HmacSha512::new_from_slice(&parent_chain_code)?;
        hmac.update(&hmac_input);
        hmac.finalize().into_bytes().to_vec()
    };
    
    // Extract I_L (left 32 bytes) and computed child chain code (right 32 bytes)
    let il_bytes = &hmac_result[0..32];
    let computed_child_chain_code = &hmac_result[32..64];
    
    // Verify child chain code matches
    let given_child_chain_code = hex_to_bytes_32(&json.cc_i);
    assert_eq!(computed_child_chain_code, given_child_chain_code, "Child chain code mismatch");
    println!("Child chain code matches HMAC computation");
    
    // Verify I_L constraints
    let il_big = BigUint::from_bytes_be(il_bytes);
    if il_big == BigUint::from(0u32) {
        return Err(anyhow::anyhow!("BIP32 derivation invalid: I_L = 0"));
    }
    
    let secp256k1_order = BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
    ).unwrap();
    if il_big >= secp256k1_order {
        return Err(anyhow::anyhow!("BIP32 derivation invalid: I_L >= secp256k1_order"));
    }
    println!("I_L is valid: 0 < I_L < secp256k1_order");
    
    // Compute expected child public key: child_pk = parent_pk + I_L * G
    let il_secret = K256Secret::from_slice(il_bytes)?;
    let il_point = K256Public::from(il_secret.verifying_key());
    
    // Convert to projective coordinates for addition
    let parent_projective = pk_0_calc.to_projective();
    let il_projective = il_point.to_projective();
    let computed_child_projective = parent_projective + il_projective;
    let computed_child_public = computed_child_projective.to_affine();
    
    // Build given child public key from JSON
    let x_i_bytes = hex_to_bytes(&json.pk_i.x);
    let y_i_bytes = hex_to_bytes(&json.pk_i.y);
    let mut pk_i_bytes = vec![0x04];
    pk_i_bytes.extend_from_slice(&x_i_bytes);
    pk_i_bytes.extend_from_slice(&y_i_bytes);
    let given_child_public = K256Public::from_sec1_bytes(&pk_i_bytes)?;
    
    // Verify child public key matches computation (convert to bytes for comparison)
    let computed_child_bytes = computed_child_public.to_encoded_point(false).as_bytes().to_vec();
    let given_child_bytes = given_child_public.to_encoded_point(false).as_bytes().to_vec();
    assert_eq!(computed_child_bytes, given_child_bytes, "Child public key mismatch");
    println!("Child public key matches BIP32 computation: pk_i = pk_0 + I_L * G");
    
    // ---------- 5. Summary ----------
    println!("\n=== VALIDATION SUMMARY ===");
    println!("P-256 EUDI signature verification passed (static public key)");
    println!("P-256 EUDI keypair consistency verified");
    println!("secp256k1 parent keypair consistency verified");
    println!("BIP32 non-hardened derivation verified");
    println!("All mathematical relationships are correct");
    println!("\nInput is VALID for Unified Proof Generation!");
    
    println!("\nKey Details:");
    println!("  Static Issuer PK: {}||{} (from sig_verify_static)", expected_x, expected_y);
    println!("  Parent PK: {}||{}", json.pk_0.x, json.pk_0.y);
    println!("  Parent CC: {}", json.cc_0);
    println!("  Index: {} (non-hardened)", json.derivation_index);
    println!("  Child PK: {}||{}", json.pk_i.x, json.pk_i.y);
    println!("  Child CC: {}", json.cc_i);
    
    Ok(())
}