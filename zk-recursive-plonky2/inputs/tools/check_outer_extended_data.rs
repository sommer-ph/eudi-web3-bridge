use anyhow::Result;
use hex::FromHex;
use k256::{ecdsa::SigningKey as K256Secret, PublicKey as K256Public, elliptic_curve::sec1::ToEncodedPoint};
use p256::{
    ecdsa::{Signature, VerifyingKey as P256Public, SigningKey as P256Secret, signature::hazmat::PrehashVerifier},
    PublicKey as P256PublicKey,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use num_bigint::BigUint;
use num_traits::Num;

type HmacSha512 = Hmac<Sha512>;

#[derive(Deserialize)]
struct Point { x: String, y: String }

#[derive(Deserialize)]
struct Sig { r: String, s: String }

#[derive(Deserialize)]
struct Input {
    // Inner extended circuit fields (EUDI P-256)
    pk_issuer: Point,
    msg: String,
    signature: Sig,
    pk_c: Point,
    sk_c: String,
    sk_0: String,
    pk_0: Point,
    
    // Outer extended circuit BIP32 fields
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

fn main() -> Result<()> {
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/outer_extended.json"))?
    )?;

    println!("=== CHECKING OUTER EXTENDED INPUT DATA ===");

    // ---------- 1. Check P-256 EUDI Signature (Inner Extended Part) ----------
    println!("\n1. Verifying P-256 EUDI signature...");
    let x_issuer_bytes = hex_to_bytes(&json.pk_issuer.x);
    let y_issuer_bytes = hex_to_bytes(&json.pk_issuer.y);
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
    println!("P-256 signature matches pk_issuer and msg");

    // ---------- 2. Check P-256 EUDI Key Derivation (Inner Extended Part) ----------
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

    // ---------- 4. Check BIP32 Non-Hardened Derivation (Outer Extended Part) ----------
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
    
    // Compute HMAC-SHA512(parent_chain_code, compressed_parent_pubkey || child_index)
    let mut hmac = HmacSha512::new_from_slice(&parent_chain_code)?;
    hmac.update(&hmac_input);
    let hmac_result = hmac.finalize().into_bytes();
    
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
    println!("P-256 EUDI signature verification passed");
    println!("P-256 EUDI keypair consistency verified");
    println!("secp256k1 parent keypair consistency verified");
    println!("BIP32 non-hardened derivation verified");
    println!("All mathematical relationships are correct");
    println!("\nInput is VALID for Outer Extended Proof Generation!");
    
    println!("\nBIP32 Derivation Details:");
    println!("  Parent PK: {}||{}", json.pk_0.x, json.pk_0.y);
    println!("  Parent CC: {}", json.cc_0);
    println!("  Index: {} (non-hardened)", json.derivation_index);
    println!("  Child PK: {}||{}", json.pk_i.x, json.pk_i.y);
    println!("  Child CC: {}", json.cc_i);
    
    Ok(())
}