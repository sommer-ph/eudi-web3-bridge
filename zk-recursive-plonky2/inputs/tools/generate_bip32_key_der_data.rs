use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2_ecdsa::curve::{ecdsa::ECDSASecretKey, secp256k1::Secp256K1};
use serde::Serialize;
use std::{fs, path::PathBuf};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};

type HmacSha512 = Hmac<Sha512>;

#[derive(Parser)]
struct Args {
    /// Output file path
    #[arg(short, long, default_value = "inputs/experiments/bip32_key_der.json")]
    output: PathBuf,
    
    /// Derivation index (non-hardened, must be < 2^31)
    #[arg(short, long, default_value = "0")]
    derivation_index: u32,
}

#[derive(Serialize)]
struct Point {
    x: String,
    y: String,
}

#[derive(Serialize)]
struct Bip32KeyDerInput {
    // Parent key and chain code (parent public key is private input)
    pk_0: Point,
    cc_0: String,
    // Derivation parameters and expected results (public inputs)
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

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Ensure derivation index is non-hardened (< 2^31)
    if args.derivation_index >= 0x80000000 {
        return Err(anyhow::anyhow!("Derivation index must be < 2^31 (non-hardened)"));
    }

    println!("Generating BIP32 key derivation proof input with derivation index: {}", args.derivation_index);

    // ---------- 1. secp256k1 Parent Key ----------
    let sk_0_scalar = Secp256K1Scalar::rand();
    let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_scalar);
    let pk_0_point = sk_0.to_public().0;

    // ---------- 2. BIP32 Key Derivation ----------
    
    // Generate parent chain code (32 random bytes)
    let parent_chain_code: [u8; 32] = (0..32)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // BIP32 Non-Hardened Key Derivation: child_pk = parent_pk + I_L * G
    println!("Computing BIP32 derivation for index {}", args.derivation_index);
    
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
    hmac_input.extend_from_slice(&args.derivation_index.to_be_bytes());
    
    // Compute HMAC-SHA512(parent_chain_code, compressed_parent_pubkey || child_index)
    let mut hmac = HmacSha512::new_from_slice(&parent_chain_code)?;
    hmac.update(&hmac_input);
    let hmac_result = hmac.finalize().into_bytes();
    
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
    println!("  Child index: {}", args.derivation_index);
    println!("  Child chain code: {}", bytes_to_hex(child_chain_code_bytes));
    println!("  I_L: {}", to_hex(&il_scalar));

    // ---------- 3. Generate Output JSON ----------
    let json = Bip32KeyDerInput {
        // Parent key (pk_0 is private input, cc_0 is public)
        pk_0: Point {
            x: to_hex_biguint(&pk_0_point.x.to_canonical_biguint()),
            y: to_hex_biguint(&pk_0_point.y.to_canonical_biguint()),
        },
        cc_0: bytes_to_hex(&parent_chain_code),
        
        // Derivation parameters and expected results (all public inputs)
        derivation_index: args.derivation_index,
        pk_i: Point {
            x: to_hex_biguint(&child_public_key.x.to_canonical_biguint()),
            y: to_hex_biguint(&child_public_key.y.to_canonical_biguint()),
        },
        cc_i: bytes_to_hex(child_chain_code_bytes),
    };

    fs::write(&args.output, serde_json::to_string_pretty(&json)?)?;
    println!("\nBIP32 key derivation proof input JSON written to {:?}", args.output);
    Ok(())
}