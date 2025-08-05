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

type HmacSha512 = Hmac<Sha512>;

#[derive(Parser)]
struct Args {
    /// Output file path
    #[arg(short, long, default_value = "inputs/outer_extended.json")]
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
struct Signature {
    r: String,
    s: String,
}

#[derive(Serialize)]
struct OuterExtendedInput {
    // Inner extended circuit fields (EUDI + secp256k1)
    pk_issuer: Point,
    msg: String,
    signature: Signature,
    pk_c: Point,
    sk_c: String,
    sk_0: String,
    pk_0: Point,
    
    // Outer extended circuit BIP32 fields
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

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Ensure derivation index is non-hardened (< 2^31)
    if args.derivation_index >= 0x80000000 {
        return Err(anyhow::anyhow!("Derivation index must be < 2^31 (non-hardened)"));
    }

    println!("Generating outer extended proof input with derivation index: {}", args.derivation_index);

    // ---------- 1. EUDI P-256 Data (Inner Extended Part) ----------
    let sk_issuer = ECDSASecretKey::<P256>(P256Scalar::rand());
    let pk_issuer = sk_issuer.to_public().0;

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

    // ---------- 2. secp256k1 Parent Key (Inner + Outer Extended Part) ----------
    let sk_0_scalar = Secp256K1Scalar::rand();
    let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_scalar);
    let pk_0_point = sk_0.to_public().0;

    // ---------- 3. BIP32 Key Derivation (Outer Extended Part) ----------
    
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

    // ---------- 4. Generate Output JSON ----------
    let json = OuterExtendedInput {
        // Inner extended circuit fields (EUDI P-256)
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
        
        // BIP32 derivation data (outer extended circuit)
        cc_0: bytes_to_hex(&parent_chain_code),
        derivation_index: args.derivation_index,
        pk_i: Point {
            x: to_hex_biguint(&child_public_key.x.to_canonical_biguint()),
            y: to_hex_biguint(&child_public_key.y.to_canonical_biguint()),
        },
        cc_i: bytes_to_hex(child_chain_code_bytes),
    };

    fs::write(&args.output, serde_json::to_string_pretty(&json)?)?;
    println!("\nOuter extended proof input JSON written to {:?}", args.output);
    Ok(())
}