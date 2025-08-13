use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, PrimeField64, Sample};
use plonky2::field::goldilocks_field::GoldilocksField as GL;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
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
    #[arg(short, long, default_value = "inputs/input.json")]
    output: PathBuf,
    
    /// Derivation index (non-hardened, must be < 2^31)
    #[arg(short, long, default_value = "0")]
    derivation_index: u32,
    
    /// Derivation mode: sha512 or poseidon
    #[arg(long, default_value = "sha512")]
    derivation_mode: String,
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
    
    // Outer circuit key derivation fields
    cc_0: String,
    derivation_index: u32,
    pk_i: Point, 
    
    // SHA512-specific: Chain code output (optional for Poseidon mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    cc_i: Option<String>,
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

/// Convert u64 array to bytes (big-endian)
fn u64s_to_bytes(limbs: &[u64; 4]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &limb in limbs {
        bytes.extend_from_slice(&limb.to_be_bytes());
    }
    bytes
}

/// Convert BigUint to 8×u32 limbs in LE order (like NonNative-Target)
fn biguint_to_u32_limbs_le(big: &BigUint) -> [u32; 8] {
    let mut bytes = big.to_bytes_le();
    // Pad to 32 bytes (8×u32)
    bytes.resize(32, 0);
    
    let mut limbs = [0u32; 8];
    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        let mut chunk = [0u8; 4];
        chunk.copy_from_slice(&bytes[start..end]);
        limbs[i] = u32::from_le_bytes(chunk);
    }
    limbs
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Validate derivation mode
    if args.derivation_mode != "sha512" && args.derivation_mode != "poseidon" {
        return Err(anyhow::anyhow!("Invalid derivation mode: {}. Use 'sha512' or 'poseidon'", args.derivation_mode));
    }
    
    // Ensure derivation index is non-hardened (< 2^31)
    if args.derivation_index >= 0x80000000 {
        return Err(anyhow::anyhow!("Derivation index must be < 2^31 (non-hardened)"));
    }

    println!("Generating full input with derivation mode: {} and index: {}", args.derivation_mode, args.derivation_index);

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

    // ---------- 3. Key Derivation (Outer Part) ----------
    
    // Generate parent chain code (32 random bytes)
    let parent_chain_code: [u8; 32] = (0..32)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    let (child_public_key, child_chain_code_opt) = match args.derivation_mode.as_str() {
        "sha512" => {
            println!("Computing BIP32/SHA512 derivation for index {}", args.derivation_index);
            
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
            let child_pk = (pk_0_point.to_projective() + il_point.to_projective()).to_affine();
            
            println!("BIP32/SHA512 derivation successful:");
            println!("  Parent chain code: {}", bytes_to_hex(&parent_chain_code));
            println!("  Child index: {}", args.derivation_index);
            println!("  Child chain code: {}", bytes_to_hex(child_chain_code_bytes));
            println!("  I_L: {}", to_hex(&il_scalar));
            
            (child_pk, Some(bytes_to_hex(child_chain_code_bytes)))
        }
        "poseidon" => {
            println!("Computing Poseidon-based derivation for index {}", args.derivation_index);
            
            // Prepare pk_0 coordinates as bytes (padded to 32 bytes)
            let mut pk0_x_bytes = pk_0_point.x.to_canonical_biguint().to_bytes_be();
            let mut pk0_y_bytes = pk_0_point.y.to_canonical_biguint().to_bytes_be();
            
            while pk0_x_bytes.len() < 32 { pk0_x_bytes.insert(0, 0); }
            while pk0_y_bytes.len() < 32 { pk0_y_bytes.insert(0, 0); }
            
            // Build Poseidon preimage: pk0.x (8×u32), pk0.y (8×u32), cc0 (8×u32), i (1)
            let mut inputs_gl: Vec<GL> = Vec::new();
            
            // pk0.x as 8×u32-Limbs (LE-order like NonNative-Target)
            for limb in biguint_to_u32_limbs_le(&BigUint::from_bytes_be(&pk0_x_bytes)) {
                inputs_gl.push(GL::from_canonical_u32(limb));
            }
            
            // pk0.y as 8×u32-Limbs (LE-order)
            for limb in biguint_to_u32_limbs_le(&BigUint::from_bytes_be(&pk0_y_bytes)) {
                inputs_gl.push(GL::from_canonical_u32(limb));
            }
            
            // cc0 as 8×u32-Limbs (LE-order) 
            for limb in biguint_to_u32_limbs_le(&BigUint::from_bytes_be(&parent_chain_code)) {
                inputs_gl.push(GL::from_canonical_u32(limb));
            }
            
            // derivation_index as Goldilocks-Element
            inputs_gl.push(GL::from_canonical_u32(args.derivation_index));

            // Poseidon-Hashing with domain separation (circuit-compatible)
            let mut w_inputs = inputs_gl.clone();
            w_inputs.push(GL::from_canonical_u32(0)); // domain_tag=0 for scalar w
            let w_hash = PoseidonHash::hash_no_pad(&w_inputs);
            
            // w-scalar directly from Poseidon-output (circuit-compatible)
            let w_u64s: [u64; 4] = [
                w_hash.elements[0].to_canonical_u64(),
                w_hash.elements[1].to_canonical_u64(),
                w_hash.elements[2].to_canonical_u64(),
                w_hash.elements[3].to_canonical_u64(),
            ];
            
            let w_scalar = Secp256K1Scalar::from_noncanonical_biguint(
                BigUint::from_bytes_be(&u64s_to_bytes(&w_u64s))
            );
            
            // Check for w=0 (very unlikely but possible)
            if w_scalar.is_zero() {
                return Err(anyhow::anyhow!("Poseidon derivation resulted in w=0; please retry with different index."));
            }

            // Child Key derivation: child_pk = pk0 + w*G
            let w_sk = ECDSASecretKey::<Secp256K1>(w_scalar);
            let w_point = w_sk.to_public().0;
            let child_pk = (pk_0_point.to_projective() + w_point.to_projective()).to_affine();

            println!("Poseidon derivation successful:");
            println!("  Parent chain code: {}", bytes_to_hex(&parent_chain_code));
            println!("  Child index: {}", args.derivation_index);
            println!("  w (scalar): {}", to_hex(&w_scalar));
            println!("  Note: No child chain code for Poseidon mode");
            
            (child_pk, None)
        }
        _ => unreachable!("Derivation mode already validated"),
    };

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
        
        // Key derivation data (outer circuit)
        cc_0: bytes_to_hex(&parent_chain_code),
        derivation_index: args.derivation_index,
        pk_i: Point {
            x: to_hex_biguint(&child_public_key.x.to_canonical_biguint()),
            y: to_hex_biguint(&child_public_key.y.to_canonical_biguint()),
        },
        cc_i: child_chain_code_opt,
    };

    fs::write(&args.output, serde_json::to_string_pretty(&json)?)?;
    println!("\nUnified input JSON written to {:?}", args.output);
    println!("Derivation mode: {}", args.derivation_mode);
    println!("Note: Uses static public key from sig_verify_static for ECDSA signature verification");
    Ok(())
}