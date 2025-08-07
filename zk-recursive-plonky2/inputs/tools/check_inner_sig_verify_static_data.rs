use anyhow::Result;
use hex::FromHex;
use p256::{
    ecdsa::{Signature, VerifyingKey as P256Public, signature::hazmat::PrehashVerifier},
    elliptic_curve::{PrimeField, sec1::{FromEncodedPoint, ToEncodedPoint}},
    AffinePoint as P256AffinePoint, ProjectivePoint, Scalar, PublicKey as P256PublicKey,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use num_bigint::BigUint;
use num_traits::Num;

#[derive(Deserialize)]
struct Sig { r: String, s: String }

#[derive(Deserialize)]
struct Input {
    // No pk_issuer field needed since it's fixed in the circuit
    msg: String,
    signature: Sig,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(s);
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    result
}

fn dec32(s: &str) -> [u8; 32] {
    let num = BigUint::from_str_radix(s, 10).unwrap();
    let hex_str = format!("{:064x}", num);
    let bytes = hex::decode(&hex_str).unwrap();
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    result
}

fn main() -> Result<()> {
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/experiments/inner_sig_verify_static.json"))?
    )?;

    // Check P-256 signature with fixed issuer public key
    // Use the fixed issuer public key coordinates
    let pk_issuer_x = "66432692286261411630769223098970693805397596870633670159153355502222145619968";
    let pk_issuer_y = "63182586149833488067701290985084360701345487374231728189741684364091950142361";
    
    // Convert decimal strings to bytes properly for big numbers
    let x_bytes = {
        let num = BigUint::from_str_radix(pk_issuer_x, 10).unwrap();
        let hex_str = format!("{:064x}", num);
        hex::decode(&hex_str).unwrap()
    };
    
    let y_bytes = {
        let num = BigUint::from_str_radix(pk_issuer_y, 10).unwrap();
        let hex_str = format!("{:064x}", num);
        hex::decode(&hex_str).unwrap()
    };

    // SEC1 uncompressed format: 0x04 + x + y
    let mut pk_issuer_bytes = vec![0x04];
    pk_issuer_bytes.extend_from_slice(&x_bytes);
    pk_issuer_bytes.extend_from_slice(&y_bytes);
    let pk_issuer = P256Public::from_sec1_bytes(&pk_issuer_bytes)?;
    let vk = p256::ecdsa::VerifyingKey::from(pk_issuer);
    
    let sig_bytes = [hex_to_bytes(&json.signature.r), hex_to_bytes(&json.signature.s)].concat();
    let sig = Signature::from_slice(&sig_bytes)?;
    let msg_bytes = hex_to_bytes(&json.msg);

    vk.verify_prehash(&msg_bytes, &sig)
        .map_err(|_| anyhow::anyhow!("P-256 signature invalid"))?;
    
    println!("=== Standard P-256 Library Verification ===");
    println!("P-256 signature matches fixed issuer public key and message");
    println!("Fixed issuer public key coordinates:");
    println!("  x: {}", pk_issuer_x);
    println!("  y: {}", pk_issuer_y);
    println!("Message: {}", json.msg);
    println!("Signature r: {}", json.signature.r);
    println!("Signature s: {}", json.signature.s);
    println!("Inner signature verification (static PK) data is valid!");
    
    println!("\n=== Manual ECDSA Verification with Intermediate Steps ===");
    
    // Manual ECDSA verification
    let msg_hex = &json.msg;
    let r_hex = &json.signature.r;
    let s_hex = &json.signature.s;
    let qx_dec = pk_issuer_x;
    let qy_dec = pk_issuer_y;
    
    println!("Input values:");
    println!("  Message (hex): {}", msg_hex);
    println!("  r (hex): {}", r_hex);
    println!("  s (hex): {}", s_hex);
    println!("  Q.x (decimal): {}", qx_dec);
    println!("  Q.y (decimal): {}", qy_dec);
    
    // 1) Create public key point Q from coordinates
    let ep = p256::EncodedPoint::from_affine_coordinates(&dec32(qx_dec).into(), &dec32(qy_dec).into(), false);
    let q = P256AffinePoint::from_encoded_point(&ep).unwrap();
    let pk_manual = P256PublicKey::from_affine(q).unwrap();
    let vk_manual = p256::ecdsa::VerifyingKey::from(&pk_manual);
    
    // 2) Create signature and verify (same as above, but explicit)
    let sig_manual = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&hex32(r_hex));
        b[32..].copy_from_slice(&hex32(s_hex));
        Signature::from_slice(&b).unwrap()
    };
    vk_manual.verify_prehash(&hex32(msg_hex), &sig_manual)
        .expect("Manual host verify failed");
    println!("Manual library verification successful");
    
    // 3) Explicit mathematical verification: r ?= x(u1*G + u2*Q) mod n
    println!("\nMathematical verification:");
    let r = Scalar::from_repr(hex32(r_hex).into()).unwrap();
    let s = Scalar::from_repr(hex32(s_hex).into()).unwrap();
    let m = Scalar::from_repr(hex32(msg_hex).into()).unwrap();
    
    println!("  r (scalar): {:?}", r);
    println!("  s (scalar): {:?}", s);
    println!("  m (scalar): {:?}", m);
    
    // Calculate s^{-1} mod n
    let c = s.invert().unwrap();
    println!("  s^-1 (scalar): {:?}", c);
    
    // Calculate u1 = m * s^{-1} mod n
    let u1 = m * c;
    println!("  u1 = m * s^-1 (scalar): {:?}", u1);
    
    // Calculate u2 = r * s^{-1} mod n
    let u2 = r * c;
    println!("  u2 = r * s^-1 (scalar): {:?}", u2);
    
    // Calculate R = u1*G + u2*Q
    let r_point = ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(q) * u2;
    println!("  R = u1*G + u2*Q (point): {:?}", r_point);
    
    // Get x-coordinate of R and reduce mod n
    let r_affine = r_point.to_affine();
    let r_encoded = r_affine.to_encoded_point(false);
    let rx_bytes = r_encoded.x().unwrap();
    let rx_mod_n = Scalar::from_repr((*rx_bytes).into()).unwrap();
    
    println!("  R.x (bytes): {:02x?}", rx_bytes);
    println!("  R.x mod n (scalar): {:?}", rx_mod_n);
    
    // Final verification: rx_mod_n == r
    if rx_mod_n == r {
        println!("Mathematical verification: x(R) mod n == r");
    } else {
        return Err(anyhow::anyhow!("Mathematical verification failed: x(R) mod n != r"));
    }
    
    println!("\n=== All Verifications Successful ===");

    Ok(())
}