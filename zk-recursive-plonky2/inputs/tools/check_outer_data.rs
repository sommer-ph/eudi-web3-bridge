use anyhow::Result;
use hex::FromHex;
use k256::{ecdsa::SigningKey as K256Secret, PublicKey as K256Public};
use p256::{
    ecdsa::{Signature, VerifyingKey as P256Public, SigningKey as P256Secret, signature::hazmat::PrehashVerifier},
    PublicKey as P256PublicKey,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct Point { x: String, y: String }

#[derive(Deserialize)]
struct Sig { r: String, s: String }

#[derive(Deserialize)]
struct Input {
    // Inner circuit fields
    pk_issuer: Point,
    msg: String,
    signature: Sig,
    pk_c: Point,
    sk_c: String,
    // Outer circuit fields
    sk_0: String,
    pk_0: Point,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn main() -> Result<()> {
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/outer.json"))?
    )?;

    // ---------- 1. Check P-256 signature (Inner Circuit Part) ----------
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

    // ---------- 2. Check P-256 Key Derivation (Inner Circuit Part) ----------
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

    // ---------- 3. Check secp256k1 Key Derivation (Outer Circuit Part) ----------
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
    println!("secp256k1 keypair (sk_0 / pk_0) is consistent");

    println!("All validations successful - Input is valid for Outer Proof!");
    Ok(())
}