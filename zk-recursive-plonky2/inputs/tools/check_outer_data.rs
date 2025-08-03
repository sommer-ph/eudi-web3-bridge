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
    pk_i: Point,
    msg: String,
    signature: Sig,
    pk_cred: Point,
    sk_c: String,
    // Outer circuit fields
    sk0: String,
    pk0: Point,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn main() -> Result<()> {
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/outer.json"))?
    )?;

    // ---------- 1. Check P-256 signature (Inner Circuit Part) ----------
    let x_i_bytes = hex_to_bytes(&json.pk_i.x);
    let y_i_bytes = hex_to_bytes(&json.pk_i.y);
    // SEC1 uncompressed format: 0x04 + x + y
    let mut pk_i_bytes = vec![0x04];
    pk_i_bytes.extend_from_slice(&x_i_bytes);
    pk_i_bytes.extend_from_slice(&y_i_bytes);
    let pk_i = P256PublicKey::from_sec1_bytes(&pk_i_bytes)?;
    let vk = P256Public::from(pk_i);
    let sig_bytes = [hex_to_bytes(&json.signature.r), hex_to_bytes(&json.signature.s)].concat();
    let sig = Signature::from_slice(&sig_bytes)?;
    let msg_bytes = hex_to_bytes(&json.msg);

    vk.verify_prehash(&msg_bytes, &sig)
        .map_err(|_| anyhow::anyhow!("P-256 signature invalid"))?;
    println!("P-256 signature matches pk_i and msg");

    // ---------- 2. Check P-256 Key Derivation (Inner Circuit Part) ----------
    let sk_c_bytes = hex_to_bytes(&json.sk_c);
    let sk_c = P256Secret::from_slice(&sk_c_bytes)?;
    let pk_cred_calc = P256PublicKey::from(sk_c.verifying_key());

    let x_cred_bytes = hex_to_bytes(&json.pk_cred.x);
    let y_cred_bytes = hex_to_bytes(&json.pk_cred.y);
    let mut pk_cred_bytes = vec![0x04];
    pk_cred_bytes.extend_from_slice(&x_cred_bytes);
    pk_cred_bytes.extend_from_slice(&y_cred_bytes);
    let pk_cred_given = P256PublicKey::from_sec1_bytes(&pk_cred_bytes)?;

    assert_eq!(pk_cred_calc, pk_cred_given, "pk_cred does not match sk_c");
    println!("P-256 keypair (sk_c / pk_cred) is consistent");

    // ---------- 3. Check secp256k1 Key Derivation (Outer Circuit Part) ----------
    let sk0_bytes = hex_to_bytes(&json.sk0);
    let sk0 = K256Secret::from_slice(&sk0_bytes)?;
    let pk0_calc = K256Public::from(sk0.verifying_key());

    let x0_bytes = hex_to_bytes(&json.pk0.x);
    let y0_bytes = hex_to_bytes(&json.pk0.y);
    let mut pk0_bytes = vec![0x04];
    pk0_bytes.extend_from_slice(&x0_bytes);
    pk0_bytes.extend_from_slice(&y0_bytes);
    let pk0_given = K256Public::from_sec1_bytes(&pk0_bytes)?;

    assert_eq!(pk0_calc, pk0_given, "pk0 does not match sk0");
    println!("secp256k1 keypair (sk0 / pk0) is consistent");

    println!("All validations successful - Input is valid for Outer Proof!");
    Ok(())
}