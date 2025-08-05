use anyhow::Result;
use hex::FromHex;
use k256::{ecdsa::SigningKey as K256Secret, PublicKey as K256Public};
use p256::{
    ecdsa::{Signature, VerifyingKey as P256Public, signature::hazmat::PrehashVerifier},
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct Point { x: String, y: String }
#[derive(Deserialize)]
struct Sig   { r: String, s: String }
#[derive(Deserialize)]
struct Input {
    pk_issuer: Point,
    msg: String,
    signature: Sig,
    sk_0: String,
    pk_0: Point,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn main() -> Result<()> {
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/experiments/outer_sig_verify.json"))?
    )?;

    // ---------- 1. Check P-256 signature ----------
    let x_bytes = hex_to_bytes(&json.pk_issuer.x);
    let y_bytes = hex_to_bytes(&json.pk_issuer.y);
    // SEC1 uncompressed format: 0x04 + x + y
    let mut pk_issuer_bytes = vec![0x04];
    pk_issuer_bytes.extend_from_slice(&x_bytes);
    pk_issuer_bytes.extend_from_slice(&y_bytes);
    let pk_issuer   = P256Public::from_sec1_bytes(&pk_issuer_bytes)?;
    let vk          = p256::ecdsa::VerifyingKey::from(pk_issuer);
    let sig_bytes   = [hex_to_bytes(&json.signature.r), hex_to_bytes(&json.signature.s)].concat();
    let sig         = Signature::from_slice(&sig_bytes)?;
    let msg_bytes   = hex_to_bytes(&json.msg);

    vk.verify_prehash(&msg_bytes, &sig)
        .map_err(|_| anyhow::anyhow!("P-256 signature invalid"))?;
    println!("P-256 signature matches pk_issuer and msg");

    // ---------- 2. Check secp256k1 keypair ----------
    let sk_0_bytes  = hex_to_bytes(&json.sk_0);
    let sk_0        = K256Secret::from_slice(&sk_0_bytes)?;
    let pk_0_calc   = K256Public::from(sk_0.verifying_key());

    let x_0_bytes = hex_to_bytes(&json.pk_0.x);
    let y_0_bytes = hex_to_bytes(&json.pk_0.y);
    let mut pk_0_bytes = vec![0x04];
    pk_0_bytes.extend_from_slice(&x_0_bytes);
    pk_0_bytes.extend_from_slice(&y_0_bytes);
    let pk_0_given  = K256Public::from_sec1_bytes(&pk_0_bytes)?;

    assert_eq!(pk_0_calc, pk_0_given, "pk_0 does not match sk_0");
    println!("secp256k1 keypair (sk_0 / pk_0) is consistent");

    Ok(())
}
