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
    pk_i: Point,
    msg: String,
    signature: Sig,
    sk0: String,
    pk0: Point,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn main() -> Result<()> {
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/experiments/outer_sig_verify.json"))?
    )?;

    // ---------- 1. Check P-256 signature ----------
    let x_bytes = hex_to_bytes(&json.pk_i.x);
    let y_bytes = hex_to_bytes(&json.pk_i.y);
    // SEC1 uncompressed format: 0x04 + x + y
    let mut pk_i_bytes = vec![0x04];
    pk_i_bytes.extend_from_slice(&x_bytes);
    pk_i_bytes.extend_from_slice(&y_bytes);
    let pk_i        = P256Public::from_sec1_bytes(&pk_i_bytes)?;
    let vk          = p256::ecdsa::VerifyingKey::from(pk_i);
    let sig_bytes   = [hex_to_bytes(&json.signature.r), hex_to_bytes(&json.signature.s)].concat();
    let sig         = Signature::from_slice(&sig_bytes)?;
    let msg_bytes   = hex_to_bytes(&json.msg);

    vk.verify_prehash(&msg_bytes, &sig)
        .map_err(|_| anyhow::anyhow!("P-256 signature invalid"))?;
    println!("P-256 signature matches pk_i and msg");

    // ---------- 2. Check secp256k1 keypair ----------
    let sk0_bytes   = hex_to_bytes(&json.sk0);
    let sk0         = K256Secret::from_slice(&sk0_bytes)?;
    let pk0_calc    = K256Public::from(sk0.verifying_key());

    let x0_bytes = hex_to_bytes(&json.pk0.x);
    let y0_bytes = hex_to_bytes(&json.pk0.y);
    let mut pk0_bytes = vec![0x04];
    pk0_bytes.extend_from_slice(&x0_bytes);
    pk0_bytes.extend_from_slice(&y0_bytes);
    let pk0_given   = K256Public::from_sec1_bytes(&pk0_bytes)?;

    assert_eq!(pk0_calc, pk0_given, "pk0 does not match sk0");
    println!("secp256k1 keypair (sk0 / pk0) is consistent");

    Ok(())
}
